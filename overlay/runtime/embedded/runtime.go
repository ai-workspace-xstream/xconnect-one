package embedded

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
)

type activeManifest struct {
	PID         int       `json:"pid"`
	Interface   string    `json:"interface"`
	Revision    string    `json:"revision"`
	Address     string    `json:"address"`
	LocalPort   int       `json:"local_port"`
	CoreID      string    `json:"core_id"`
	AdapterID   string    `json:"adapter_id"`
	RuntimeMode string    `json:"runtime_mode"`
	StartedAt   time.Time `json:"started_at"`
}

// Runtime implements overlayruntime.Lifecycle, DataPlaneHealth, and Level-1
// RestartTransport inside a single process using embedded xray-core,
// wireguard-go, and platform-native NetConfigurator.
type Runtime struct {
	mu            sync.Mutex
	stateDir      string
	netCfg        NetConfigurator
	privilegedFn  func() bool
	xray          *xrayHost
	wg            *wgHost
	activeCfg     *model.Config
	activePrivKey string
	applied       bool
	revision      string
	ifaceName     string
}

// New constructs an in-process embedded overlay runtime bound to stateDir.
func New(stateDir string) *Runtime {
	return &Runtime{
		stateDir:     strings.TrimSpace(stateDir),
		netCfg:       newPlatformNetConfigurator(),
		privilegedFn: isPlatformPrivileged,
		xray:         newXrayHost(),
		wg:           newWGHost(),
	}
}

func (r *Runtime) Apply(ctx context.Context, request overlayruntime.ApplyRequest) (overlayruntime.ApplyResult, error) {
	if err := request.Config.Validate(); err != nil {
		return overlayruntime.ApplyResult{}, err
	}
	if strings.TrimSpace(request.WireGuardPrivateKey) == "" {
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeInvalidConfig, "validate WireGuard private key", nil)
	}
	if !r.privileged() {
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimePermission, "apply embedded overlay runtime", nil)
	}

	localPrefix, allowedPrefixes, err := parseNetworkPrefixes(request.Config)
	if err != nil {
		var fe *fault.Error
		if errors.As(err, &fe) {
			return overlayruntime.ApplyResult{}, err
		}
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeInvalidConfig, "parse overlay network prefixes", err)
	}
	mtu := defaultTUNMTU(request.Config.WireGuard.MTU)

	r.mu.Lock()
	defer r.mu.Unlock()

	// In-place update when tunnel & Xray host are already running in this process.
	if r.applied && r.wg.Running() && r.xray.Running() {
		if _, err := r.xray.Update(request.Config); err != nil {
			return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "update embedded xray transport", err)
		}
		if err := r.wg.UpdateConfig(request.WireGuardPrivateKey, request.Config); err != nil {
			return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "update embedded wireguard peers", err)
		}
		if err := r.netCfg.Configure(ctx, r.ifaceName, localPrefix, mtu, allowedPrefixes); err != nil {
			return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "reconcile embedded network routes", err)
		}
		cfgCopy := request.Config
		r.activeCfg = &cfgCopy
		r.activePrivKey = request.WireGuardPrivateKey
		r.revision = request.Config.Revision
		_ = r.writeActiveManifestLocked(cfgCopy)
		return overlayruntime.ApplyResult{
			Revision:  request.Config.Revision,
			CoreID:    model.CoreIDXray,
			AdapterID: model.AdapterIDXrayCore,
		}, nil
	}

	// Clean any partial state from an earlier failed apply.
	_ = r.wg.Close()
	_ = r.xray.Close()

	// 1. Start embedded Xray loopback listener before WireGuard dials 127.0.0.1:<port>.
	if err := r.xray.Start(request.Config); err != nil {
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "start embedded xray transport", err)
	}

	// 2. Create TUN device via kernel / Wintun.
	tunDev, realIface, err := r.netCfg.CreateTUN(request.Config.WireGuard.Interface, mtu)
	if err != nil {
		_ = r.xray.Close()
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "create embedded TUN device", err)
	}

	// 3. Attach wireguard-go device and configure peers via in-process UAPI.
	if err := r.wg.Start(tunDev, realIface, request.WireGuardPrivateKey, request.Config); err != nil {
		_ = tunDev.Close()
		_ = r.xray.Close()
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "start embedded wireguard device", err)
	}

	// 4. Configure interface IP, MTU, link UP, and AllowedIPs routes natively.
	if err := r.netCfg.Configure(ctx, realIface, localPrefix, mtu, allowedPrefixes); err != nil {
		_ = r.netCfg.Teardown(ctx, realIface)
		_ = r.wg.Close()
		_ = r.xray.Close()
		return overlayruntime.ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "configure embedded network interface", err)
	}

	cfgCopy := request.Config
	r.activeCfg = &cfgCopy
	r.activePrivKey = request.WireGuardPrivateKey
	r.ifaceName = realIface
	r.revision = request.Config.Revision
	r.applied = true
	_ = r.writeActiveManifestLocked(cfgCopy)

	return overlayruntime.ApplyResult{
		Revision:  request.Config.Revision,
		CoreID:    model.CoreIDXray,
		AdapterID: model.AdapterIDXrayCore,
	}, nil
}

// RestartTransport performs a Level-1 millisecond hot restart: only the
// embedded xray-core Instance is cycled while keeping the TUN interface,
// assigned IP, and kernel routes intact, then nudges WireGuard via UAPI.
func (r *Runtime) RestartTransport(ctx context.Context) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.applied || r.activeCfg == nil || !r.wg.Running() {
		return fault.New(fault.CodeRuntimeApplyFailed, "restart embedded transport", errors.New("embedded runtime is not active"))
	}
	if err := r.xray.Restart(*r.activeCfg); err != nil {
		return fault.New(fault.CodeRuntimeApplyFailed, "restart embedded xray instance", err)
	}
	if err := r.wg.NudgePeer(); err != nil {
		return fault.New(fault.CodeRuntimeApplyFailed, "nudge embedded wireguard peer", err)
	}
	return nil
}

// DataPlaneHealth returns in-process Xray liveness and wireguard-go UAPI peer
// handshake/transfer counters with zero external subprocess forks.
func (r *Runtime) DataPlaneHealth(_ context.Context) (overlayruntime.DataPlaneStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.applied {
		return overlayruntime.DataPlaneStatus{}, nil
	}
	xrayAlive := r.xray.Running()
	wgAlive := r.wg.Running()
	status := overlayruntime.DataPlaneStatus{
		Applied:       xrayAlive && wgAlive,
		Interface:     r.ifaceName,
		XrayAlive:     xrayAlive,
		LoopbackOwned: xrayAlive,
	}
	if wgAlive {
		if hs, rx, tx, err := r.wg.Stats(); err == nil {
			status.LatestHandshake = hs
			status.RxBytes = rx
			status.TxBytes = tx
			status.HasStats = true
		}
	}
	return status, nil
}

func (r *Runtime) Status(_ context.Context) (overlayruntime.Status, error) {
	r.mu.Lock()
	if r.applied && r.wg.Running() && r.xray.Running() {
		status := overlayruntime.Status{
			Available:      true,
			Applied:        true,
			ManagedRuntime: true,
			RuntimeVersion: "embedded",
			Revision:       r.revision,
			CoreID:         model.CoreIDXray,
			AdapterID:      model.AdapterIDXrayCore,
			Interface:      r.ifaceName,
		}
		r.mu.Unlock()
		return status, nil
	}
	r.mu.Unlock()

	if manifest, ok := r.readActiveManifest(); ok && isProcessAlive(manifest.PID) {
		return overlayruntime.Status{
			Available:      true,
			Applied:        true,
			ManagedRuntime: true,
			RuntimeVersion: "embedded",
			Revision:       manifest.Revision,
			CoreID:         manifest.CoreID,
			AdapterID:      manifest.AdapterID,
			Interface:      manifest.Interface,
		}, nil
	}

	return overlayruntime.Status{
		Available:      true,
		Applied:        false,
		ManagedRuntime: true,
		RuntimeVersion: "embedded",
		CoreID:         model.CoreIDXray,
		AdapterID:      model.AdapterIDXrayCore,
	}, nil
}

func (r *Runtime) Down(ctx context.Context) error {
	r.mu.Lock()
	if r.applied || r.wg.Running() || r.xray.Running() {
		iface := r.ifaceName
		r.applied = false
		r.activeCfg = nil
		r.activePrivKey = ""
		r.revision = ""
		r.ifaceName = ""

		var errs []error
		if iface != "" {
			if err := r.netCfg.Teardown(ctx, iface); err != nil {
				errs = append(errs, err)
			}
		}
		if err := r.wg.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := r.xray.Close(); err != nil {
			errs = append(errs, err)
		}
		r.removeActiveManifest()
		r.mu.Unlock()
		if len(errs) > 0 {
			return fault.New(fault.CodeRuntimeApplyFailed, "stop embedded runtime", errors.Join(errs...))
		}
		return nil
	}
	r.mu.Unlock()

	if manifest, ok := r.readActiveManifest(); ok && isProcessAlive(manifest.PID) {
		if !r.privileged() {
			return fault.New(fault.CodeRuntimePermission, "stop embedded overlay daemon", nil)
		}
		if err := signalProcessStop(manifest.PID); err != nil {
			return fault.New(fault.CodeRuntimeApplyFailed, fmt.Sprintf("signal embedded daemon pid %d", manifest.PID), err)
		}
		r.removeActiveManifest()
	}
	return nil
}

func (r *Runtime) Cleanup(ctx context.Context) error {
	err := r.Down(ctx)
	r.removeActiveManifest()
	return err
}

func (r *Runtime) Diagnose(_ context.Context) ([]overlayruntime.Diagnostic, error) {
	return []overlayruntime.Diagnostic{
		{Code: "embedded_xray_core", Healthy: true},
		{Code: "embedded_wireguard_go", Healthy: true},
		{Code: "platform_runtime_available", Healthy: true},
		{Code: "runtime_privileged", Healthy: r.privileged()},
	}, nil
}

func (r *Runtime) privileged() bool {
	if r.privilegedFn != nil {
		return r.privilegedFn()
	}
	return isPlatformPrivileged()
}

func (r *Runtime) activeManifestPath() string {
	if r.stateDir == "" {
		return ""
	}
	return filepath.Join(r.stateDir, "runtime", "embedded-active.json")
}

func (r *Runtime) writeActiveManifestLocked(cfg model.Config) error {
	manifestPath := r.activeManifestPath()
	if manifestPath == "" {
		return nil
	}
	runtimeDir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return err
	}
	data := activeManifest{
		PID:         os.Getpid(),
		Interface:   r.ifaceName,
		Revision:    cfg.Revision,
		Address:     cfg.WireGuard.Address,
		LocalPort:   cfg.Transport.LocalPort,
		CoreID:      model.CoreIDXray,
		AdapterID:   model.AdapterIDXrayCore,
		RuntimeMode: "embedded",
		StartedAt:   time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp := manifestPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	preserveRuntimeOwnership(r.stateDir, runtimeDir, tmp)
	if err := os.Rename(tmp, manifestPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	preserveRuntimeOwnership(r.stateDir, runtimeDir, manifestPath)
	return nil
}

func (r *Runtime) readActiveManifest() (activeManifest, bool) {
	manifestPath := r.activeManifestPath()
	if manifestPath == "" {
		return activeManifest{}, false
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return activeManifest{}, false
	}
	var m activeManifest
	if err := json.Unmarshal(raw, &m); err != nil || m.PID <= 0 {
		return activeManifest{}, false
	}
	return m, true
}

func (r *Runtime) removeActiveManifest() {
	manifestPath := r.activeManifestPath()
	if manifestPath != "" {
		_ = os.Remove(manifestPath)
	}
}

// reserveFreeUDPPort is a small helper for tests needing an ephemeral UDP loopback port.
func reserveFreeUDPPort() (int, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()
	return addr.Port, nil
}
