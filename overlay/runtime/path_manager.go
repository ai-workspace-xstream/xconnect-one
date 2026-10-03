package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/pathmanager"
)

type meshRuntimeFile struct {
	Config       pathmanager.Config `json:"config"`
	WGConfigPath string             `json:"wg_config_path"`
	StatusPath   string             `json:"status_path"`
}

func freeLocalPort(network string) (string, error) {
	if network == "tcp" {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			return "", e
		}
		defer l.Close()
		return l.Addr().String(), nil
	}
	l, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		return "", e
	}
	defer l.Close()
	return l.LocalAddr().String(), nil
}
func allocateMesh(c *model.Config) error {
	mesh := *c.Mesh
	mesh.Peers = append([]pathmanager.Peer(nil), mesh.Peers...)
	used := map[string]bool{c.WireGuard.PeerEndpoint: true}
	allocate := func(network string) (string, error) {
		for i := 0; i < 32; i++ {
			a, e := freeLocalPort(network)
			if e != nil {
				return "", e
			}
			if !used[a] {
				used[a] = true
				return a, nil
			}
		}
		return "", errors.New("cannot allocate distinct local sockets")
	}
	var e error
	mesh.RelayEndpoint, e = allocate("tcp")
	if e != nil {
		return e
	}
	mesh.WGEndpoint, e = allocate("udp")
	if e != nil {
		return e
	}
	_, p, _ := net.SplitHostPort(mesh.WGEndpoint)
	c.WireGuard.ListenPort, _ = strconv.Atoi(p)
	for i := range mesh.Peers {
		mesh.Peers[i].LocalEndpoint, e = allocate("udp")
		if e != nil {
			return e
		}
	}
	c.Mesh = &mesh
	return c.Validate()
}
func loadMesh(path string) (meshRuntimeFile, error) {
	var f meshRuntimeFile
	if !privateRegularFile(path) {
		return f, errors.New("untrusted path manager file")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return f, e
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		return f, e
	}
	if e = f.Config.Validate(); e != nil {
		return f, e
	}
	dir := filepath.Dir(path)
	if f.WGConfigPath != filepath.Join(dir, f.Config.Interface+".conf") || f.StatusPath != filepath.Join(dir, "paths.json") {
		return f, errors.New("invalid mesh artifact paths")
	}
	return f, nil
}
func meshMatches(manifest desktopManifest, template *pathmanager.Config) bool {
	if template == nil {
		return manifest.PathManager == nil
	}
	if manifest.PathManager == nil {
		return false
	}
	f, e := loadMesh(manifest.PathManager.ConfigPath)
	if e != nil {
		return false
	}
	peers := append([]pathmanager.Peer(nil), f.Config.Peers...)
	for i := range peers {
		peers[i].LocalEndpoint = ""
	}
	return reflect.DeepEqual(peers, template.Peers) && f.Config.NetworkID == template.NetworkID && f.Config.DeviceID == template.DeviceID && f.Config.GatewayPublicKey == template.GatewayPublicKey
}
func refreshMeshExpiry(manifest *desktopManifest, expires time.Time) error {
	f, e := loadMesh(manifest.PathManager.ConfigPath)
	if e != nil {
		return e
	}
	f.Config.ExpiresAt = expires
	raw, e := json.Marshal(f)
	if e != nil {
		return e
	}
	if e = writeFile0600(manifest.PathManager.ConfigPath, raw); e != nil {
		return e
	}
	digest := sha256.Sum256(raw)
	manifest.PathManager.ConfigSHA256 = hex.EncodeToString(digest[:])
	return nil
}
func meshSocketsOwned(backend desktopBackend, manifest desktopManifest) bool {
	f, e := loadMesh(manifest.PathManager.ConfigPath)
	if e != nil {
		return false
	}
	for _, p := range f.Config.Peers {
		owned, e := backend.LoopbackOwned(*manifest.PathManager, p.LocalEndpoint)
		if e != nil || !owned {
			return false
		}
	}
	return true
}
func (r *Desktop) waitForPathManager(ctx context.Context, manifest desktopManifest) error {
	deadline := time.Now().Add(r.readinessTimeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		alive, e := r.backend.ProcessAlive(*manifest.PathManager)
		if e != nil {
			return e
		}
		if alive && meshSocketsOwned(r.backend, manifest) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("path manager sockets not ready")
}

// RunPathManager is an internal subprocess entrypoint; keys stay in the existing
// protected WG file, never in arguments, status, discovery or logs.
func RunPathManager(parent context.Context, args []string) error {
	flags := flag.NewFlagSet("path-manager", flag.ContinueOnError)
	path := flags.String("config", "", "protected runtime configuration")
	if e := flags.Parse(args); e != nil {
		return e
	}
	f, e := loadMesh(*path)
	if e != nil {
		return e
	}
	if !privateRegularFile(f.WGConfigPath) {
		return errors.New("untrusted WireGuard key file")
	}
	raw, e := os.ReadFile(f.WGConfigPath)
	if e != nil {
		return e
	}
	key := ""
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(name) == "PrivateKey" {
			key = strings.TrimSpace(value)
			break
		}
	}
	manager, e := pathmanager.New(f.Config, key, pathmanager.Options{})
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = manager.Start(ctx); e != nil {
		return e
	}
	defer manager.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			next, e := loadMesh(*path)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(f.Config, next.Config) {
				if e = manager.Reconfigure(next.Config); e != nil {
					return e
				}
			}

			f = next
			if e = manager.WriteReport(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(*path))), "overlay-status.json")); e != nil {
				return e
			}
			if e = manager.WriteStatus(f.StatusPath); e != nil {
				return e
			}
		}
	}
}

// reconcileMesh changes signed membership in place. Existing sockets and WG
// sessions survive, while removed peers lose path-manager authority first.
func (r *Desktop) reconcileMesh(ctx context.Context, active desktopManifest, request ApplyRequest, dependencies desktopDependencies) (handled bool, resultErr error) {
	if active.PathManager == nil || request.Config.Mesh == nil {
		return false, nil
	}
	previous, e := loadMesh(active.PathManager.ConfigPath)
	if e != nil {
		return false, e
	}
	config := request.Config
	old := previous.Config
	template := config.Mesh
	if old.NetworkID != template.NetworkID || old.DeviceID != template.DeviceID || old.GatewayPublicKey != template.GatewayPublicKey || old.Interface != template.Interface || old.OverlayCIDR != template.OverlayCIDR {
		return false, nil
	}
	config.Mesh = &old
	_, port, _ := net.SplitHostPort(old.WGEndpoint)
	config.WireGuard.ListenPort, _ = strconv.Atoi(port)
	// Only membership/TTL can change in this transaction; other profile changes
	// retain the existing full runtime transaction and rollback mechanism.
	originalWG, e := os.ReadFile(active.WGConfigPath)
	if e != nil {
		return false, e
	}
	if string(originalWG) != renderWireGuardConfig(config, request.WireGuardPrivateKey) {
		return false, nil
	}
	profile, e := renderXrayConfig(config)
	if e != nil {
		return false, e
	}
	originalXray, e := os.ReadFile(active.XrayConfigPath)
	if e != nil {
		return false, e
	}
	if string(profile) != string(originalXray) {
		return false, nil
	}
	next := old
	next.ExpiresAt = template.ExpiresAt
	next.Peers = append([]pathmanager.Peer(nil), template.Peers...)
	used := map[string]bool{old.RelayEndpoint: true, old.WGEndpoint: true, config.WireGuard.PeerEndpoint: true}
	byID := map[string]pathmanager.Peer{}
	for _, p := range old.Peers {
		byID[p.DeviceID] = p
		used[p.LocalEndpoint] = true
	}
	for i, p := range next.Peers {
		if previous, ok := byID[p.DeviceID]; ok && previous.PublicKey == p.PublicKey && previous.Address == p.Address {
			next.Peers[i].LocalEndpoint = previous.LocalEndpoint
			continue
		}
		for attempts := 0; attempts < 32; attempts++ {
			address, e := freeLocalPort("udp")
			if e != nil {
				return true, e
			}
			if !used[address] {
				next.Peers[i].LocalEndpoint = address
				used[address] = true
				break
			}
		}
		if next.Peers[i].LocalEndpoint == "" {
			return true, errors.New("cannot allocate new peer socket")
		}
	}
	config.Mesh = &next
	if e = config.Validate(); e != nil {
		return true, e
	}
	newFile := previous
	newFile.Config = next
	meshBytes, e := json.Marshal(newFile)
	if e != nil {
		return true, e
	}
	oldMeshBytes, e := os.ReadFile(active.PathManager.ConfigPath)
	if e != nil {
		return true, e
	}
	newWG := []byte(renderWireGuardConfig(config, request.WireGuardPrivateKey))
	syncPath := filepath.Join(filepath.Dir(active.WGConfigPath), "mesh-sync.conf")
	syncConfig := func(raw []byte) []byte {
		var lines []string
		for _, line := range strings.Split(string(raw), "\n") {
			name, _, ok := strings.Cut(line, "=")
			name = strings.TrimSpace(name)
			if ok && (name == "Address" || name == "MTU" || name == "DNS") {
				continue
			}
			lines = append(lines, line)
		}
		return []byte(strings.Join(lines, "\n"))
	}
	candidate := active
	candidate.Revision = config.Revision
	candidate.Xray.Revision = config.Revision
	identity := *active.PathManager
	candidate.PathManager = &identity
	candidate.PathManager.Revision = config.Revision
	hash := sha256.Sum256(meshBytes)
	candidate.PathManager.ConfigSHA256 = hex.EncodeToString(hash[:])
	hash = sha256.Sum256(newWG)
	candidate.WGConfigSHA256 = hex.EncodeToString(hash[:])
	committed := false
	defer func() {
		if !committed {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, writeFile0600(active.PathManager.ConfigPath, oldMeshBytes), writeFile0600(active.WGConfigPath, originalWG))
			if err := writeFile0600(syncPath, syncConfig(originalWG)); err != nil {
				resultErr = errors.Join(resultErr, err)
			} else {
				resultErr = errors.Join(resultErr, r.run(rollbackCtx, dependencies.wg, "syncconf", active.Interface, syncPath))
			}
		}
		_ = os.Remove(syncPath)
	}()
	if e = writeFile0600(active.PathManager.ConfigPath, meshBytes); e != nil {
		return true, e
	}
	if e = r.waitForPathManager(ctx, candidate); e != nil {
		return true, e
	}
	if e = writeFile0600(active.WGConfigPath, newWG); e != nil {
		return true, e
	}
	if e = writeFile0600(syncPath, syncConfig(newWG)); e != nil {
		return true, e
	}
	if e = r.run(ctx, dependencies.wg, "syncconf", active.Interface, syncPath); e != nil {
		return true, e
	}
	if e = r.saveManifest(r.activeManifestPath(), candidate); e != nil {
		return true, e
	}
	committed = true
	return true, nil
}
