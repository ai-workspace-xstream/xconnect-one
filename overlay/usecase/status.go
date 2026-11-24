// Modified for XConnect-One: standalone module imports.
package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

type StatusResult struct {
	Joined      bool             `json:"joined"`
	Controller  string           `json:"controller,omitempty"`
	DeviceID    string           `json:"device_id,omitempty"`
	NetworkID   string           `json:"network_id,omitempty"`
	Address     string           `json:"address,omitempty"`
	OverlayIP   string           `json:"overlay_ip,omitempty"`
	Interface   string           `json:"interface,omitempty"`
	MTU         int              `json:"mtu,omitempty"`
	AllowedIPs  []string         `json:"allowed_ips,omitempty"`
	Revision    string           `json:"revision,omitempty"`
	Gateway     *GatewayStatus   `json:"gateway,omitempty"`
	Generations GenerationStatus `json:"generations"`
	Runtime     runtime.Status   `json:"runtime"`
	Credential  CredentialStatus `json:"credential"`
}

type GatewayStatus struct {
	ID                 string   `json:"id,omitempty"`
	OverlayIP          string   `json:"overlay_ip,omitempty"`
	Endpoint           string   `json:"endpoint,omitempty"`
	EndpointHost       string   `json:"endpoint_host,omitempty"`
	EndpointPort       int      `json:"endpoint_port,omitempty"`
	ServerName         string   `json:"server_name,omitempty"`
	Transport          string   `json:"transport,omitempty"`
	TransportPath      string   `json:"transport_path,omitempty"`
	TransportMode      string   `json:"transport_mode,omitempty"`
	LocalProxyEndpoint string   `json:"local_proxy_endpoint,omitempty"`
	WireGuardPublicKey string   `json:"wireguard_public_key,omitempty"`
	AllowedIPs         []string `json:"allowed_ips,omitempty"`
}

type CredentialStatus struct {
	Backend      string    `json:"backend"`
	Present      bool      `json:"present"`
	CredentialID string    `json:"credential_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Expired      bool      `json:"expired"`
	RotationDue  bool      `json:"rotation_due"`
	Pending      bool      `json:"rotation_pending"`
}

type GenerationStatus struct {
	State           uint64 `json:"state"`
	RuntimeRevision string `json:"runtime_revision,omitempty"`
	Policy          uint64 `json:"policy"`
	PolicyExpired   bool   `json:"policy_expired"`
}

type DiagnosticResult struct {
	Code       string `json:"code"`
	Healthy    bool   `json:"healthy"`
	Generation uint64 `json:"generation,omitempty"`
	Revision   string `json:"revision,omitempty"`
}

func Status(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface) (StatusResult, error) {
	return StatusWithCredential(ctx, store, tunnelRuntime, nil)
}

func StatusWithCredential(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, credentials credential.Store) (StatusResult, error) {
	lastKnown, err := store.LoadLastKnown()
	statePresent := err == nil
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return StatusResult{}, err
	}
	runtimeStatus, err := tunnelRuntime.Status(ctx)
	if err != nil {
		return StatusResult{}, fault.New(fault.CodeRuntimeStatusFailed, "read runtime status", err)
	}
	credentialStatus, err := inspectCredential(ctx, credentials, time.Now().UTC())
	if err != nil {
		return StatusResult{}, err
	}
	generations := GenerationStatus{State: lastKnown.SignedGeneration, RuntimeRevision: runtimeStatus.Revision}
	if !statePresent {
		return StatusResult{Generations: generations, Runtime: runtimeStatus, Credential: credentialStatus}, nil
	}
	policyState, policyErr := store.LoadPolicyState()
	if policyErr == nil && policyState.NetworkID == lastKnown.NetworkID {
		generations.Policy = policyState.Generation
		generations.PolicyExpired = !policyState.ExpiresAt.After(time.Now().UTC())
	} else if policyErr != nil && !errors.Is(policyErr, state.ErrNotFound) {
		return StatusResult{}, policyErr
	}
	addr := strings.TrimSpace(lastKnown.Config.WireGuard.Address)
	if addr == "" {
		addr = strings.TrimSpace(lastKnown.Config.Device.WireGuardAddress)
	}
	if addr == "" {
		addr = strings.TrimSpace(runtimeStatus.Address)
	}
	overlayIP := extractOverlayIP(addr)
	iface := strings.TrimSpace(runtimeStatus.Interface)
	if iface == "" {
		iface = strings.TrimSpace(lastKnown.Config.WireGuard.Interface)
	}
	allowedIPs := append([]string(nil), lastKnown.Config.WireGuard.PeerAllowedIPs...)

	return StatusResult{
		Joined: lastKnown.Phase == state.PhaseAcknowledged &&
			runtimeStatus.Applied &&
			runtimeStatus.Revision == lastKnown.Config.Revision &&
			runtimeStatus.CoreID == model.CoreIDXray &&
			model.SupportedAdapterID(runtimeStatus.AdapterID),
		Controller:  strings.TrimSpace(lastKnown.Server),
		DeviceID:    lastKnown.DeviceID,
		NetworkID:   lastKnown.NetworkID,
		Address:     addr,
		OverlayIP:   overlayIP,
		Interface:   iface,
		MTU:         lastKnown.Config.WireGuard.MTU,
		AllowedIPs:  allowedIPs,
		Revision:    lastKnown.Config.Revision,
		Gateway:     buildGatewayStatus(lastKnown.Config),
		Generations: generations,
		Runtime:     runtimeStatus,
		Credential:  credentialStatus,
	}, nil
}

func extractOverlayIP(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if p, err := netip.ParsePrefix(trimmed); err == nil {
		return p.Addr().String()
	}
	if ip, err := netip.ParseAddr(trimmed); err == nil {
		return ip.String()
	}
	if idx := strings.IndexByte(trimmed, '/'); idx > 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func deriveGatewayOverlayIP(cfg model.Config) string {
	gwIP := strings.TrimSpace(cfg.WireGuard.GatewayWireGuardIP)
	if gwIP != "" && gwIP != "127.0.0.1" && gwIP != "::1" {
		if addr, err := netip.ParseAddr(gwIP); err == nil && !addr.IsLoopback() {
			return addr.String()
		}
	}
	candidates := append([]string(nil), cfg.WireGuard.PeerAllowedIPs...)
	if strings.TrimSpace(cfg.Network.CIDR) != "" {
		candidates = append(candidates, cfg.Network.CIDR)
	}
	for _, raw := range candidates {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !p.Addr().Is4() || p.Bits() <= 0 || p.Bits() >= 31 {
			continue
		}
		masked := p.Masked().Addr().As4()
		masked[3] |= 1
		return netip.AddrFrom4(masked).String()
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(cfg.WireGuard.Address)); err == nil && p.Addr().Is4() {
		a4 := p.Addr().As4()
		a4[3] = 1
		candidate := netip.AddrFrom4(a4)
		if candidate != p.Addr() {
			return candidate.String()
		}
	}
	return ""
}

func buildGatewayStatus(cfg model.Config) *GatewayStatus {
	host := strings.TrimSpace(cfg.Transport.Server)
	if host == "" {
		host = strings.TrimSpace(cfg.Network.GatewayEndpointHost)
	}
	port := cfg.Transport.Port
	if port == 0 {
		port = cfg.Network.GatewayEndpointPort
	}
	if port == 0 {
		port = cfg.Network.TransportPort
	}
	endpoint := host
	if host != "" && port > 0 {
		endpoint = fmt.Sprintf("%s:%d", host, port)
	}
	serverName := strings.TrimSpace(cfg.Transport.ServerName)
	if serverName == "" {
		serverName = strings.TrimSpace(cfg.Network.TransportServerName)
	}
	transport := strings.TrimSpace(cfg.Transport.Type)
	if transport == "" {
		transport = strings.TrimSpace(cfg.Network.TransportKind)
	}
	pubKey := strings.TrimSpace(cfg.WireGuard.PeerPublicKey)
	if pubKey == "" {
		pubKey = strings.TrimSpace(cfg.Network.GatewayWireGuardKey)
	}
	localProxy := strings.TrimSpace(cfg.WireGuard.LocalProxyEndpoint)
	if localProxy == "" && cfg.Transport.LocalPort > 0 {
		localProxy = fmt.Sprintf("127.0.0.1:%d", cfg.Transport.LocalPort)
	}
	gwOverlayIP := deriveGatewayOverlayIP(cfg)
	gwID := strings.TrimSpace(cfg.Network.GatewayID)
	allowed := append([]string(nil), cfg.WireGuard.PeerAllowedIPs...)

	if gwID == "" && host == "" && pubKey == "" && gwOverlayIP == "" && len(allowed) == 0 {
		return nil
	}
	return &GatewayStatus{
		ID:                 gwID,
		OverlayIP:          gwOverlayIP,
		Endpoint:           endpoint,
		EndpointHost:       host,
		EndpointPort:       port,
		ServerName:         serverName,
		Transport:          transport,
		TransportPath:      strings.TrimSpace(cfg.Transport.Path),
		TransportMode:      strings.TrimSpace(cfg.Transport.Mode),
		LocalProxyEndpoint: localProxy,
		WireGuardPublicKey: pubKey,
		AllowedIPs:         allowed,
	}
}

func Diagnose(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface) ([]DiagnosticResult, error) {
	return DiagnoseWithCredential(ctx, store, tunnelRuntime, nil)
}

func DiagnoseWithCredential(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, credentials credential.Store) ([]DiagnosticResult, error) {
	results := make([]DiagnosticResult, 0, 6)
	lastKnown, err := store.LoadLastKnown()
	statePresent := err == nil
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return nil, err
	}
	results = append(results, DiagnosticResult{Code: "last_known_state_present", Healthy: statePresent})
	if statePresent {
		results = append(results,
			DiagnosticResult{Code: "state_file_permissions_0600", Healthy: state.ValidatePermissions(store.LastKnownPath(), 0o600) == nil},
			DiagnosticResult{Code: "proxy_core_xray", Healthy: lastKnown.Config.CoreID() == model.CoreIDXray},
			DiagnosticResult{Code: "state_generation", Healthy: lastKnown.SignedGeneration > 0 || lastKnown.ConfigContract == string(ConfigContractLegacy), Generation: lastKnown.SignedGeneration},
		)
	}
	runtimeDiagnostics, err := tunnelRuntime.Diagnose(ctx)
	if err != nil {
		return nil, fault.New(fault.CodeRuntimeStatusFailed, "diagnose runtime", err)
	}
	for _, item := range runtimeDiagnostics {
		results = append(results, DiagnosticResult{Code: item.Code, Healthy: item.Healthy})
	}
	runtimeStatus, statusErr := tunnelRuntime.Status(ctx)
	if statusErr != nil {
		return nil, fault.New(fault.CodeRuntimeStatusFailed, "diagnose runtime generation", statusErr)
	}
	results = append(results, DiagnosticResult{Code: "runtime_revision", Healthy: runtimeStatus.Revision != "", Revision: runtimeStatus.Revision})
	credentialStatus, credentialErr := inspectCredential(ctx, credentials, time.Now().UTC())
	if credentialErr != nil {
		return nil, credentialErr
	}
	results = append(results,
		DiagnosticResult{Code: "credential_storage_available", Healthy: credentials != nil},
		DiagnosticResult{Code: "device_credential_present", Healthy: credentialStatus.Present},
		DiagnosticResult{Code: "device_credential_not_expired", Healthy: credentialStatus.Present && !credentialStatus.Expired},
	)
	policyState, policyErr := store.LoadPolicyState()
	if errors.Is(policyErr, state.ErrNotFound) {
		results = append(results, DiagnosticResult{Code: "policy_generation", Healthy: false})
	} else if policyErr != nil {
		return nil, policyErr
	} else {
		healthy := statePresent && policyState.NetworkID == lastKnown.NetworkID && policyState.ExpiresAt.After(time.Now().UTC())
		results = append(results, DiagnosticResult{Code: "policy_generation", Healthy: healthy, Generation: policyState.Generation})
	}
	return results, nil
}

func inspectCredential(ctx context.Context, credentials credential.Store, now time.Time) (CredentialStatus, error) {
	if credentials == nil {
		return CredentialStatus{Backend: "unavailable"}, nil
	}
	result := CredentialStatus{Backend: credentials.Backend()}
	record, err := credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return result, nil
	}
	if err != nil {
		return CredentialStatus{}, err
	}
	result.Present = true
	result.CredentialID = record.CredentialID
	result.ExpiresAt = record.ExpiresAt
	result.Expired = record.Expired(now)
	result.RotationDue = record.RotationDue(now)
	result.Pending = record.Pending != nil
	return result, nil
}
