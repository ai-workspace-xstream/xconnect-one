package embedded

import (
	"context"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/pathmanager"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
)

func TestParseNetworkPrefixesKeepsSplitTunnelAndRejectsDefaultRoute(t *testing.T) {
	t.Parallel()
	cfg := model.Config{
		Network: model.Network{CIDR: "10.66.0.0/16"},
		WireGuard: model.WireGuardConfig{
			Address:              "10.66.0.8/32",
			GatewayWireGuardCIDR: "10.66.0.0/16",
			PeerAllowedIPs:       []string{"10.66.0.0/16", "10.66.2.0/24"},
		},
	}
	local, allowed, err := parseNetworkPrefixes(cfg)
	if err != nil {
		t.Fatalf("parseNetworkPrefixes split-tunnel: %v", err)
	}
	if local.String() != "10.66.0.8/32" {
		t.Fatalf("local = %s", local)
	}
	if len(allowed) != 2 || allowed[0].String() != "10.66.0.0/16" || allowed[1].String() != "10.66.2.0/24" {
		t.Fatalf("allowed = %#v", allowed)
	}

	cfg.WireGuard.PeerAllowedIPs = []string{"0.0.0.0/0", "::/0"}
	cfg.Mesh = &pathmanager.Config{OverlayCIDR: "10.66.0.0/16"}
	_, allowed, err = parseNetworkPrefixes(cfg)
	if err != nil {
		t.Fatalf("parseNetworkPrefixes default-route fallback: %v", err)
	}
	if len(allowed) == 0 {
		t.Fatal("expected overlay route intent prefixes")
	}
	for _, p := range allowed {
		if p.Bits() == 0 {
			t.Fatalf("default route leaked into allowed prefixes: %#v", allowed)
		}
	}
}

func TestBuildUAPISetConfigRejectsDefaultRouteAndFailsWithoutIntent(t *testing.T) {
	t.Parallel()
	privB64, _ := generateTestKeys(t)
	_, peerPubB64 := generateTestKeys(t)

	cfg := sampleEmbeddedConfig(t, 51820, peerPubB64)
	cfg.Network.CIDR = "10.66.0.0/16"
	cfg.WireGuard.PeerAllowedIPs = []string{"0.0.0.0/0", "::/0"}

	uapi, _, _, err := buildUAPISetConfig(privB64, cfg)
	if err != nil {
		t.Fatalf("buildUAPISetConfig with overlay intent: %v", err)
	}
	if strings.Contains(uapi, "allowed_ip=0.0.0.0/0") || strings.Contains(uapi, "allowed_ip=::/0") {
		t.Fatalf("UAPI leaked default route:\n%s", uapi)
	}
	if !strings.Contains(uapi, "allowed_ip=10.66.0.0/16") {
		t.Fatalf("expected overlay CIDR in UAPI:\n%s", uapi)
	}

	// Without any overlay CIDR intent, buildUAPISetConfig must fail closed.
	noIntent := model.Config{
		WireGuard: model.WireGuardConfig{
			PeerPublicKey:  peerPubB64,
			PeerAllowedIPs: []string{"0.0.0.0/0"},
		},
		Transport: model.TransportConfig{LocalPort: 51820},
	}
	_, _, _, err = buildUAPISetConfig(privB64, noIntent)
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("expected CodeRuntimeApplyFailed without overlay intent, got %v", err)
	}
}

func TestEmbeddedRuntimeApplySanitizesDefaultRouteAllowedIPs(t *testing.T) {
	port, err := reserveFreeUDPPort()
	if err != nil {
		t.Fatalf("reserveFreeUDPPort: %v", err)
	}
	privB64, _ := generateTestKeys(t)
	_, peerPubB64 := generateTestKeys(t)
	cfg := sampleEmbeddedConfig(t, port, peerPubB64)
	cfg.Network.CIDR = "10.66.0.0/16"
	cfg.WireGuard.PeerAllowedIPs = []string{"0.0.0.0/0", "::/0"}

	fakeNet := &fakeNetConfigurator{}
	rt := New(t.TempDir())
	rt.netCfg = fakeNet
	rt.privilegedFn = func() bool { return true }

	if _, err := rt.Apply(context.Background(), overlayruntime.ApplyRequest{
		Config:              cfg,
		WireGuardPrivateKey: privB64,
	}); err != nil {
		t.Fatalf("Runtime.Apply: %v", err)
	}
	t.Cleanup(func() { _ = rt.Down(context.Background()) })

	if len(fakeNet.lastAllowed) == 0 {
		t.Fatal("expected sanitized routes installed")
	}
	for _, p := range fakeNet.lastAllowed {
		if p.Bits() == 0 {
			t.Fatalf("default route passed to NetConfigurator: %#v", fakeNet.lastAllowed)
		}
	}
}
