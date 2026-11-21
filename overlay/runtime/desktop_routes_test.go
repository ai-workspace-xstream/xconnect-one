package runtime

import (
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/pathmanager"
)

func TestSanitizeWireGuardAllowedIPsKeepsSplitTunnel(t *testing.T) {
	t.Parallel()
	config := model.Config{
		Network:   model.Network{CIDR: "10.66.0.0/16"},
		WireGuard: model.WireGuardConfig{PeerAllowedIPs: []string{"10.66.0.0/16", "10.66.1.0/24"}},
	}
	got, rejected, err := sanitizeWireGuardAllowedIPs(config)
	if err != nil || rejected {
		t.Fatalf("sanitize = %v rejected=%v err=%v", got, rejected, err)
	}
	if len(got) != 2 || got[0] != "10.66.0.0/16" || got[1] != "10.66.1.0/24" {
		t.Fatalf("got %#v", got)
	}
}

func TestSanitizeWireGuardAllowedIPsRejectsDefaultRouteAndUsesOverlayIntent(t *testing.T) {
	t.Parallel()
	config := model.Config{
		Network: model.Network{CIDR: "10.66.0.0/16"},
		WireGuard: model.WireGuardConfig{
			Address:              "10.66.0.8/32",
			GatewayWireGuardCIDR: "10.66.0.0/16",
			PeerAllowedIPs:       []string{"0.0.0.0/0", "::/0"},
		},
		Mesh: &pathmanager.Config{OverlayCIDR: "10.66.0.0/16"},
	}
	got, rejected, err := sanitizeWireGuardAllowedIPs(config)
	if err != nil {
		t.Fatalf("sanitize err: %v", err)
	}
	if !rejected {
		t.Fatal("expected default route to be rejected")
	}
	if len(got) != 2 {
		t.Fatalf("expected overlay address and cidr, got %#v", got)
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "10.66.0.0/16") || !strings.Contains(joined, "10.66.0.8/32") {
		t.Fatalf("got %#v", got)
	}
	for _, ip := range got {
		if isDefaultRoutePrefix(ip) {
			t.Fatalf("default route leaked: %#v", got)
		}
	}
}

func TestSanitizeWireGuardAllowedIPsFailsWithoutOverlayIntent(t *testing.T) {
	t.Parallel()
	config := model.Config{WireGuard: model.WireGuardConfig{PeerAllowedIPs: []string{"0.0.0.0/0"}}}
	_, rejected, err := sanitizeWireGuardAllowedIPs(config)
	if !rejected || fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("rejected=%v err=%v", rejected, err)
	}
	if !strings.Contains(err.Error(), "refuse default-route") {
		t.Fatalf("error = %v", err)
	}
}

func TestRenderWireGuardConfigUsesSanitizedAllowedIPs(t *testing.T) {
	t.Parallel()
	config := model.Config{
		Network: model.Network{CIDR: "10.66.0.0/16"},
		WireGuard: model.WireGuardConfig{
			Address:              "10.66.0.8/32",
			MTU:                  1280,
			PeerPublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			PeerAllowedIPs:       []string{"0.0.0.0/0"},
			PeerEndpoint:         "127.0.0.1:51820",
			GatewayWireGuardCIDR: "10.66.0.0/16",
		},
	}
	allowed, rejected, err := sanitizeWireGuardAllowedIPs(config)
	if err != nil || !rejected {
		t.Fatalf("sanitize: %v rejected=%v", err, rejected)
	}
	config.WireGuard.PeerAllowedIPs = allowed
	rendered := renderWireGuardConfig(config, "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
	if strings.Contains(rendered, "0.0.0.0/0") || strings.Contains(rendered, "::/0") {
		t.Fatalf("rendered default route:\n%s", rendered)
	}
	if !strings.Contains(rendered, "AllowedIPs = 10.66.0.0/16") && !strings.Contains(rendered, "AllowedIPs = 10.66.0.8/32") {
		t.Fatalf("missing overlay AllowedIPs:\n%s", rendered)
	}
}
