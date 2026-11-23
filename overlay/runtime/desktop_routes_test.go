package runtime

import (
	"context"
	"errors"
	"os"
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
	got, rejected, err := SanitizeWireGuardAllowedIPs(config)
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
	got, rejected, err := SanitizeWireGuardAllowedIPs(config)
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
		if IsDefaultRoutePrefix(ip) {
			t.Fatalf("default route leaked: %#v", got)
		}
	}
}

func TestSanitizeWireGuardAllowedIPsFailsWithoutOverlayIntent(t *testing.T) {
	t.Parallel()
	config := model.Config{WireGuard: model.WireGuardConfig{PeerAllowedIPs: []string{"0.0.0.0/0"}}}
	_, rejected, err := SanitizeWireGuardAllowedIPs(config)
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
	allowed, rejected, err := SanitizeWireGuardAllowedIPs(config)
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

func TestDesktopPrepareSanitizesDefaultRouteAllowedIPs(t *testing.T) {
	t.Parallel()
	desktop := newDesktop(t.TempDir(), newFakeDesktopBackend())
	req := desktopApplyRequest("rev_default_route")
	req.Config.WireGuard.PeerAllowedIPs = []string{"0.0.0.0/0", "::/0"}

	manifest, err := desktop.prepare(req, "/usr/bin/xray")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	raw, err := os.ReadFile(manifest.WGConfigPath)
	if err != nil {
		t.Fatalf("read wg config: %v", err)
	}
	rendered := string(raw)
	if strings.Contains(rendered, "0.0.0.0/0") || strings.Contains(rendered, "::/0") {
		t.Fatalf("prepare wrote default route:\n%s", rendered)
	}
	if !strings.Contains(rendered, "AllowedIPs = 10.77.0.0/16") {
		t.Fatalf("missing sanitized overlay AllowedIPs:\n%s", rendered)
	}
}

func TestDesktopStartManifestPreservesHintedStartError(t *testing.T) {
	t.Parallel()
	backend := newFakeDesktopBackend()
	backend.startError = &HintedError{Hint: "systemd-run failed to start the process"}
	desktop := newDesktop(t.TempDir(), backend)
	req := desktopApplyRequest("rev_hint")
	manifest, err := desktop.prepare(req, backend.paths["xray"])
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	deps := desktopDependencies{xray: backend.paths["xray"], wg: backend.paths["wg"], wgQuick: backend.paths["wg-quick"]}
	_, err = desktop.startManifestWithPrivateKey(context.Background(), manifest, deps, req.WireGuardPrivateKey)
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("expected CodeRuntimeApplyFailed, got %v", err)
	}
	var hinted interface{ SafeHint() string }
	if !strings.Contains(err.Error(), "start Xray runtime") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.As(err, &hinted) || !strings.Contains(hinted.SafeHint(), "systemd-run") {
		t.Fatalf("expected SafeHint preserved on wrapped fault error, got %v", err)
	}
}
