package embedded

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
)

type fakeNetConfigurator struct {
	createCalls    int
	configureCalls int
	teardownCalls  int
	lastIface      string
	lastLocalAddr  netip.Prefix
	lastAllowed    []netip.Prefix
	chTUN          *tuntest.ChannelTUN
}

func (f *fakeNetConfigurator) CreateTUN(desiredName string, _ int) (tun.Device, string, error) {
	f.createCalls++
	f.chTUN = tuntest.NewChannelTUN()
	name := strings.TrimSpace(desiredName)
	if name == "" {
		name = "utun99"
	}
	f.lastIface = name
	return f.chTUN.TUN(), name, nil
}

func (f *fakeNetConfigurator) Configure(_ context.Context, ifaceName string, localAddr netip.Prefix, _ int, allowedIPs []netip.Prefix) error {
	f.configureCalls++
	f.lastIface = ifaceName
	f.lastLocalAddr = localAddr
	f.lastAllowed = append([]netip.Prefix(nil), allowedIPs...)
	return nil
}

func (f *fakeNetConfigurator) Teardown(_ context.Context, ifaceName string) error {
	f.teardownCalls++
	f.lastIface = ifaceName
	return nil
}

func generateTestKeys(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()), base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func sampleEmbeddedConfig(t *testing.T, localPort int, peerPubB64 string) model.Config {
	t.Helper()
	return model.Config{
		SchemaVersion: model.SchemaVersionV1,
		Revision:      "rev-1",
		Digest:        "digest-1",
		Network: model.Network{
			ID:                  "net-ph-xconnect",
			GatewayID:           "gw-ph-01",
			GatewayWireGuardKey: peerPubB64,
			GatewayEndpointHost: "127.0.0.1",
			GatewayEndpointPort: 51820,
			TransportServerName: "gateway.test.invalid",
			TransportPort:       443,
			TransportAuthID:     "11111111-1111-1111-1111-111111111111",
		},
		Device: model.Device{
			ID:               "mac-test",
			NetworkID:        "net-ph-xconnect",
			WireGuardAddress: "10.66.0.2/24",
		},
		WireGuard: model.WireGuardConfig{
			Interface:            "xconone0",
			Address:              "10.66.0.2/24",
			MTU:                  1420,
			PrivateKeyRef:        "device-wireguard-private-key",
			PeerPublicKey:        peerPubB64,
			PeerAllowedIPs:       []string{"10.66.0.0/24"},
			PeerEndpoint:         "127.0.0.1:" + itoa(localPort),
			PersistentKeepalive:  25,
			GatewayWireGuardIP:   "10.66.0.1",
			GatewayWireGuardCIDR: "10.66.0.1/32",
			LocalProxyEndpoint:   "127.0.0.1:" + itoa(localPort),
		},
		Transport: model.TransportConfig{
			Runtime:        model.WireRuntimeXrayCore,
			Type:           model.TransportVLESSXHTTP,
			Security:       model.TransportSecurityTLS,
			Server:         "127.0.0.1",
			ServerName:     "gateway.test.invalid",
			Port:           443,
			UUID:           "11111111-1111-1111-1111-111111111111",
			Path:           "/xconnect",
			Mode:           "auto",
			Host:           "gateway.test.invalid",
			PacketEncoding: model.PacketEncodingXUDP,
			LocalPort:      localPort,
		},
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestMinimalXrayHostStartRestartClose(t *testing.T) {
	port, err := reserveFreeUDPPort()
	if err != nil {
		t.Fatalf("reserveFreeUDPPort: %v", err)
	}
	_, peerPub := generateTestKeys(t)
	cfg := sampleEmbeddedConfig(t, port, peerPub)

	host := newXrayHost()
	if err := host.Start(cfg); err != nil {
		t.Fatalf("xrayHost.Start: %v", err)
	}
	if !host.Running() {
		t.Fatal("expected xrayHost to report running after Start")
	}

	changed, err := host.Update(cfg)
	if err != nil || changed {
		t.Fatalf("expected identical Update to be no-op, got changed=%v err=%v", changed, err)
	}

	if err := host.Restart(cfg); err != nil {
		t.Fatalf("xrayHost.Restart: %v", err)
	}
	if !host.Running() {
		t.Fatal("expected xrayHost running after Restart")
	}

	if err := host.Close(); err != nil {
		t.Fatalf("xrayHost.Close: %v", err)
	}
	if host.Running() {
		t.Fatal("expected xrayHost stopped after Close")
	}
}

func TestWireGuardHostUAPIConfigStatsAndNudge(t *testing.T) {
	port, err := reserveFreeUDPPort()
	if err != nil {
		t.Fatalf("reserveFreeUDPPort: %v", err)
	}
	privB64, _ := generateTestKeys(t)
	_, peerPub := generateTestKeys(t)
	cfg := sampleEmbeddedConfig(t, port, peerPub)

	chTUN := tuntest.NewChannelTUN()
	host := newWGHost()
	if err := host.Start(chTUN.TUN(), "utuntest0", privB64, cfg); err != nil {
		t.Fatalf("wgHost.Start: %v", err)
	}
	defer func() { _ = host.Close() }()

	hs, rx, _, err := host.Stats()
	if err != nil {
		t.Fatalf("wgHost.Stats: %v", err)
	}
	if !hs.IsZero() || rx != 0 {
		t.Fatalf("expected clean initial handshake/rx stats, got hs=%v rx=%d", hs, rx)
	}

	if err := host.NudgePeer(); err != nil {
		t.Fatalf("wgHost.NudgePeer: %v", err)
	}

	sampleStats := "private_key=00\npublic_key=11\nlast_handshake_time_sec=1700000000\nrx_bytes=1234\ntx_bytes=5678\n"
	parsedHS, parsedRX, parsedTX := parseUAPIGetStats(sampleStats)
	if parsedHS.Unix() != 1700000000 || parsedRX != 1234 || parsedTX != 5678 {
		t.Fatalf("unexpected parsed UAPI stats: hs=%v rx=%d tx=%d", parsedHS, parsedRX, parsedTX)
	}
}

func TestEmbeddedRuntimeLifecycleAndLevel1HotRestart(t *testing.T) {
	port, err := reserveFreeUDPPort()
	if err != nil {
		t.Fatalf("reserveFreeUDPPort: %v", err)
	}
	privB64, _ := generateTestKeys(t)
	_, peerPub := generateTestKeys(t)
	cfg := sampleEmbeddedConfig(t, port, peerPub)

	stateDir := t.TempDir()
	fakeNet := &fakeNetConfigurator{}
	rt := New(stateDir)
	rt.netCfg = fakeNet
	rt.privilegedFn = func() bool { return true }

	res, err := rt.Apply(context.Background(), overlayruntime.ApplyRequest{
		Config:              cfg,
		WireGuardPrivateKey: privB64,
	})
	if err != nil {
		t.Fatalf("Runtime.Apply: %v", err)
	}
	if res.Revision != "rev-1" || res.CoreID != model.CoreIDXray || res.AdapterID != model.AdapterIDXrayCore {
		t.Fatalf("unexpected ApplyResult: %+v", res)
	}
	if fakeNet.createCalls != 1 || fakeNet.configureCalls != 1 {
		t.Fatalf("unexpected netConfigurator counts: create=%d configure=%d", fakeNet.createCalls, fakeNet.configureCalls)
	}

	manifestPath := filepath.Join(stateDir, "runtime", "embedded-active.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected active manifest at %s: %v", manifestPath, err)
	}

	health, err := rt.DataPlaneHealth(context.Background())
	if err != nil {
		t.Fatalf("DataPlaneHealth: %v", err)
	}
	if !health.Applied || !health.XrayAlive || !health.LoopbackOwned || !health.HasStats || health.Interface != "xconone0" {
		t.Fatalf("unexpected DataPlaneHealth: %+v", health)
	}

	// Level-1 Hot Restart must keep TUN device/routes untouched.
	if err := rt.RestartTransport(context.Background()); err != nil {
		t.Fatalf("RestartTransport: %v", err)
	}
	if fakeNet.createCalls != 1 || fakeNet.teardownCalls != 0 {
		t.Fatalf("RestartTransport must not recreate TUN or tear down routes: create=%d teardown=%d", fakeNet.createCalls, fakeNet.teardownCalls)
	}

	// Second Apply with updated revision reuses TUN & updates routes in place.
	cfg.Revision = "rev-2"
	res2, err := rt.Apply(context.Background(), overlayruntime.ApplyRequest{
		Config:              cfg,
		WireGuardPrivateKey: privB64,
	})
	if err != nil || res2.Revision != "rev-2" {
		t.Fatalf("in-place Apply failed: res=%+v err=%v", res2, err)
	}
	if fakeNet.createCalls != 1 || fakeNet.configureCalls != 2 {
		t.Fatalf("in-place Apply should reuse TUN (create=%d, configure=%d)", fakeNet.createCalls, fakeNet.configureCalls)
	}

	status, err := rt.Status(context.Background())
	if err != nil || !status.Applied || status.RuntimeVersion != "embedded" || status.Revision != "rev-2" {
		t.Fatalf("unexpected Status: %+v err=%v", status, err)
	}

	if err := rt.Down(context.Background()); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if fakeNet.teardownCalls != 1 {
		t.Fatalf("expected Teardown called once on Down, got %d", fakeNet.teardownCalls)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("expected active manifest removed after Down, stat err=%v", err)
	}

	// Confirm the compiled test binary runs quickly after cleanup.
	time.Sleep(10 * time.Millisecond)
}

func TestEmbeddedRuntimeReadsActiveManifestFromAnotherInstance(t *testing.T) {
	stateDir := t.TempDir()
	writer := New(stateDir)
	writer.ifaceName = "xconone0"
	if err := writer.writeActiveManifestLocked(model.Config{
		Revision:  "rev-manifest",
		WireGuard: model.WireGuardConfig{Address: "10.66.0.6/32"},
		Transport: model.TransportConfig{LocalPort: 51830},
	}); err != nil {
		t.Fatalf("writeActiveManifestLocked: %v", err)
	}

	reader := New(stateDir)
	status, err := reader.Status(context.Background())
	if err != nil {
		t.Fatalf("reader.Status: %v", err)
	}
	if !status.Applied || !status.ManagedRuntime || status.RuntimeVersion != "embedded" || status.Revision != "rev-manifest" || status.Interface != "xconone0" {
		t.Fatalf("unexpected reader status: %+v", status)
	}
}
