package runtime

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/pathmanager"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMeshRuntimeOwnsMultiplePeersAndRefreshesWithoutRestart(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("mesh-revision")
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	gateway, _ := ecdh.X25519().GenerateKey(rand.Reader)
	request.WireGuardPrivateKey = base64.StdEncoding.EncodeToString(key.Bytes())
	request.Config.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString(gateway.PublicKey().Bytes())
	request.Config.Mesh = &pathmanager.Config{NetworkID: request.Config.Network.ID, DeviceID: request.Config.Device.ID, GatewayPublicKey: request.Config.WireGuard.PeerPublicKey, Interface: request.Config.WireGuard.Interface, OverlayCIDR: "10.77.0.0/16", ExpiresAt: time.Now().Add(time.Minute), LANListen: "0.0.0.0:0"}
	for i, id := range []string{"one-b", "one-c"} {
		peer, _ := ecdh.X25519().GenerateKey(rand.Reader)
		address := "10.77.0.3/32"
		if i == 1 {
			address = "10.77.0.4/32"
		}
		request.Config.Mesh.Peers = append(request.Config.Mesh.Peers, pathmanager.Peer{DeviceID: id, PublicKey: base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), Address: address})
	}
	if _, e := runtime.Apply(t.Context(), request); e != nil {
		t.Fatal(e)
	}
	manifest, e := runtime.loadManifest(runtime.activeManifestPath())
	if e != nil {
		t.Fatal(e)
	}
	if manifest.PathManager == nil || len(backend.starts) != 2 {
		t.Fatal("path manager was not started")
	}
	raw, _ := os.ReadFile(manifest.WGConfigPath)
	if strings.Count(string(raw), "[Peer]") != 3 {
		t.Fatal("one peer missing")
	}
	var profile map[string]any
	raw, _ = os.ReadFile(manifest.XrayConfigPath)
	if json.Unmarshal(raw, &profile) != nil || len(profile["inbounds"].([]any)) != 2 {
		t.Fatal("TCP relay inbound missing")
	}
	before := len(backend.starts)
	request.Config.Mesh.ExpiresAt = time.Now().Add(2 * time.Minute)
	if _, e = runtime.Apply(t.Context(), request); e != nil {
		t.Fatal(e)
	}
	if len(backend.starts) != before {
		t.Fatal("TTL renewal restarted runtime")
	}
	previous, e := loadMesh(manifest.PathManager.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	request.Config.Revision = "mesh-revision-2"
	request.Config.Mesh.Peers = request.Config.Mesh.Peers[1:]
	if _, e = runtime.Apply(t.Context(), request); e != nil {
		t.Fatal(e)
	}
	updated, e := runtime.loadManifest(runtime.activeManifestPath())
	if e != nil {
		t.Fatal(e)
	}
	current, e := loadMesh(updated.PathManager.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	if len(backend.starts) != before || len(backend.stops) != 0 || updated.Xray.PID != manifest.Xray.PID || updated.PathManager.PID != manifest.PathManager.PID {
		t.Fatal("membership restarted runtime")
	}
	if len(current.Config.Peers) != 1 || current.Config.Peers[0].LocalEndpoint != previous.Config.Peers[1].LocalEndpoint {
		t.Fatal("unaffected peer socket changed")
	}
	if !strings.Contains(strings.Join(backend.runs, "\n"), "wg syncconf ") {
		t.Fatal("membership not applied to WireGuard")
	}
	request.Config.Revision = "mesh-revision-3"
	keyD, _ := ecdh.X25519().GenerateKey(rand.Reader)
	request.Config.Mesh.Peers = append(request.Config.Mesh.Peers, pathmanager.Peer{DeviceID: "one-d", PublicKey: base64.StdEncoding.EncodeToString(keyD.PublicKey().Bytes()), Address: "10.77.0.5/32"})
	if _, e = runtime.Apply(t.Context(), request); e != nil {
		t.Fatal(e)
	}
	if len(backend.starts) != before {
		t.Fatal("joining peer restarted runtime")
	}
	beforeFailure, e := runtime.loadManifest(runtime.activeManifestPath())
	if e != nil {
		t.Fatal(e)
	}
	request.Config.Revision = "mesh-revision-failure"
	request.Config.Mesh.Peers = request.Config.Mesh.Peers[:1]
	backend.runErrorContains["wg syncconf "] = []error{errors.New("injected sync failure")}
	if _, e = runtime.Apply(t.Context(), request); e == nil {
		t.Fatal("failed WG reconciliation accepted")
	}
	afterFailure, e := runtime.loadManifest(runtime.activeManifestPath())
	if e != nil {
		t.Fatal(e)
	}
	restored, e := loadMesh(afterFailure.PathManager.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	if afterFailure.Revision != beforeFailure.Revision || len(restored.Config.Peers) != 2 || len(backend.starts) != before {
		t.Fatal("failed update did not preserve previous runtime")
	}
	if e = runtime.Down(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(backend.stops) != 2 {
		t.Fatal("owned runtime processes not stopped")
	}
}

// Export actual renderer output for cross-repository Xray transport tests.
func TestExportMeshXrayProfiles(t *testing.T) {
	dir := os.Getenv("XCONNECT_MESH_FIXTURE_DIR")
	if dir == "" {
		t.Skip("cross-repository runner only")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "fixtures.json"))
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		One []signedconfig.Config `json:"one"`
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, signed := range fixture.One {
		compiled, e := signedconfig.Compile(signed)
		if e != nil {
			t.Fatal(e)
		}
		baseline, e := freeLocalPort("udp")
		if e != nil {
			t.Fatal(e)
		}
		_, port, _ := net.SplitHostPort(baseline)
		compiled.Transport.LocalPort, _ = strconv.Atoi(port)
		compiled.WireGuard.PeerEndpoint = baseline
		compiled.WireGuard.LocalProxyEndpoint = baseline
		if e = allocateMesh(&compiled); e != nil {
			t.Fatal(e)
		}
		profile, e := renderXrayConfig(compiled)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, signed.DeviceID+".xray.json"), profile, 0600); e != nil {
			t.Fatal(e)
		}
		raw, e = json.Marshal(compiled)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, signed.DeviceID+".runtime.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
