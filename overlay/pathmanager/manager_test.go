package pathmanager

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/pathwire"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestReplayWindowAllowsReorderingAndRejectsRetiredEpoch(t *testing.T) {
	p := &peerState{retired: map[string]bool{}, pending: map[string]probe{}}
	f := pathwire.Frame{Type: "data", Epoch: "11111111111111111111111111111111", Seq: 2}
	if !accept(p, f) {
		t.Fatal("initial authenticated data rejected")
	}
	f.Seq = 1
	if !accept(p, f) {
		t.Fatal("reordered data rejected")
	}
	if accept(p, f) {
		t.Fatal("replay accepted")
	}
	f.Epoch = "22222222222222222222222222222222"
	f.Type = "discover"
	f.Seq = 1
	if !accept(p, f) {
		t.Fatal("new session rejected")
	}
	f.Epoch = "11111111111111111111111111111111"
	f.Seq = 3
	if accept(p, f) {
		t.Fatal("retired epoch accepted")
	}
}
func TestLANFrameBoundariesAndIdentityBinding(t *testing.T) {
	a, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encode := base64.StdEncoding.EncodeToString
	key, e := pathwire.Key(encode(a.Bytes()), encode(b.PublicKey().Bytes()), "network", "peer")
	if e != nil {
		t.Fatal(e)
	}
	other, e := pathwire.Key(encode(b.Bytes()), encode(a.PublicKey().Bytes()), "network", "peer")
	if e != nil {
		t.Fatal(e)
	}
	f := pathwire.Sign(pathwire.Frame{Type: "data", Network: "network", From: "one-a", To: "one-b", Epoch: "11111111111111111111111111111111", Seq: 1, Payload: make([]byte, 1280+32)}, key)
	raw, e := pathwire.EncodeLAN(f)
	if e != nil {
		t.Fatal(e)
	}
	if len(raw)+28 > 1500 {
		t.Fatal("LAN envelope fragments at standard MTU")
	}
	decoded, e := pathwire.DecodeLAN(raw, "network", "one-b", []string{"one-a"})
	if e != nil || !pathwire.Verify(decoded, other) {
		t.Fatal("LAN roundtrip failed")
	}
	if _, e = pathwire.DecodeLAN(raw, "other-network", "one-b", []string{"one-a"}); e == nil {
		t.Fatal("cross-network frame accepted")
	}
	raw[len(raw)-1] ^= 1
	decoded, _ = pathwire.DecodeLAN(raw, "network", "one-b", []string{"one-a"})
	if pathwire.Verify(decoded, other) {
		t.Fatal("tampered payload accepted")
	}
}
func TestProbeRequiresPendingNonceAndCurrentAuthority(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	peer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	gateway, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encode := base64.StdEncoding.EncodeToString
	config := Config{NetworkID: "net", DeviceID: "one-a", GatewayPublicKey: encode(gateway.PublicKey().Bytes()), RelayEndpoint: "127.0.0.1:1", LANListen: "127.0.0.1:0", WGEndpoint: "127.0.0.1:2", OverlayCIDR: "10.79.0.0/24", ExpiresAt: time.Now().Add(time.Minute), Peers: []Peer{{DeviceID: "one-b", PublicKey: encode(peer.PublicKey().Bytes()), Address: "10.79.0.3/32", LocalEndpoint: "127.0.0.1:3"}}}
	m, e := New(config, encode(key.Bytes()), Options{PromoteAfter: 1, OnLink: func(a netip.AddrPort) bool { return a.Addr().IsLoopback() }})
	if e != nil {
		t.Fatal(e)
	}
	p := m.peers["one-b"]
	address := netip.MustParseAddrPort("127.0.0.1:4")
	known := nonce()
	p.pending[known] = probe{address, time.Now()}
	f := pathwire.Frame{Type: "ack", Network: "net", From: "one-b", To: "one-a", Epoch: nonce(), Seq: 1, Nonce: nonce()}
	p.epoch = f.Epoch // Candidate exchange already established this remote session.
	m.receive(pathwire.Sign(f, p.key), address)
	if p.active.IsValid() {
		t.Fatal("unsolicited ACK promoted LAN")
	}
	f.Seq++
	f.Nonce = known
	m.receive(pathwire.Sign(f, p.key), address)
	if p.active != address {
		t.Fatal("valid ACK did not promote LAN")
	}
	m.RefreshExpiry(time.Now().Add(-time.Second))
	stale := m.frame(p, "probe")
	if m.sendRelay(stale) == nil || m.sendLAN(stale, netip.MustParseAddrPort("127.0.0.1:2")) == nil {
		t.Fatal("expired send accepted")
	}
	p.active = netip.AddrPort{}
	known = nonce()
	p.pending[known] = probe{address, time.Now()}
	f.Seq++
	f.Nonce = known
	m.receive(pathwire.Sign(f, p.key), address)
	if p.active.IsValid() {
		t.Fatal("expired grant used for LAN")
	}
}

func TestReconfigurePreservesExistingPeerAndOwnsNewSockets(t *testing.T) {
	encode := base64.StdEncoding.EncodeToString
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	gateway, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c, _ := ecdh.X25519().GenerateKey(rand.Reader)
	port := func() string {
		socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		address := socket.LocalAddr().String()
		socket.Close()
		return address
	}
	config := Config{NetworkID: "net", DeviceID: "one-a", GatewayPublicKey: encode(gateway.PublicKey().Bytes()), RelayEndpoint: "127.0.0.1:1", LANListen: "127.0.0.1:0", WGEndpoint: port(), OverlayCIDR: "10.79.0.0/24", ExpiresAt: time.Now().Add(time.Minute), Peers: []Peer{{DeviceID: "one-b", PublicKey: encode(b.PublicKey().Bytes()), Address: "10.79.0.3/32", LocalEndpoint: port()}}}
	m, e := New(config, encode(key.Bytes()), Options{ProbeInterval: time.Millisecond * 5})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Start(t.Context()); e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	original := m.peerSnapshot()[0]
	originalLAN := m.LANAddress()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			m.Status()
			time.Sleep(time.Microsecond)
		}
	}()
	for i := 0; i < 10; i++ {
		next := config
		next.Peers = append(append([]Peer(nil), config.Peers...), Peer{DeviceID: "one-c", PublicKey: encode(c.PublicKey().Bytes()), Address: "10.79.0.4/32", LocalEndpoint: port()})
		if e = m.Reconfigure(next); e != nil {
			t.Fatal(e)
		}
		if len(m.Status()) != 2 || m.LANAddress() != originalLAN {
			t.Fatal("new membership not installed")
		}
		if e = m.Reconfigure(config); e != nil {
			t.Fatal(e)
		}
		if m.peerSnapshot()[0] != original {
			t.Fatal("unchanged peer replaced")
		}
		address, _ := net.ResolveUDPAddr("udp4", next.Peers[1].LocalEndpoint)
		socket, e := net.ListenUDP("udp4", address)
		if e != nil {
			t.Fatal("removed peer socket remained open", e)
		}
		socket.Close()
	}
	<-done
}

func TestIdleKeepaliveElectionAndReplaySequenceArePerPeer(t *testing.T) {
	for _, pair := range [][2]string{{"uuid-z", "uuid-a"}, {"node-41", "node-42"}} {
		if WireGuardKeepalive(pair[0], pair[1])+WireGuardKeepalive(pair[1], pair[0]) != 5 {
			t.Fatal("pair has ambiguous idle initiator")
		}
	}
	m := &Manager{cfg: Config{NetworkID: "net", DeviceID: "node"}}
	a, b := &peerState{peer: Peer{DeviceID: "a"}, sendEpoch: nonce()}, &peerState{peer: Peer{DeviceID: "b"}, sendEpoch: nonce()}
	first := m.frame(a, "data")
	for i := 0; i < 500; i++ {
		m.frame(b, "probe")
	}
	second := m.frame(a, "data")
	if first.Seq != 1 || second.Seq != 2 || first.Epoch != second.Epoch || first.Epoch == b.sendEpoch {
		t.Fatal("peer traffic shares replay sequence or epoch")
	}
}
