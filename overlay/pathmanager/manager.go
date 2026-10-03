// Package pathmanager adapts each authorized peer independently, below WireGuard.
package pathmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/pathwire"
)

type Options struct {
	ProbeInterval time.Duration
	FailureAfter  time.Duration
	PromoteAfter  int
	// Hooks are for tests or an owning runtime; CLI uses physical on-link networks.
	Candidates func(uint16) []string
	OnLink     func(netip.AddrPort) bool
}
type PeerStatus struct {
	DeviceID        string `json:"device_id"`
	Path            string `json:"path"`
	Endpoint        string `json:"endpoint,omitempty"`
	RTTMillis       int64  `json:"rtt_ms,omitempty"`
	Reason          string `json:"reason"`
	SentPackets     uint64 `json:"sent_packets"`
	ReceivedPackets uint64 `json:"received_packets"`
}
type candidateHealth struct {
	ack     time.Time
	success int
	rtt     time.Duration
}
type peerState struct {
	sendEpoch    string
	sendSequence uint64
	health       map[netip.AddrPort]candidateHealth
	peer         Peer
	key          []byte
	local        *net.UDPConn
	candidates   []netip.AddrPort
	active       netip.AddrPort
	ack          time.Time
	success      int
	pending      map[string]probe
	epoch        string
	high         uint64
	bitmap       uint64
	retired      map[string]bool
	rtt          time.Duration
	sent         uint64
	received     uint64
	reason       string
}
type probe struct {
	address netip.AddrPort
	sent    time.Time
}
type Manager struct {
	cfg        Config
	opt        Options
	privateKey string
	relayKey   []byte
	mu         sync.Mutex
	networkMu  sync.RWMutex
	prefixes   []netip.Prefix
	peers      map[string]*peerState
	lan        *net.UDPConn
	relay      net.Conn
	outbound   chan pathwire.Frame
	expiry     atomic.Int64
	wg         netip.AddrPort
	ctx        context.Context
	cancel     context.CancelFunc
	workers    sync.WaitGroup
}

func New(c Config, privateKey string, opt Options) (*Manager, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if opt.ProbeInterval <= 0 {
		opt.ProbeInterval = time.Second
	}
	if opt.FailureAfter <= 0 {
		opt.FailureAfter = 4 * time.Second
	}
	if opt.PromoteAfter <= 0 {
		opt.PromoteAfter = 3
	}
	key, e := pathwire.Key(privateKey, c.GatewayPublicKey, c.NetworkID, "relay")
	if e != nil {
		return nil, e
	}
	m := &Manager{cfg: c, opt: opt, privateKey: privateKey, relayKey: key, peers: map[string]*peerState{}, outbound: make(chan pathwire.Frame, 256)}
	m.prefixes = m.physicalPrefixes()
	m.expiry.Store(c.ExpiresAt.UnixNano())
	m.wg, _ = netip.ParseAddrPort(c.WGEndpoint)
	for _, p := range c.Peers {
		k, e := pathwire.Key(privateKey, p.PublicKey, c.NetworkID, "peer")
		if e != nil {
			return nil, e
		}
		m.peers[p.DeviceID] = &peerState{sendEpoch: nonce(), peer: p, key: k, pending: map[string]probe{}, retired: map[string]bool{}, health: map[netip.AddrPort]candidateHealth{}, reason: "awaiting LAN proof"}
	}
	return m, nil
}
func nonce() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func (m *Manager) Start(parent context.Context) error {
	m.ctx, m.cancel = context.WithCancel(parent)
	a, e := net.ResolveUDPAddr("udp4", m.cfg.LANListen)
	if e != nil {
		return e
	}
	m.lan, e = net.ListenUDP("udp4", a)
	if e != nil {
		return e
	}
	for _, p := range m.peers {
		a, _ := net.ResolveUDPAddr("udp4", p.peer.LocalEndpoint)
		p.local, e = net.ListenUDP("udp4", a)
		if e != nil {
			m.closeSockets()
			return e
		}
	}
	m.spawn(m.readLAN)
	for _, p := range m.peers {
		p := p
		m.spawn(func() { m.readWG(p) })
	}
	m.spawn(m.relayLoop)
	m.spawn(m.relayWriter)
	m.spawn(m.probeLoop)
	m.spawn(func() { <-m.ctx.Done(); m.closeSockets() })
	return nil
}
func (m *Manager) spawn(f func()) { m.workers.Add(1); go func() { defer m.workers.Done(); f() }() }
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.workers.Wait()
}
func (m *Manager) closeSockets() {
	if m.lan != nil {
		m.lan.Close()
	}
	for _, p := range m.peerSnapshot() {
		if p.local != nil {
			p.local.Close()
		}
	}
	m.mu.Lock()
	if m.relay != nil {
		m.relay.Close()
	}
	m.mu.Unlock()
}
func (m *Manager) LANAddress() netip.AddrPort { return m.lan.LocalAddr().(*net.UDPAddr).AddrPort() }
func (m *Manager) Status() []PeerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := make([]PeerStatus, 0, len(m.peers))
	for _, spec := range m.cfg.Peers {
		p := m.peers[spec.DeviceID]
		s := PeerStatus{DeviceID: p.peer.DeviceID, Path: "relay", Reason: p.reason, SentPackets: p.sent, ReceivedPackets: p.received}
		if p.active.IsValid() {
			s.Path = "direct-lan"
			s.Endpoint = p.active.String()
			s.RTTMillis = p.rtt.Milliseconds()
		}
		r = append(r, s)
	}
	return r
}
func (m *Manager) frame(p *peerState, typ string) pathwire.Frame {
	m.mu.Lock()
	p.sendSequence++
	seq := p.sendSequence
	m.mu.Unlock()
	return pathwire.Frame{Type: typ, Network: m.cfg.NetworkID, From: m.cfg.DeviceID, To: p.peer.DeviceID, Epoch: p.sendEpoch, Seq: seq}
}
func (m *Manager) readWG(p *peerState) {
	b := make([]byte, 4096)
	for {
		n, a, e := p.local.ReadFromUDPAddrPort(b)
		if e != nil {
			if errors.Is(e, net.ErrClosed) || m.ctx.Err() != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if a != m.wg || n == len(b) {
			continue
		}
		m.mu.Lock()
		if m.peers[p.peer.DeviceID] != p {
			m.mu.Unlock()
			return
		}
		p.sent++
		m.mu.Unlock()
		f := m.frame(p, "data")
		f.Payload = append([]byte(nil), b[:n]...)
		f = pathwire.Sign(f, p.key)
		m.mu.Lock()
		target := p.active
		m.mu.Unlock()
		if target.IsValid() {
			if e := m.sendLAN(f, target); e == nil {
				continue
			}
		}
		_ = m.sendRelay(f)
	}
}
func (m *Manager) readLAN() {
	b := make([]byte, pathwire.MaxFrame+1)
	for {
		n, a, e := m.lan.ReadFromUDPAddrPort(b)
		if e != nil {
			if errors.Is(e, net.ErrClosed) || m.ctx.Err() != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		m.mu.Lock()
		ids := make([]string, 0, len(m.peers))
		for id := range m.peers {
			ids = append(ids, id)
		}
		m.mu.Unlock()
		f, e := pathwire.DecodeLAN(b[:n], m.cfg.NetworkID, m.cfg.DeviceID, ids)
		if e == nil {
			m.receive(f, a)
		}
	}
}
func (m *Manager) sendLAN(f pathwire.Frame, a netip.AddrPort) error {
	m.mu.Lock()
	p := m.peers[f.To]
	valid := p != nil && f.Epoch == p.sendEpoch && time.Now().UnixNano() < m.expiry.Load()
	m.mu.Unlock()
	if !valid {
		return errors.New("peer send authority withdrawn")
	}
	b, e := pathwire.EncodeLAN(f)
	if e != nil {
		return e
	}
	_, e = m.lan.WriteToUDPAddrPort(b, a)
	return e
}
func (m *Manager) sendRelay(f pathwire.Frame) error {
	if time.Now().UnixNano() >= m.expiry.Load() {
		return errors.New("relay send authority expired")
	}
	select {
	case m.outbound <- f:
		return nil
	default:
		return errors.New("relay queue full")
	}
}
func (m *Manager) relayWriter() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case f := <-m.outbound:
			var c net.Conn
			for {
				m.mu.Lock()
				c = m.relay
				valid := f.Type == "keepalive" && time.Now().UnixNano() < m.expiry.Load()
				if p := m.peers[f.To]; p != nil {
					valid = f.Epoch == p.sendEpoch && time.Now().UnixNano() < m.expiry.Load() && pathwire.Verify(f, p.key)
				}
				m.mu.Unlock()
				if !valid {
					c = nil
					break
				}
				if c != nil {
					break
				}
				select {
				case <-m.ctx.Done():
					return
				case <-time.After(25 * time.Millisecond):
				}
			}
			if c == nil {
				continue
			}
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if pathwire.Write(c, f) != nil {
				c.Close()
			}
		}
	}
}

// Accept reordered datagrams, reject replay and bounded retired session epochs.
func accept(p *peerState, f pathwire.Frame) bool {
	if len(f.Epoch) != 32 || f.Seq == 0 {
		return false
	}
	if f.Epoch != p.epoch {
		if p.retired[f.Epoch] || (p.epoch != "" && f.Type != "discover") || len(p.retired) >= 64 {
			return false
		}
		if p.epoch != "" {
			p.retired[p.epoch] = true
		}
		p.epoch = f.Epoch
		p.high = 0
		p.bitmap = 0
		p.active = netip.AddrPort{}
		p.success = 0
		p.pending = map[string]probe{}
		p.health = map[netip.AddrPort]candidateHealth{}
	}
	if f.Seq > p.high {
		delta := f.Seq - p.high
		if delta >= 64 {
			p.bitmap = 0
		} else {
			p.bitmap <<= delta
		}
		p.high = f.Seq
		p.bitmap |= 1
		return true
	}
	delta := p.high - f.Seq
	if delta >= 64 || p.bitmap&(uint64(1)<<delta) != 0 {
		return false
	}
	p.bitmap |= uint64(1) << delta
	return true
}
func (m *Manager) receive(f pathwire.Frame, source netip.AddrPort) {
	m.mu.Lock()
	p := m.peers[f.From]
	m.mu.Unlock()
	if p == nil || f.Network != m.cfg.NetworkID || f.To != m.cfg.DeviceID || !pathwire.Verify(f, p.key) || time.Now().UnixNano() >= m.expiry.Load() {
		return
	}
	if source.IsValid() && !m.onLink(source) {
		return
	}
	m.mu.Lock()
	if m.peers[f.From] != p {
		m.mu.Unlock()
		return
	}
	if !accept(p, f) {
		m.mu.Unlock()
		return
	}
	switch f.Type {
	case "discover":
		if source.IsValid() || len(f.Candidates) > 32 {
			m.mu.Unlock()
			return
		}
		var candidates []netip.AddrPort
		for _, s := range f.Candidates {
			a, e := netip.ParseAddrPort(s)
			if e == nil && m.onLink(a) {
				candidates = append(candidates, a)
			}
		}
		health := map[netip.AddrPort]candidateHealth{}
		for _, a := range candidates {
			if h, ok := p.health[a]; ok {
				health[a] = h
			}
		}
		p.health = health
		for nonce, probe := range p.pending {
			found := false
			for _, a := range candidates {
				if a == probe.address {
					found = true
					break
				}
			}
			if !found {
				delete(p.pending, nonce)
			}
		}
		p.candidates = candidates
		if p.active.IsValid() {
			found := false
			for _, a := range candidates {
				if a == p.active {
					found = true
				}
			}
			if !found {
				p.active = netip.AddrPort{}
				p.success = 0
				p.reason = "LAN candidate changed"
			}
		}
	case "probe":
		if !source.IsValid() || len(f.Nonce) != 32 {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		reply := m.frame(p, "ack")
		reply.Nonce = f.Nonce
		_ = m.sendLAN(pathwire.Sign(reply, p.key), source)
		return
	case "ack":
		pending, ok := p.pending[f.Nonce]
		delete(p.pending, f.Nonce)
		if !ok || source != pending.address || time.Since(pending.sent) > m.opt.FailureAfter {
			m.mu.Unlock()
			return
		}
		health := p.health[source]
		if time.Since(health.ack) > m.opt.FailureAfter {
			health.success = 0
		}
		health.ack = time.Now()
		health.rtt = time.Since(pending.sent)
		health.success++
		p.health[source] = health
		if source == p.active {
			p.ack = health.ack
			p.rtt = health.rtt
		}
		// Keep a healthy selected interface; avoid flapping between NICs on tiny RTT changes.
		if !p.active.IsValid() && health.success >= m.opt.PromoteAfter {
			p.active = source
			p.ack = health.ack
			p.rtt = health.rtt
			p.reason = "authenticated LAN probes healthy"
		}

	case "data":
		p.received++
		if len(f.Payload) == 0 || len(f.Payload) > 4096 {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		_, _ = p.local.WriteToUDPAddrPort(f.Payload, m.wg)
		return
	}
	m.mu.Unlock()
}
func (m *Manager) probeLoop() {
	ticker := time.NewTicker(m.opt.ProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if time.Now().UnixNano() >= m.expiry.Load() {
				m.cancel()
				return
			}
			m.networkMu.Lock()
			m.prefixes = m.physicalPrefixes()
			m.networkMu.Unlock()
			candidates := m.candidates()
			for _, p := range m.peerSnapshot() {
				f := m.frame(p, "discover")
				f.Candidates = candidates
				_ = m.sendRelay(pathwire.Sign(f, p.key))
				m.mu.Lock()
				if p.active.IsValid() && time.Since(p.ack) > m.opt.FailureAfter {
					p.active = netip.AddrPort{}
					p.success = 0
					p.reason = "LAN probes timed out"
				}
				addresses := append([]netip.AddrPort(nil), p.candidates...)
				for n, v := range p.pending {
					if time.Since(v.sent) > m.opt.FailureAfter {
						delete(p.pending, n)
					}
				}
				m.mu.Unlock()
				for _, a := range addresses {
					f := m.frame(p, "probe")
					f.Nonce = nonce()
					m.mu.Lock()
					p.pending[f.Nonce] = probe{a, time.Now()}
					m.mu.Unlock()
					_ = m.sendLAN(pathwire.Sign(f, p.key), a)
				}
			}
			_ = m.sendRelay(pathwire.Sign(pathwire.Frame{Type: "keepalive", Network: m.cfg.NetworkID, From: m.cfg.DeviceID}, m.relayKey))
		}
	}
}
func (m *Manager) relayLoop() {
	for m.ctx.Err() == nil {
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(m.ctx, "tcp", m.cfg.RelayEndpoint)
		if e == nil {
			m.serveRelay(c)
			c.Close()
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
func (m *Manager) serveRelay(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	challenge, e := pathwire.Read(c)
	if e != nil || challenge.Type != "challenge" || len(challenge.Nonce) != 32 {
		return
	}
	auth := pathwire.Sign(pathwire.Frame{Type: "auth", Network: m.cfg.NetworkID, From: m.cfg.DeviceID, Nonce: challenge.Nonce}, m.relayKey)
	if pathwire.Write(c, auth) != nil {
		return
	}
	welcome, e := pathwire.Read(c)
	if e != nil || welcome.Type != "welcome" || welcome.Nonce != challenge.Nonce || welcome.Network != m.cfg.NetworkID || welcome.To != m.cfg.DeviceID || !pathwire.Verify(welcome, m.relayKey) {
		return
	}
	_ = c.SetDeadline(time.Time{})
	m.mu.Lock()
	m.relay = c
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.relay == c {
			m.relay = nil
		}
		m.mu.Unlock()
	}()
	for m.ctx.Err() == nil {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, e := pathwire.Read(c)
		if e != nil {
			return
		}
		if f.Type == "keepalive" {
			if !pathwire.Verify(f, m.relayKey) {
				return
			}
			continue
		}
		m.receive(f, netip.AddrPort{})
	}
}
func (m *Manager) candidates() []string {
	port := m.LANAddress().Port()
	if m.opt.Candidates != nil {
		return m.opt.Candidates(port)
	}
	var r []string
	for _, prefix := range m.cachedPrefixes() {
		a := prefix.Addr()
		if a.Is4() && a.IsPrivate() {
			r = append(r, netip.AddrPortFrom(a, port).String())
			if len(r) == 32 {
				break
			}
		}
	}
	return r
}
func (m *Manager) onLink(a netip.AddrPort) bool {
	if m.opt.OnLink != nil {
		return m.opt.OnLink(a)
	}
	if a.Port() == 0 || !a.Addr().Is4() || !a.Addr().IsPrivate() {
		return false
	}
	overlay, _ := netip.ParsePrefix(m.cfg.OverlayCIDR)
	if overlay.Contains(a.Addr()) {
		return false
	}
	for _, prefix := range m.cachedPrefixes() {
		if prefix.Contains(a.Addr()) {
			return true
		}
	}
	return false
}
func (m *Manager) physicalPrefixes() []netip.Prefix {
	interfaces, _ := net.Interfaces()
	var r []netip.Prefix
	for _, iface := range interfaces {
		name := strings.ToLower(iface.Name)
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == m.cfg.Interface || strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "xcon") {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			p, e := netip.ParsePrefix(address.String())
			if e == nil {
				r = append(r, p)
			}
		}
	}
	return r
}
func (m *Manager) WriteStatus(path string) error {
	b, e := json.Marshal(m.Status())
	if e != nil {
		return e
	}
	tmp := filepath.Clean(path) + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

func (m *Manager) RefreshExpiry(expires time.Time) { m.expiry.Store(expires.UnixNano()) }

// WriteReport publishes only telemetry for xconnect-edge-agent. It confers no
// peer authority; Zero still issues the signed mesh grants.
func (m *Manager) WriteReport(path string) error {
	paths := m.Status()
	m.mu.Lock()
	healthy := m.relay != nil
	m.mu.Unlock()
	for _, p := range paths {
		if p.Path == "direct-lan" {
			healthy = true
		}
	}
	report := struct {
		NetworkID    string       `json:"network_id"`
		DeviceID     string       `json:"device_id"`
		Role         string       `json:"role"`
		Capabilities []string     `json:"capabilities"`
		Healthy      bool         `json:"healthy"`
		UpdatedAt    time.Time    `json:"updated_at"`
		ExpiresAt    time.Time    `json:"expires_at"`
		Paths        []PeerStatus `json:"paths"`
	}{m.cfg.NetworkID, m.cfg.DeviceID, "one", []string{"lan-udp-v1", "gateway-relay-v1"}, healthy, time.Now().UTC(), time.Unix(0, m.expiry.Load()).UTC(), paths}
	b, e := json.Marshal(report)
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

func (m *Manager) cachedPrefixes() []netip.Prefix {
	m.networkMu.RLock()
	defer m.networkMu.RUnlock()
	return append([]netip.Prefix(nil), m.prefixes...)
}

// Reconfigure applies newly signed membership without replacing LAN/relay
// sockets or existing peer path state. The owning runtime reconciles WG peers.
func (m *Manager) Reconfigure(c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if c.NetworkID != m.cfg.NetworkID || c.DeviceID != m.cfg.DeviceID || c.GatewayPublicKey != m.cfg.GatewayPublicKey || c.RelayEndpoint != m.cfg.RelayEndpoint || c.LANListen != m.cfg.LANListen || c.WGEndpoint != m.cfg.WGEndpoint || c.Interface != m.cfg.Interface || c.OverlayCIDR != m.cfg.OverlayCIDR {
		return errors.New("mesh transport identity changed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil || m.ctx.Err() != nil {
		return errors.New("path manager stopped")
	}
	next := map[string]*peerState{}
	var created []*peerState
	cleanup := func() {
		for _, p := range created {
			p.local.Close()
		}
	}
	for _, spec := range c.Peers {
		old := m.peers[spec.DeviceID]
		if old != nil && old.peer == spec {
			next[spec.DeviceID] = old
			continue
		}
		key, e := pathwire.Key(m.privateKey, spec.PublicKey, c.NetworkID, "peer")
		if e != nil {
			cleanup()
			return e
		}
		address, _ := net.ResolveUDPAddr("udp4", spec.LocalEndpoint)
		socket, e := net.ListenUDP("udp4", address)
		if e != nil {
			cleanup()
			return e
		}
		p := &peerState{sendEpoch: nonce(), peer: spec, key: key, local: socket, pending: map[string]probe{}, retired: map[string]bool{}, health: map[netip.AddrPort]candidateHealth{}, reason: "awaiting LAN proof"}
		created = append(created, p)
		next[spec.DeviceID] = p
	}
	for id, p := range m.peers {
		if next[id] != p {
			p.local.Close()
		}
	}
	m.peers = next
	m.cfg.Peers = append([]Peer(nil), c.Peers...)
	m.expiry.Store(c.ExpiresAt.UnixNano())
	for _, p := range created {
		p := p
		m.spawn(func() { m.readWG(p) })
	}
	return nil
}
func (m *Manager) peerSnapshot() []*peerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := make([]*peerState, 0, len(m.peers))
	for _, p := range m.peers {
		r = append(r, p)
	}
	return r
}
