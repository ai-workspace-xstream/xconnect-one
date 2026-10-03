package pathmanager

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"time"
)

const MaxPeers = 256

type Peer struct {
	DeviceID      string `json:"device_id"`
	PublicKey     string `json:"public_key"`
	Address       string `json:"address"`
	LocalEndpoint string `json:"local_endpoint,omitempty"`
}

// Spec is signed by Zero. LAN addresses are runtime candidates, never authority.
// Peers authorize whole-device traffic only; restricted ACLs must not issue Spec.
type Spec struct {
	Peers []Peer `json:"peers"`
}

type Config struct {
	NetworkID        string    `json:"network_id"`
	DeviceID         string    `json:"device_id"`
	GatewayPublicKey string    `json:"gateway_public_key"`
	RelayEndpoint    string    `json:"relay_endpoint"`
	LANListen        string    `json:"lan_listen"`
	WGEndpoint       string    `json:"wg_endpoint"`
	Interface        string    `json:"interface"`
	OverlayCIDR      string    `json:"overlay_cidr"`
	ExpiresAt        time.Time `json:"expires_at"`
	Peers            []Peer    `json:"peers"`
}

func (s Spec) Validate(self string) error {
	if len(s.Peers) == 0 || len(s.Peers) > MaxPeers {
		return errors.New("invalid mesh peer count")
	}
	ids, keys, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range s.Peers {
		k, e := base64.StdEncoding.DecodeString(p.PublicKey)
		a, ae := netip.ParsePrefix(p.Address)
		if p.DeviceID == "" || len(p.DeviceID) > 128 || p.DeviceID == self || ids[p.DeviceID] || keys[p.PublicKey] || e != nil || len(k) != 32 || base64.StdEncoding.EncodeToString(k) != p.PublicKey || ae != nil || a.Bits() != a.Addr().BitLen() || a.String() != p.Address || addresses[p.Address] || p.LocalEndpoint != "" {
			return errors.New("invalid mesh peer")
		}
		ids[p.DeviceID] = true
		keys[p.PublicKey] = true
		addresses[p.Address] = true
	}
	return nil
}
func (c Config) Validate() error {
	if c.NetworkID == "" || c.DeviceID == "" || !c.ExpiresAt.After(time.Now()) || c.ExpiresAt.After(time.Now().Add(16*time.Minute)) {
		return errors.New("invalid mesh identity or lifetime")
	}
	peers := append([]Peer(nil), c.Peers...)
	endpoints := map[string]bool{}
	for i, p := range peers {
		if !loopback(p.LocalEndpoint) || endpoints[p.LocalEndpoint] || p.LocalEndpoint == c.RelayEndpoint || p.LocalEndpoint == c.WGEndpoint {
			return errors.New("invalid peer local endpoint")
		}
		endpoints[p.LocalEndpoint] = true
		peers[i].LocalEndpoint = ""
	}
	if e := (Spec{Peers: peers}).Validate(c.DeviceID); e != nil {
		return e
	}
	if !loopback(c.RelayEndpoint) || !loopback(c.WGEndpoint) || c.RelayEndpoint == c.WGEndpoint {
		return errors.New("invalid local transport")
	}
	if _, e := netip.ParsePrefix(c.OverlayCIDR); e != nil {
		return errors.New("invalid overlay prefix")
	}
	if _, e := net.ResolveUDPAddr("udp4", c.LANListen); e != nil {
		return errors.New("invalid LAN listener")
	}
	return nil
}
func loopback(s string) bool {
	a, e := netip.ParseAddrPort(s)
	return e == nil && a.Addr() == netip.MustParseAddr("127.0.0.1") && a.Port() != 0
}

// WireGuardKeepalive elects one idle initiator per authorized pair. Both peers
// remain able to initiate application traffic. This prevents simultaneous
// keepalive-only handshakes when many devices start together.
func WireGuardKeepalive(self, peer string) int {
	if self < peer {
		return 5
	}
	return 0
}
