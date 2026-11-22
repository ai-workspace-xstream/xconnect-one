package embedded

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

type wgHost struct {
	mu         sync.Mutex
	dev        *device.Device
	tunDev     tun.Device
	ifaceName  string
	peerPubHex string
	localPort  int
}

func newWGHost() *wgHost {
	return &wgHost{}
}

func (h *wgHost) Start(tunDev tun.Device, ifaceName, privKeyB64 string, cfg model.Config) error {
	uapi, peerPubHex, localPort, err := buildUAPISetConfig(privKeyB64, cfg)
	if err != nil {
		return err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard UAPI IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard device up: %w", err)
	}

	h.mu.Lock()
	h.dev = dev
	h.tunDev = tunDev
	h.ifaceName = ifaceName
	h.peerPubHex = peerPubHex
	h.localPort = localPort
	h.mu.Unlock()
	return nil
}

func (h *wgHost) UpdateConfig(privKeyB64 string, cfg model.Config) error {
	uapi, peerPubHex, localPort, err := buildUAPISetConfig(privKeyB64, cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	dev := h.dev
	h.mu.Unlock()
	if dev == nil {
		return errors.New("wireguard device is not running")
	}
	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("wireguard UAPI update: %w", err)
	}
	h.mu.Lock()
	h.peerPubHex = peerPubHex
	h.localPort = localPort
	h.mu.Unlock()
	return nil
}

func (h *wgHost) NudgePeer() error {
	h.mu.Lock()
	dev := h.dev
	peerPubHex := h.peerPubHex
	localPort := h.localPort
	h.mu.Unlock()
	if dev == nil {
		return errors.New("wireguard device is not running")
	}
	if peerPubHex == "" || localPort <= 0 {
		return errors.New("missing WireGuard peer or loopback port")
	}
	uapi := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", peerPubHex, localPort)
	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("wireguard nudge peer: %w", err)
	}
	return nil
}

func (h *wgHost) Stats() (latestHandshake time.Time, rxBytes, txBytes uint64, err error) {
	h.mu.Lock()
	dev := h.dev
	h.mu.Unlock()
	if dev == nil {
		return time.Time{}, 0, 0, errors.New("wireguard device is not running")
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return time.Time{}, 0, 0, fmt.Errorf("wireguard UAPI IpcGet: %w", err)
	}
	hs, rx, tx := parseUAPIGetStats(raw)
	return hs, rx, tx, nil
}

func (h *wgHost) Interface() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ifaceName
}

func (h *wgHost) Running() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dev != nil
}

func (h *wgHost) Close() error {
	h.mu.Lock()
	dev := h.dev
	h.dev = nil
	h.tunDev = nil
	h.ifaceName = ""
	h.peerPubHex = ""
	h.localPort = 0
	h.mu.Unlock()
	if dev == nil {
		return nil
	}
	dev.Close()
	return nil
}

func buildUAPISetConfig(privKeyB64 string, cfg model.Config) (string, string, int, error) {
	privHex, err := base64KeyToHex(privKeyB64)
	if err != nil {
		return "", "", 0, fmt.Errorf("decode WireGuard private key: %w", err)
	}
	peerPubHex, err := base64KeyToHex(cfg.WireGuard.PeerPublicKey)
	if err != nil {
		return "", "", 0, fmt.Errorf("decode WireGuard peer public key: %w", err)
	}
	localPort := cfg.Transport.LocalPort
	if localPort <= 0 {
		return "", "", 0, errors.New("invalid local transport loopback port")
	}
	keepalive := cfg.WireGuard.PersistentKeepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if cfg.WireGuard.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.WireGuard.ListenPort)
	} else {
		b.WriteString("listen_port=0\n")
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", peerPubHex)
	fmt.Fprintf(&b, "endpoint=127.0.0.1:%d\n", localPort)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	for _, rawAllowed := range cfg.WireGuard.PeerAllowedIPs {
		cidr := strings.TrimSpace(rawAllowed)
		if cidr == "" {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(cidr)
		if parseErr != nil {
			return "", "", 0, fmt.Errorf("invalid allowed IP %q: %w", cidr, parseErr)
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", prefix.Masked().String())
	}
	if cfg.Mesh != nil {
		for _, p := range cfg.Mesh.Peers {
			meshPubHex, keyErr := base64KeyToHex(p.PublicKey)
			if keyErr != nil {
				return "", "", 0, fmt.Errorf("decode mesh peer public key: %w", keyErr)
			}
			fmt.Fprintf(&b, "public_key=%s\n", meshPubHex)
			if ep := strings.TrimSpace(p.LocalEndpoint); ep != "" {
				fmt.Fprintf(&b, "endpoint=%s\n", ep)
			}
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
			for _, addr := range strings.Split(p.Address, ",") {
				addr = strings.TrimSpace(addr)
				if addr == "" {
					continue
				}
				prefix, parseErr := netip.ParsePrefix(addr)
				if parseErr != nil {
					return "", "", 0, fmt.Errorf("invalid mesh peer address %q: %w", addr, parseErr)
				}
				fmt.Fprintf(&b, "allowed_ip=%s\n", prefix.Masked().String())
			}
		}
	}
	return b.String(), peerPubHex, localPort, nil
}

func base64KeyToHex(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil || len(raw) != 32 {
		return "", errors.New("expected 32-byte base64 WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

func parseUAPIGetStats(raw string) (latestHandshake time.Time, rxBytes, txBytes uint64) {
	var newest int64
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			sec, err := strconv.ParseInt(v, 10, 64)
			if err == nil && sec > newest {
				newest = sec
			}
		case "rx_bytes":
			rx, err := strconv.ParseUint(v, 10, 64)
			if err == nil {
				rxBytes += rx
			}
		case "tx_bytes":
			tx, err := strconv.ParseUint(v, 10, 64)
			if err == nil {
				txBytes += tx
			}
		}
	}
	if newest > 0 {
		latestHandshake = time.Unix(newest, 0).UTC()
	}
	return latestHandshake, rxBytes, txBytes
}

// quietWriter satisfies unused io.Writer references cleanly when needed.
var _ = io.Discard
