package embedded

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

// NetConfigurator abstracts platform-specific TUN interface creation,
// IP/MTU assignment, and routing table reconciliation without wg-quick.
type NetConfigurator interface {
	CreateTUN(desiredName string, mtu int) (tun.Device, string, error)
	Configure(ctx context.Context, ifaceName string, localAddr netip.Prefix, mtu int, allowedIPs []netip.Prefix) error
	Teardown(ctx context.Context, ifaceName string) error
}

func parseNetworkPrefixes(cfg model.Config) (netip.Prefix, []netip.Prefix, error) {
	localPrefix, err := netip.ParsePrefix(strings.TrimSpace(cfg.WireGuard.Address))
	if err != nil || !localPrefix.IsValid() {
		return netip.Prefix{}, nil, fmt.Errorf("invalid WireGuard address %q: %w", cfg.WireGuard.Address, err)
	}
	allowed := make([]netip.Prefix, 0, len(cfg.WireGuard.PeerAllowedIPs))
	seen := make(map[netip.Prefix]struct{}, len(cfg.WireGuard.PeerAllowedIPs))
	for _, raw := range cfg.WireGuard.PeerAllowedIPs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		p, parseErr := netip.ParsePrefix(trimmed)
		if parseErr != nil {
			return netip.Prefix{}, nil, fmt.Errorf("invalid allowed IP %q: %w", trimmed, parseErr)
		}
		masked := p.Masked()
		if _, dup := seen[masked]; dup {
			continue
		}
		seen[masked] = struct{}{}
		allowed = append(allowed, masked)
	}
	if len(allowed) == 0 && localPrefix.Addr().Is4() {
		allowed = append(allowed, localPrefix.Masked())
	}
	return localPrefix, allowed, nil
}

func defaultTUNMTU(mtu int) int {
	if mtu < 576 {
		return 1420
	}
	return mtu
}
