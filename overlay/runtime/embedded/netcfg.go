package embedded

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
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
	hasAllowed := false
	for _, raw := range cfg.WireGuard.PeerAllowedIPs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		hasAllowed = true
		if _, parseErr := netip.ParsePrefix(trimmed); parseErr != nil {
			return netip.Prefix{}, nil, fmt.Errorf("invalid allowed IP %q: %w", trimmed, parseErr)
		}
	}
	if !hasAllowed {
		if localPrefix.Addr().Is4() && localPrefix.Bits() > 0 {
			return localPrefix, []netip.Prefix{localPrefix.Masked()}, nil
		}
		return localPrefix, nil, nil
	}
	sanitized, _, err := overlayruntime.SanitizeWireGuardAllowedIPs(cfg)
	if err != nil {
		return netip.Prefix{}, nil, err
	}
	allowed := make([]netip.Prefix, 0, len(sanitized))
	for _, raw := range sanitized {
		p, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return netip.Prefix{}, nil, fmt.Errorf("invalid allowed IP %q: %w", raw, parseErr)
		}
		allowed = append(allowed, p.Masked())
	}
	return localPrefix, allowed, nil
}

func defaultTUNMTU(mtu int) int {
	if mtu < 576 {
		return 1420
	}
	return mtu
}
