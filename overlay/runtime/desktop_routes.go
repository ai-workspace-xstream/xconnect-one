package runtime

import (
	"net/netip"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

// IsDefaultRoutePrefix reports whether value parses as a /0 default-route
// prefix (such as 0.0.0.0/0 or ::/0).
func IsDefaultRoutePrefix(value string) bool {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return prefix.Bits() == 0
}

func appendUniquePrefix(dst []string, seen map[string]struct{}, raw string) []string {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || prefix.Bits() == 0 {
		return dst
	}
	key := prefix.Masked().String()
	if _, ok := seen[key]; ok {
		return dst
	}
	seen[key] = struct{}{}
	return append(dst, key)
}

// OverlayRouteIntent returns the private-network prefixes this config is
// meant to reach, excluding default routes.
func OverlayRouteIntent(config model.Config) []string {
	seen := make(map[string]struct{})
	var out []string
	out = appendUniquePrefix(out, seen, config.Network.CIDR)
	out = appendUniquePrefix(out, seen, config.WireGuard.GatewayWireGuardCIDR)
	out = appendUniquePrefix(out, seen, config.WireGuard.Address)
	if config.Mesh != nil {
		out = appendUniquePrefix(out, seen, config.Mesh.OverlayCIDR)
	}
	return out
}

// SanitizeWireGuardAllowedIPs keeps controller-supplied prefixes, but refuses
// to install 0.0.0.0/0 or ::/0 as a host default route. When a default route
// is present, it is replaced by explicit overlay prefixes (network CIDR,
// gateway CIDR, assigned address, and mesh overlay CIDR). If no overlay
// intent can be derived, Apply must fail rather than force a default route.
func SanitizeWireGuardAllowedIPs(config model.Config) (allowed []string, defaultRouteRejected bool, err error) {
	seen := make(map[string]struct{})
	for _, ip := range config.WireGuard.PeerAllowedIPs {
		if IsDefaultRoutePrefix(ip) {
			defaultRouteRejected = true
			continue
		}
		allowed = appendUniquePrefix(allowed, seen, ip)
	}
	if !defaultRouteRejected {
		if len(allowed) == 0 {
			return nil, false, fault.New(fault.CodeInvalidConfig, "validate WireGuard allowed IPs", nil)
		}
		return allowed, false, nil
	}
	if len(allowed) == 0 {
		allowed = OverlayRouteIntent(config)
	}
	if len(allowed) == 0 {
		return nil, true, fault.New(fault.CodeRuntimeApplyFailed, "refuse default-route AllowedIPs without overlay CIDR intent", newHintedError("controller AllowedIPs include a default route (0.0.0.0/0 or ::/0) and no overlay CIDR is available for split-tunnel"))
	}
	return allowed, true, nil
}
