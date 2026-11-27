package accelerate

import "net/netip"

var (
	excludedIPv4CIDRs = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
	}
	excludedIPv6CIDRs = []string{"2001:db8::/32", "3fff::/20"}
)

// PublicRoutePrefixes returns the public IPv4 and IPv6 prefixes routed through
// the acceleration TUN, excluding private, overlay, loopback, and reserved ranges.
func PublicRoutePrefixes() (ipv4 []netip.Prefix, ipv6 []netip.Prefix) {
	return publicPrefixes("0.0.0.0/0", excludedIPv4CIDRs),
		publicPrefixes("2000::/3", excludedIPv6CIDRs)
}

// PublicRouteCIDRs returns PublicRoutePrefixes formatted as CIDR strings for
// Xray's autoSystemRoutingTable configuration.
func PublicRouteCIDRs() []string {
	v4, v6 := PublicRoutePrefixes()
	out := make([]string, 0, len(v4)+len(v6))
	for _, p := range v4 {
		out = append(out, p.String())
	}
	for _, p := range v6 {
		out = append(out, p.String())
	}
	return out
}

func publicPrefixes(root string, excluded []string) []netip.Prefix {
	routes := []netip.Prefix{netip.MustParsePrefix(root)}
	for _, cidr := range excluded {
		e := netip.MustParsePrefix(cidr)
		var next []netip.Prefix
		for _, p := range routes {
			next = appendWithout(next, p, e)
		}
		routes = next
	}
	return routes
}

func appendWithout(out []netip.Prefix, p, e netip.Prefix) []netip.Prefix {
	if !p.Overlaps(e) {
		return append(out, p)
	}
	if e.Bits() <= p.Bits() {
		return out
	}
	bits := p.Bits()
	addr := p.Addr().AsSlice()
	addr[bits/8] |= 1 << (7 - bits%8)
	right, _ := netip.AddrFromSlice(addr)
	out = appendWithout(out, netip.PrefixFrom(p.Addr(), bits+1), e)
	return appendWithout(out, netip.PrefixFrom(right, bits+1), e)
}
