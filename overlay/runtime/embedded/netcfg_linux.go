//go:build linux

package embedded

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

type linuxNetConfigurator struct {
	mu     sync.Mutex
	routes map[string][]netip.Prefix
}

func newPlatformNetConfigurator() NetConfigurator {
	return &linuxNetConfigurator{routes: make(map[string][]netip.Prefix)}
}

func isPlatformPrivileged() bool {
	if os.Geteuid() == 0 {
		return true
	}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexVal := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, parseErr := strconv.ParseUint(hexVal, 16, 64)
		if parseErr == nil {
			const capNetAdminBit = 12
			return (mask & (1 << capNetAdminBit)) != 0
		}
	}
	return false
}

func (c *linuxNetConfigurator) CreateTUN(desiredName string, mtu int) (tun.Device, string, error) {
	iface := strings.TrimSpace(desiredName)
	if iface == "" {
		iface = "xconone0"
	}
	mtu = defaultTUNMTU(mtu)
	dev, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		// Reclaim a stale dead WireGuard/TUN device with the exact same name if present.
		if link, linkErr := netlink.LinkByName(iface); linkErr == nil {
			if delErr := netlink.LinkDel(link); delErr == nil {
				if retryDev, retryErr := tun.CreateTUN(iface, mtu); retryErr == nil {
					dev = retryDev
					err = nil
				}
			}
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("create Linux TUN device %q: %w", iface, err)
	}
	realName, nameErr := dev.Name()
	if nameErr != nil || strings.TrimSpace(realName) == "" {
		realName = iface
	}
	return dev, strings.TrimSpace(realName), nil
}

func (c *linuxNetConfigurator) Configure(_ context.Context, ifaceName string, localAddr netip.Prefix, mtu int, allowedIPs []netip.Prefix) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup Linux interface %q: %w", ifaceName, err)
	}
	if err := netlink.LinkSetMTU(link, defaultTUNMTU(mtu)); err != nil {
		return fmt.Errorf("set Linux interface MTU on %s: %w", ifaceName, err)
	}
	ipNet := prefixToIPNet(localAddr)
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("assign Linux address %s on %s: %w", localAddr.String(), ifaceName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up Linux interface %s: %w", ifaceName, err)
	}

	installed := make([]netip.Prefix, 0, len(allowedIPs))
	for _, prefix := range allowedIPs {
		dst := prefixToIPNet(prefix.Masked())
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("replace Linux route %s via %s: %w", prefix.String(), ifaceName, err)
		}
		installed = append(installed, prefix)
	}

	c.mu.Lock()
	c.routes[ifaceName] = installed
	c.mu.Unlock()
	return nil
}

func (c *linuxNetConfigurator) Teardown(_ context.Context, ifaceName string) error {
	c.mu.Lock()
	routes := append([]netip.Prefix(nil), c.routes[ifaceName]...)
	delete(c.routes, ifaceName)
	c.mu.Unlock()

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil
	}
	for _, prefix := range routes {
		_ = netlink.RouteDel(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       prefixToIPNet(prefix.Masked()),
		})
	}
	return nil
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addrBytes := prefix.Addr().AsSlice()
	mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
	return &net.IPNet{
		IP:   net.IP(addrBytes),
		Mask: mask,
	}
}
