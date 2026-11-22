//go:build windows

package embedded

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

type windowsNetConfigurator struct {
	mu     sync.Mutex
	routes map[string][]netip.Prefix
}

func newPlatformNetConfigurator() NetConfigurator {
	return &windowsNetConfigurator{routes: make(map[string][]netip.Prefix)}
}

func isPlatformPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (c *windowsNetConfigurator) CreateTUN(desiredName string, mtu int) (tun.Device, string, error) {
	iface := strings.TrimSpace(desiredName)
	if iface == "" {
		iface = "xconone0"
	}
	dev, err := tun.CreateTUN(iface, defaultTUNMTU(mtu))
	if err != nil {
		return nil, "", fmt.Errorf("create Windows Wintun device %q: %w", iface, err)
	}
	realName, nameErr := dev.Name()
	if nameErr != nil || strings.TrimSpace(realName) == "" {
		realName = iface
	}
	return dev, strings.TrimSpace(realName), nil
}

func (c *windowsNetConfigurator) Configure(ctx context.Context, ifaceName string, localAddr netip.Prefix, mtu int, allowedIPs []netip.Prefix) error {
	mtu = defaultTUNMTU(mtu)
	if localAddr.Addr().Is4() {
		mask := net.IP(net.CIDRMask(localAddr.Bits(), 32)).String()
		if err := runWindowsNetsh(ctx, "interface", "ipv4", "set", "address", "name="+ifaceName, "source=static", "address="+localAddr.Addr().String(), "mask="+mask); err != nil {
			return err
		}
		_ = runWindowsNetsh(ctx, "interface", "ipv4", "set", "subinterface", ifaceName, "mtu="+strconv.Itoa(mtu), "store=active")
	} else {
		if err := runWindowsNetsh(ctx, "interface", "ipv6", "set", "address", "interface="+ifaceName, "address="+localAddr.String()); err != nil {
			return err
		}
		_ = runWindowsNetsh(ctx, "interface", "ipv6", "set", "subinterface", ifaceName, "mtu="+strconv.Itoa(mtu), "store=active")
	}

	installed := make([]netip.Prefix, 0, len(allowedIPs))
	for _, prefix := range allowedIPs {
		family := "ipv4"
		if prefix.Addr().Is6() {
			family = "ipv6"
		}
		if err := runWindowsNetsh(ctx, "interface", family, "set", "route", "prefix="+prefix.String(), "interface="+ifaceName, "store=active"); err != nil {
			if addErr := runWindowsNetsh(ctx, "interface", family, "add", "route", "prefix="+prefix.String(), "interface="+ifaceName, "store=active"); addErr != nil {
				return addErr
			}
		}
		installed = append(installed, prefix)
	}

	c.mu.Lock()
	c.routes[ifaceName] = installed
	c.mu.Unlock()
	return nil
}

func (c *windowsNetConfigurator) Teardown(ctx context.Context, ifaceName string) error {
	c.mu.Lock()
	routes := append([]netip.Prefix(nil), c.routes[ifaceName]...)
	delete(c.routes, ifaceName)
	c.mu.Unlock()

	for _, prefix := range routes {
		family := "ipv4"
		if prefix.Addr().Is6() {
			family = "ipv6"
		}
		_ = runWindowsNetsh(ctx, "interface", family, "delete", "route", "prefix="+prefix.String(), "interface="+ifaceName)
	}
	return nil
}

func runWindowsNetsh(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "netsh", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("netsh %s: %w (%s)", strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("netsh %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
