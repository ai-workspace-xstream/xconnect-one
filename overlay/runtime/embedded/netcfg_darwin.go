//go:build darwin

package embedded

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

type darwinNetConfigurator struct {
	mu     sync.Mutex
	routes map[string][]netip.Prefix
}

func newPlatformNetConfigurator() NetConfigurator {
	return &darwinNetConfigurator{routes: make(map[string][]netip.Prefix)}
}

func isPlatformPrivileged() bool {
	return os.Geteuid() == 0
}

func (c *darwinNetConfigurator) CreateTUN(_ string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN("utun", defaultTUNMTU(mtu))
	if err != nil {
		return nil, "", fmt.Errorf("create macOS utun device: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, "", fmt.Errorf("read macOS utun device name: %w", err)
	}
	return dev, strings.TrimSpace(name), nil
}

func (c *darwinNetConfigurator) Configure(ctx context.Context, ifaceName string, localAddr netip.Prefix, mtu int, allowedIPs []netip.Prefix) error {
	mtu = defaultTUNMTU(mtu)
	ipStr := localAddr.Addr().String()
	if localAddr.Addr().Is4() {
		if err := runNetCmd(ctx, "/sbin/ifconfig", ifaceName, "inet", ipStr, ipStr, "netmask", "255.255.255.255", "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
			return fmt.Errorf("configure macOS IPv4 address on %s: %w", ifaceName, err)
		}
	} else {
		if err := runNetCmd(ctx, "/sbin/ifconfig", ifaceName, "inet6", localAddr.String(), "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
			return fmt.Errorf("configure macOS IPv6 address on %s: %w", ifaceName, err)
		}
	}

	installed := make([]netip.Prefix, 0, len(allowedIPs))
	for _, prefix := range allowedIPs {
		familyFlag := "-inet"
		if prefix.Addr().Is6() {
			familyFlag = "-inet6"
		}
		target := prefix.String()
		if err := runNetCmd(ctx, "/sbin/route", "-n", "add", familyFlag, "-net", target, "-interface", ifaceName); err != nil {
			// Replace stale route left over from an ungraceful previous run.
			if changeErr := runNetCmd(ctx, "/sbin/route", "-n", "change", familyFlag, "-net", target, "-interface", ifaceName); changeErr != nil {
				_ = runNetCmd(ctx, "/sbin/route", "-n", "delete", familyFlag, "-net", target)
				if retryErr := runNetCmd(ctx, "/sbin/route", "-n", "add", familyFlag, "-net", target, "-interface", ifaceName); retryErr != nil {
					return fmt.Errorf("add macOS route %s via %s: %w", target, ifaceName, retryErr)
				}
			}
		}
		installed = append(installed, prefix)
	}

	c.mu.Lock()
	c.routes[ifaceName] = installed
	c.mu.Unlock()
	return nil
}

func (c *darwinNetConfigurator) Teardown(ctx context.Context, ifaceName string) error {
	c.mu.Lock()
	routes := append([]netip.Prefix(nil), c.routes[ifaceName]...)
	delete(c.routes, ifaceName)
	c.mu.Unlock()

	for _, prefix := range routes {
		familyFlag := "-inet"
		if prefix.Addr().Is6() {
			familyFlag = "-inet6"
		}
		_ = runNetCmd(ctx, "/sbin/route", "-n", "delete", familyFlag, "-net", prefix.String(), "-interface", ifaceName)
	}
	return nil
}

func runNetCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
