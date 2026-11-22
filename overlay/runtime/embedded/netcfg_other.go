//go:build !linux && !darwin && !windows

package embedded

import (
	"context"
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

type unsupportedNetConfigurator struct{}

func newPlatformNetConfigurator() NetConfigurator {
	return unsupportedNetConfigurator{}
}

func isPlatformPrivileged() bool { return false }

func (unsupportedNetConfigurator) CreateTUN(string, int) (tun.Device, string, error) {
	return nil, "", errors.New("embedded TUN runtime is unsupported on this OS")
}

func (unsupportedNetConfigurator) Configure(context.Context, string, netip.Prefix, int, []netip.Prefix) error {
	return errors.New("embedded TUN runtime is unsupported on this OS")
}

func (unsupportedNetConfigurator) Teardown(context.Context, string) error {
	return nil
}
