//go:build linux

package accelerate

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	mainPriority = 32764
	tunPriority  = 32765
	routeTable   = 45230
	ruleProtocol = 212
)

// Acceleration applies only to locally generated sockets for the selected UID.
// Existing policy rules run first. Existing main-table routes other than a
// default also run first, including any routes One installs while we run.
func rulesFor(family int, uid uint32) [2]netlink.Rule {
	makeRule := func(priority, table int) netlink.Rule {
		r := netlink.NewRule()
		r.Priority, r.Table, r.Family = priority, table, family
		r.IifName = "lo"
		r.UIDRange = netlink.NewRuleUIDRange(uid, uid)
		r.Protocol = ruleProtocol
		r.Type = unix.FR_ACT_TO_TBL
		return *r
	}
	main := makeRule(mainPriority, unix.RT_TABLE_MAIN)
	main.SuppressPrefixlen = 0
	return [2]netlink.Rule{main, makeRule(tunPriority, routeTable)}
}

func reserveRoutes() error {
	_, err := netlink.LinkByName(tunName)
	if err == nil {
		return fmt.Errorf("network interface %s is already in use", tunName)
	}
	var missing netlink.LinkNotFoundError
	if !errors.As(err, &missing) {
		return fmt.Errorf("inspect acceleration interface: %w", err)
	}
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("inspect local addresses: %w", err)
	}
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			continue
		}
		for _, cidr := range []string{tunIPv4, tunIPv6} {
			if netip.MustParsePrefix(cidr).Contains(ip.Unmap()) {
				return errors.New("acceleration TUN address is already assigned to another interface")
			}
		}
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: routeTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return fmt.Errorf("inspect acceleration routing table: %w", err)
		}
		if len(routes) != 0 {
			return fmt.Errorf("routing table %d is already in use", routeTable)
		}
		rules, err := netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("inspect routing rules: %w", err)
		}
		for _, r := range rules {
			if r.Priority != mainPriority && r.Priority != tunPriority && r.Table != routeTable {
				continue
			}
			// A killed process loses its nonpersistent TUN and the routes tied
			// to it. Recover only rules that carry our private protocol and
			// exact selector, with the interface and table already absent.
			if r.UIDRange != nil && r.UIDRange.Start != 0 {
				expected := rulesFor(family, r.UIDRange.Start)
				if isOwnedRule(r, expected[0]) || isOwnedRule(r, expected[1]) {
					if err := netlink.RuleDel(&r); err != nil {
						return fmt.Errorf("recover stale acceleration rule: %w", err)
					}
					continue
				}
			}
			return errors.New("acceleration routing priorities or table are already in use")
		}
	}
	return nil
}

func isOwnedRule(have, want netlink.Rule) bool {
	// An omitted action is returned as FR_ACT_UNSPEC by older netlink decoders.
	if have.Type == 0 {
		have.Type = unix.FR_ACT_TO_TBL
	}
	return reflect.DeepEqual(have, want)
}

func installRoutes(link netlink.Link, uid uint32) (func() error, error) {
	var installed []netlink.Rule
	cleanup := func() error {
		var err error
		for i := len(installed) - 1; i >= 0; i-- {
			if removeErr := netlink.RuleDel(&installed[i]); removeErr != nil && !errors.Is(removeErr, unix.ENOENT) {
				err = errors.Join(err, fmt.Errorf("remove acceleration routing rule: %w", removeErr))
			}
		}
		return err
	}
	prefixes4, prefixes6 := PublicRoutePrefixes()
	for _, item := range []struct {
		family   int
		prefixes []netip.Prefix
	}{
		{netlink.FAMILY_V4, prefixes4},
		{netlink.FAMILY_V6, prefixes6},
	} {
		for _, prefix := range item.prefixes {
			ip := prefix.Addr()
			mask := net.CIDRMask(prefix.Bits(), ip.BitLen())
			route := netlink.Route{
				LinkIndex: link.Attrs().Index, Table: routeTable,
				Dst: &net.IPNet{IP: net.IP(ip.AsSlice()), Mask: mask}, Scope: netlink.SCOPE_LINK,
			}
			if err := netlink.RouteAdd(&route); err != nil {
				return cleanup, fmt.Errorf("add acceleration route: %w", err)
			}
		}
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, r := range rulesFor(family, uid) {
			if err := netlink.RuleAdd(&r); err != nil {
				return cleanup, fmt.Errorf("add acceleration routing rule: %w", err)
			}
			installed = append(installed, r)
		}
	}
	return cleanup, nil
}
