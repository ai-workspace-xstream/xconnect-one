//go:build linux && !android

package runtime

import (
	"context"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (m *NetworkMonitor) watchOS(ctx context.Context, emit func()) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		m.pollSnapshotLoop(ctx, defaultPollInterval, emit)
		return
	}
	defer func() { _ = unix.Close(fd) }()

	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK |
			unix.RTMGRP_IPV4_IFADDR |
			unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE |
			unix.RTMGRP_IPV6_ROUTE,
	}
	if err := unix.Bind(fd, sa); err != nil {
		m.pollSnapshotLoop(ctx, defaultPollInterval, emit)
		return
	}

	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, recvErr := unix.Recvfrom(fd, buf, 0)
		if recvErr != nil {
			if recvErr == syscall.EAGAIN || recvErr == syscall.EWOULDBLOCK || recvErr == syscall.EINTR {
				continue
			}
			m.pollSnapshotLoop(ctx, defaultPollInterval, emit)
			return
		}
		if n <= 0 {
			continue
		}
		msgs, parseErr := syscall.ParseNetlinkMessage(buf[:n])
		if parseErr != nil {
			continue
		}
		ignoredIndex := m.ignoredInterfaceIndex()
		for _, msg := range msgs {
			if netlinkMessageRelevant(msg, ignoredIndex) {
				emit()
				break
			}
		}
	}
}

func (m *NetworkMonitor) ignoredInterfaceIndex() int {
	if m.ignoreInterface == "" {
		return 0
	}
	iface, err := net.InterfaceByName(m.ignoreInterface)
	if err != nil {
		return 0
	}
	return iface.Index
}

func netlinkMessageRelevant(msg syscall.NetlinkMessage, ignoredIndex int) bool {
	switch msg.Header.Type {
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		if ignoredIndex > 0 && len(msg.Data) >= int(unsafe.Sizeof(unix.IfInfomsg{})) {
			info := (*unix.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
			if int(info.Index) == ignoredIndex {
				return false
			}
		}
		return true
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		if ignoredIndex > 0 && len(msg.Data) >= 8 {
			// struct ifaddrmsg has ifa_index (uint32) at offset 4.
			idx := *(*uint32)(unsafe.Pointer(&msg.Data[4]))
			if int(idx) == ignoredIndex {
				return false
			}
		}
		return true
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		return true
	default:
		return false
	}
}
