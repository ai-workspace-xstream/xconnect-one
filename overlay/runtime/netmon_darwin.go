//go:build darwin && !ios

package runtime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (m *NetworkMonitor) watchOS(ctx context.Context, emit func()) {
	m.resolveIgnored = darwinResolveIgnoredInterfaces

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		m.pollSnapshotLoop(ctx, defaultPollInterval, emit)
		return
	}
	defer func() { _ = unix.Close(fd) }()

	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return
		}
		n, recvErr := unix.Read(fd, buf)
		if recvErr != nil {
			if recvErr == syscall.EAGAIN || recvErr == syscall.EWOULDBLOCK || recvErr == syscall.EINTR {
				continue
			}
			m.pollSnapshotLoop(ctx, defaultPollInterval, emit)
			return
		}
		if n < 4 {
			continue
		}
		ignoredIndices := m.ignoredDarwinIndices()
		if darwinRouteMessageRelevant(buf[:n], ignoredIndices) {
			emit()
		}
	}
}

func darwinResolveIgnoredInterfaces(logicalName string) []string {
	raw, err := os.ReadFile(filepath.Join(darwinWireGuardRuntimeDir, logicalName+".name"))
	if err != nil {
		return nil
	}
	realName := strings.TrimSpace(string(raw))
	if !darwinRealInterfaceNamePattern.MatchString(realName) {
		return nil
	}
	return []string{realName}
}

func (m *NetworkMonitor) ignoredDarwinIndices() map[uint16]struct{} {
	out := make(map[uint16]struct{})
	for name := range m.ignoredNames() {
		if iface, err := net.InterfaceByName(name); err == nil && iface.Index > 0 {
			out[uint16(iface.Index)] = struct{}{}
		}
	}
	return out
}

func darwinRouteMessageRelevant(raw []byte, ignored map[uint16]struct{}) bool {
	if len(raw) < int(unsafe.Sizeof(unix.IfaMsghdr{})) {
		return false
	}
	// First 4 bytes on Darwin routing messages: uint16 msglen, uint8 version, uint8 type.
	msgType := raw[3]
	switch msgType {
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		if len(raw) >= int(unsafe.Sizeof(unix.IfaMsghdr{})) {
			hdr := (*unix.IfaMsghdr)(unsafe.Pointer(&raw[0]))
			if _, skip := ignored[hdr.Index]; skip {
				return false
			}
		}
		return true
	case unix.RTM_IFINFO, unix.RTM_IFINFO2:
		if len(raw) >= int(unsafe.Sizeof(unix.IfMsghdr{})) {
			hdr := (*unix.IfMsghdr)(unsafe.Pointer(&raw[0]))
			if _, skip := ignored[hdr.Index]; skip {
				return false
			}
		}
		return true
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
		if len(raw) >= int(unsafe.Sizeof(unix.RtMsghdr{})) {
			hdr := (*unix.RtMsghdr)(unsafe.Pointer(&raw[0]))
			if _, skip := ignored[hdr.Index]; skip {
				return false
			}
		}
		return true
	default:
		return false
	}
}
