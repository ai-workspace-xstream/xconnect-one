//go:build (linux && !android) || (darwin && !ios)

package credential

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func directoryOwnerUID(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func isDirectoryWritableByCurrentUser(path string) bool {
	return unix.Access(path, unix.R_OK|unix.W_OK|unix.X_OK) == nil
}

// ResolveSudoInvoker returns the non-root UID and home directory of the user
// that invoked sudo when the current process runs as euid 0.
func ResolveSudoInvoker() (uint32, string, bool) {
	if os.Geteuid() != 0 {
		return 0, "", false
	}
	rawUID := strings.TrimSpace(os.Getenv("SUDO_UID"))
	if rawUID != "" {
		if parsed, err := strconv.ParseUint(rawUID, 10, 32); err == nil && parsed > 0 {
			if u, lookupErr := user.LookupId(rawUID); lookupErr == nil && strings.TrimSpace(u.HomeDir) != "" {
				return uint32(parsed), u.HomeDir, true
			}
			return uint32(parsed), "", true
		}
	}
	sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if sudoUser != "" && sudoUser != "root" {
		if u, err := user.Lookup(sudoUser); err == nil {
			if parsed, parseErr := strconv.ParseUint(u.Uid, 10, 32); parseErr == nil && parsed > 0 {
				return uint32(parsed), u.HomeDir, true
			}
		}
	}
	return 0, "", false
}

func sudoInvokerUIDGID() (uint32, int, bool) {
	uid, _, ok := ResolveSudoInvoker()
	if !ok || uid == 0 {
		return 0, -1, false
	}
	if rawGID := strings.TrimSpace(os.Getenv("SUDO_GID")); rawGID != "" {
		if parsed, err := strconv.ParseUint(rawGID, 10, 32); err == nil {
			return uid, int(parsed), true
		}
	}
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		if parsed, err := strconv.ParseUint(u.Gid, 10, 32); err == nil {
			return uid, int(parsed), true
		}
	}
	return uid, -1, true
}

func chownToSudoInvokerIfMatching(path string, targetUID uint32, targetGID int) {
	if os.Geteuid() != 0 || targetUID == 0 {
		return
	}
	_ = os.Chown(path, int(targetUID), targetGID)
}
