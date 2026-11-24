//go:build !windows

package state

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func secureStateDirectory(path string) error { return os.Chmod(path, 0o700) }

func secureStateFile(path string) error { return os.Chmod(path, 0o600) }

func replaceStateFile(source, target string) error { return os.Rename(source, target) }

func privateStateDirectory(_ string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0o700
}

func privateStateRegular(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func statePermissionOK(_ string, info os.FileInfo, expected os.FileMode) bool {
	return info != nil && info.Mode().Perm() == expected
}

func sudoInvokerUIDGID() (uint32, int, bool) {
	if os.Geteuid() != 0 {
		return 0, -1, false
	}
	rawUID := strings.TrimSpace(os.Getenv("SUDO_UID"))
	if rawUID == "" {
		return 0, -1, false
	}
	parsedUID, err := strconv.ParseUint(rawUID, 10, 32)
	if err != nil || parsedUID == 0 {
		return 0, -1, false
	}
	if rawGID := strings.TrimSpace(os.Getenv("SUDO_GID")); rawGID != "" {
		if parsedGID, err := strconv.ParseUint(rawGID, 10, 32); err == nil {
			return uint32(parsedUID), int(parsedGID), true
		}
	}
	if u, err := user.LookupId(rawUID); err == nil {
		if parsedGID, err := strconv.ParseUint(u.Gid, 10, 32); err == nil {
			return uint32(parsedUID), int(parsedGID), true
		}
	}
	return uint32(parsedUID), -1, true
}

func preserveSudoDirectoryOwnership(dir string, dirExisted bool) {
	if dirExisted {
		return
	}
	sudoUID, sudoGID, ok := sudoInvokerUIDGID()
	if !ok {
		return
	}
	_ = os.Chown(dir, int(sudoUID), sudoGID)
}

func preserveSudoFileOwnership(dir, filePath string) {
	if os.Geteuid() != 0 {
		return
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return
	}
	stat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return
	}
	if sudoUID, sudoGID, hasSudo := sudoInvokerUIDGID(); hasSudo {
		if stat.Uid == sudoUID {
			_ = os.Chown(filePath, int(sudoUID), sudoGID)
		}
		return
	}
	_ = os.Chown(filePath, int(stat.Uid), int(stat.Gid))
}
