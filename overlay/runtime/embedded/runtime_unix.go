//go:build unix

package embedded

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func resolveStateDirOwner(stateDir string) (int, int, bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	if info, err := os.Lstat(stateDir); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid > 0 {
			return int(stat.Uid), int(stat.Gid), true
		}
	}
	rawUID := strings.TrimSpace(os.Getenv("SUDO_UID"))
	if rawUID == "" {
		return 0, 0, false
	}
	uid, err := strconv.ParseUint(rawUID, 10, 32)
	if err != nil || uid == 0 {
		return 0, 0, false
	}
	if rawGID := strings.TrimSpace(os.Getenv("SUDO_GID")); rawGID != "" {
		if gid, gidErr := strconv.ParseUint(rawGID, 10, 32); gidErr == nil {
			return int(uid), int(gid), true
		}
	}
	if u, lookupErr := user.LookupId(rawUID); lookupErr == nil {
		if gid, gidErr := strconv.ParseUint(u.Gid, 10, 32); gidErr == nil {
			return int(uid), int(gid), true
		}
	}
	return int(uid), -1, true
}

func preserveRuntimeOwnership(stateDir, runtimeDir, filePath string) {
	uid, gid, ok := resolveStateDirOwner(stateDir)
	if !ok {
		return
	}
	if runtimeDir != "" {
		_ = os.Chown(runtimeDir, uid, gid)
	}
	if filePath != "" {
		_ = os.Chown(filePath, uid, gid)
	}
}

func signalProcessStop(pid int) error {
	if pid <= 0 {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if err == os.ErrProcessDone {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return proc.Kill()
}
