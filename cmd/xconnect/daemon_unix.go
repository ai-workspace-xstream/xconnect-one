//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func preserveDaemonOwnership(stateDir, dirPath, filePath string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, gid := 0, -1
	found := false
	if info, err := os.Lstat(stateDir); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid > 0 {
			uid, gid, found = int(stat.Uid), int(stat.Gid), true
		}
	}
	if !found {
		rawUID := strings.TrimSpace(os.Getenv("SUDO_UID"))
		if rawUID != "" {
			if parsed, err := strconv.ParseUint(rawUID, 10, 32); err == nil && parsed > 0 {
				uid, found = int(parsed), true
				if rawGID := strings.TrimSpace(os.Getenv("SUDO_GID")); rawGID != "" {
					if parsedGID, gidErr := strconv.ParseUint(rawGID, 10, 32); gidErr == nil {
						gid = int(parsedGID)
					}
				} else if u, lookupErr := user.LookupId(rawUID); lookupErr == nil {
					if parsedGID, gidErr := strconv.ParseUint(u.Gid, 10, 32); gidErr == nil {
						gid = int(parsedGID)
					}
				}
			}
		}
	}
	if !found {
		return
	}
	if dirPath != "" {
		_ = os.Chown(dirPath, uid, gid)
	}
	if filePath != "" {
		_ = os.Chown(filePath, uid, gid)
	}
}

func configureDetachedProcess(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}

func isDaemonProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func stopDaemonProcess(pid int, waitTimeout time.Duration) error {
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("signal daemon pid %d: %w", pid, os.ErrPermission)
		}
		return err
	}
	if waitTimeout <= 0 {
		waitTimeout = 5 * time.Second
	}
	deadline := time.Now().Add(waitTimeout)
	for {
		if !isDaemonProcessAlive(pid) {
			return nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("kill daemon pid %d: %w", pid, os.ErrPermission)
		}
		return err
	}
	killDeadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(killDeadline) {
		if !isDaemonProcessAlive(pid) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil
}
