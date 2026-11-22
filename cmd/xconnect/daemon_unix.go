//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

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
