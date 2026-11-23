//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const (
	detachedProcessFlag    = 0x00000008
	stillActiveProcessCode = 259
)

func configureDetachedProcess(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcessFlag,
	}
}

func isDaemonProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(handle)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActiveProcessCode
}

func stopDaemonProcess(pid int, waitTimeout time.Duration) error {
	if pid <= 0 {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("signal daemon pid %d: %w", pid, os.ErrPermission)
		}
		return nil
	}
	if err := proc.Kill(); err != nil {
		_ = proc.Release()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("kill daemon pid %d: %w", pid, os.ErrPermission)
		}
		return err
	}
	if waitTimeout <= 0 {
		waitTimeout = 5 * time.Second
	}
	done := make(chan struct{})
	go func() {
		_, _ = proc.Wait()
		close(done)
	}()
	timer := time.NewTimer(waitTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
	return nil
}
