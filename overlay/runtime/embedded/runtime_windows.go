//go:build windows

package embedded

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const stillActiveProcessCode = 259

func isProcessAlive(pid int) bool {
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

func preserveRuntimeOwnership(_, _, _ string) {}

func signalProcessStop(pid int) error {
	if pid <= 0 {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		return nil
	}
	if err := proc.Kill(); err != nil {
		_ = proc.Release()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		return err
	}
	_ = proc.Release()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}
