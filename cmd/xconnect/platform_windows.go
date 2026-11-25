//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func defaultSystemDeviceIDPath() string {
	base := os.Getenv("ProgramData")
	if strings.TrimSpace(base) == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "xconnect-one", "device-id")
}

func platformElevatedCmdPrefix() string {
	return ""
}

func platformPingArgs(count int, host string) []string {
	return []string{"ping", "-n", fmt.Sprintf("%d", count), host}
}

func platformPingCmdString(count int, host string) string {
	return fmt.Sprintf("ping -n %d %s", count, host)
}
