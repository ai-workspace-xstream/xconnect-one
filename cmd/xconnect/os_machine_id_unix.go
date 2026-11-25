//go:build !windows

package main

import (
	"os"
	"strings"
)

func readOSMachineID() string {
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/etc/hostid",
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err == nil {
			if id := strings.TrimSpace(string(raw)); id != "" {
				return id
			}
		}
	}
	return ""
}
