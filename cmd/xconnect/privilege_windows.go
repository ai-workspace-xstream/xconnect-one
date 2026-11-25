//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

func isProcessPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func effectiveProcessUID() int {
	if isProcessPrivileged() {
		return 0
	}
	return -1
}
