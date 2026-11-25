//go:build !windows

package main

import "os"

func isProcessPrivileged() bool {
	return os.Geteuid() == 0
}

func effectiveProcessUID() int {
	return os.Geteuid()
}
