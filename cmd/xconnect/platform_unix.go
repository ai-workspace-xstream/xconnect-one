//go:build !windows

package main

import "fmt"

func defaultSystemDeviceIDPath() string {
	return "/etc/xconnect-one/device-id"
}

func platformElevatedCmdPrefix() string {
	return "sudo "
}

func platformPingArgs(count int, host string) []string {
	return []string{"ping", "-c", fmt.Sprintf("%d", count), host}
}

func platformPingCmdString(count int, host string) string {
	return fmt.Sprintf("ping -c %d %s", count, host)
}
