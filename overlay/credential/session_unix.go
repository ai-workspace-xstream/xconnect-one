//go:build (linux && !android) || (darwin && !ios)

package credential

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func directoryOwnerUID(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func isDirectoryWritableByCurrentUser(path string) bool {
	return unix.Access(path, unix.R_OK|unix.W_OK|unix.X_OK) == nil
}
