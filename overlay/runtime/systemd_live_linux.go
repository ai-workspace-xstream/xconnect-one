//go:build linux

package runtime

import (
	"os"
	"strings"
)

const (
	defaultSystemdStateDir      = "/run/systemd/system"
	defaultSystemdPrivateSocket = "/run/systemd/private"
	defaultProc1CommPath        = "/proc/1/comm"
)

var (
	systemdStateDir      = defaultSystemdStateDir
	systemdPrivateSocket = defaultSystemdPrivateSocket
	proc1CommPath        = defaultProc1CommPath
	osStat               = os.Stat
	osReadFile           = os.ReadFile
	systemSystemdLive    = detectSystemSystemdLive
)

// detectSystemSystemdLive reports whether the system systemd manager is
// actually running. Presence of the systemd-run binary is not sufficient:
// container or tini-based hosts often ship the tools without a live manager.
func detectSystemSystemdLive() bool {
	state, err := osStat(systemdStateDir)
	if err != nil || !state.IsDir() {
		return false
	}
	if _, err := osStat(systemdPrivateSocket); err != nil {
		return false
	}
	comm, err := osReadFile(proc1CommPath)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(comm)) == "systemd"
}
