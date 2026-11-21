//go:build linux

package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectSystemSystemdLiveRequiresLiveManagerNotBinaries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	stateDir := filepath.Join(root, "system")
	sock := filepath.Join(root, "private")
	comm := filepath.Join(root, "comm")

	origState, origSock, origComm, origStat, origRead := systemdStateDir, systemdPrivateSocket, proc1CommPath, osStat, osReadFile
	t.Cleanup(func() {
		systemdStateDir = origState
		systemdPrivateSocket = origSock
		proc1CommPath = origComm
		osStat = origStat
		osReadFile = origRead
	})
	systemdStateDir = stateDir
	systemdPrivateSocket = sock
	proc1CommPath = comm
	osStat = os.Stat
	osReadFile = os.ReadFile

	if detectSystemSystemdLive() {
		t.Fatal("empty paths must not look like a live systemd manager")
	}
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if detectSystemSystemdLive() {
		t.Fatal("state dir alone is not a live manager")
	}
	if err := os.WriteFile(sock, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(comm, []byte("tini\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if detectSystemSystemdLive() {
		t.Fatal("tini PID 1 must not be treated as systemd")
	}
	if err := os.WriteFile(comm, []byte("systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !detectSystemSystemdLive() {
		t.Fatal("expected live systemd when state dir, private socket, and PID 1 comm match")
	}
}
