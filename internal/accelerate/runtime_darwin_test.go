//go:build darwin

package accelerate

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinAccelerateMetadataAndControlSocket(t *testing.T) {
	if !IsSupportedOS() {
		t.Fatal("expected darwin to be supported")
	}
	if os.Geteuid() != 0 && IsPrivileged() {
		t.Fatal("expected non-root user not to be privileged")
	}

	sockDir, err := os.MkdirTemp("/tmp", "xa-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "c.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	stopped := make(chan struct{})
	go serveControl(listener, func() { close(stopped) })

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{'s'}); err != nil {
		t.Fatal(err)
	}
	var statusBuf bytes.Buffer
	if _, err := statusBuf.ReadFrom(conn); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !strings.Contains(statusBuf.String(), "Acceleration on for macOS") {
		t.Fatalf("unexpected status response: %q", statusBuf.String())
	}

	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn2.Write([]byte{'d'}); err != nil {
		t.Fatal(err)
	}
	_ = conn2.Close()
	<-stopped
	_ = context.Background()
}
