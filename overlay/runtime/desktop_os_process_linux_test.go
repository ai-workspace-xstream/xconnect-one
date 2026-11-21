//go:build linux

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func buildProcessHelper(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "helper.go")
	body := `package main
import (
	"fmt"
	"os"
	"time"
)
func main() {
	if len(os.Args) > 1 && os.Args[1] == "fail" {
		fmt.Fprintln(os.Stderr, "token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		fmt.Fprintln(os.Stderr, "startup exploded")
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}
`
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "helper")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Dir = dir
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, raw)
	}
	return out
}

func TestSupervisedProcessStartStopAndIdentity(t *testing.T) {
	if detectSystemSystemdLive() {
		t.Skip("this test exercises the non-systemd supervisor")
	}
	dir := t.TempDir()
	helper := buildProcessHelper(t, dir)
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &osDesktopBackend{logDirectory: filepath.Join(dir, "logs")}
	identity, err := backend.Start(helper, []string{"-config", cfg}, "cfg_test_rev", strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = backend.Stop(identity) })
	if identity.PID <= 0 || identity.StartToken == "" || identity.Executable == "" {
		t.Fatalf("incomplete identity: %#v", identity)
	}
	alive, err := backend.ProcessAlive(identity)
	if err != nil || !alive {
		t.Fatalf("alive=%v err=%v", alive, err)
	}
	if err := backend.Stop(identity); err != nil {
		t.Fatalf("stop: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		alive, err = backend.ProcessAlive(identity)
		if err != nil {
			t.Fatalf("alive after stop: %v", err)
		}
		if !alive {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if alive {
		t.Fatal("process still alive after Stop")
	}
	if err := syscall.Kill(identity.PID, 0); err == nil {
		t.Fatal("pid still exists after Stop (orphan)")
	}
}

func TestSupervisedProcessStartFailureSurfacesSanitizedStderr(t *testing.T) {
	if detectSystemSystemdLive() {
		t.Skip("this test exercises the non-systemd supervisor")
	}
	dir := t.TempDir()
	helper := buildProcessHelper(t, dir)
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &osDesktopBackend{logDirectory: filepath.Join(dir, "logs")}
	_, err := backend.Start(helper, []string{"fail", "-config", cfg}, "cfg_fail", strings.Repeat("b", 64))
	if err == nil {
		t.Fatal("expected start failure")
	}
	hint, ok := err.(interface{ SafeHint() string })
	if !ok {
		t.Fatalf("expected SafeHint, got %T %v", err, err)
	}
	msg := hint.SafeHint()
	if !strings.Contains(msg, "startup exploded") {
		t.Fatalf("missing actionable stderr in %q", msg)
	}
	if strings.Contains(msg, "token=") || strings.Contains(msg, "AAAA") {
		t.Fatalf("leaked secret material: %q", msg)
	}
}

func TestSupervisedProcessUsesLiveSystemdPathWhenInjected(t *testing.T) {
	orig := systemSystemdLive
	t.Cleanup(func() { systemSystemdLive = orig })
	systemSystemdLive = func() bool { return true }
	dir := t.TempDir()
	backend := &osDesktopBackend{logDirectory: filepath.Join(dir, "logs")}
	_, err := backend.Start("/bin/true", []string{"-config", filepath.Join(dir, "missing.json")}, "cfg_sys", strings.Repeat("c", 64))
	if err == nil {
		t.Fatal("expected systemd-run to fail on a host without a live manager")
	}
	hint, ok := err.(interface{ SafeHint() string })
	if !ok {
		t.Fatalf("expected hinted systemd error, got %T %v", err, err)
	}
	if !strings.Contains(hint.SafeHint(), "systemd-run") {
		t.Fatalf("hint = %q", hint.SafeHint())
	}
}

func TestSanitizeProcessLogRedactsSecrets(t *testing.T) {
	t.Parallel()
	got := sanitizeProcessLog("PrivateKey = abcdefghijabcdefghijabcdefghijabcdefghij\nlistener failed on port " + strconv.Itoa(1234))
	if strings.Contains(got, "PrivateKey") || strings.Contains(got, "abcdefghij") {
		t.Fatalf("not redacted: %q", got)
	}
	if !strings.Contains(got, "listener failed on port 1234") {
		t.Fatalf("lost useful log: %q", got)
	}
}
