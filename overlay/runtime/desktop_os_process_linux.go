//go:build linux

package runtime

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	supervisedProcessSettle = 80 * time.Millisecond
	maxSurfacedLogBytes     = 2048
)

var secretLogLine = regexp.MustCompile(`(?i)(private[ _-]?key|preshared[ _-]?key|password|secret|token|authorization|credential|bearer)\b`)

func (b *osDesktopBackend) SetLogDirectory(path string) {
	b.logDirectory = path
}

func (b *osDesktopBackend) Start(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	if systemSystemdLive() {
		return b.startSystemdRun(executable, args, revision, configDigest)
	}
	return b.startSupervisedProcess(executable, args, revision, configDigest)
}

func (b *osDesktopBackend) startSystemdRun(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	unit := fmt.Sprintf("xconnect-one-xray-%d-%d", os.Getpid(), time.Now().UnixNano())
	stderrPath, stderrFile, err := b.openProcessLog(revision, "systemd-run")
	if err != nil {
		return processIdentity{}, err
	}
	defer stderrFile.Close()
	command := exec.Command("systemd-run", systemdRunArguments(unit, executable, args)...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = stderrFile
	if err := command.Run(); err != nil {
		_ = exec.Command("systemctl", "stop", unit).Run()
		return processIdentity{}, newHintedError("systemd-run failed to start the process: " + sanitizeProcessLog(readLogTail(stderrPath)))
	}
	pid, err := systemdMainPID(unit, 3*time.Second)
	if err != nil {
		_ = exec.Command("systemctl", "stop", unit).Run()
		return processIdentity{}, newHintedError("systemd-run started a unit but published no main PID")
	}
	identity := processIdentity{
		PID:          pid,
		Executable:   canonicalPath(executable),
		ConfigPath:   configArgument(args),
		ConfigSHA256: configDigest,
		Revision:     revision,
	}
	startToken, err := linuxProcessStartToken(identity.PID)
	if err != nil {
		_ = exec.Command("systemctl", "stop", unit).Run()
		return processIdentity{}, newHintedError("systemd-run process identity could not be recorded")
	}
	identity.StartToken = startToken
	return identity, nil
}

func (b *osDesktopBackend) startSupervisedProcess(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	stderrPath, stderrFile, err := b.openProcessLog(revision, filepath.Base(executable))
	if err != nil {
		return processIdentity{}, err
	}
	command := exec.Command(executable, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = stderrFile
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		_ = stderrFile.Close()
		return processIdentity{}, newHintedError("supervised process start failed: " + sanitizeProcessLog(err.Error()))
	}
	waitErr := make(chan error, 1)
	go func() {
		waitErr <- command.Wait()
		_ = stderrFile.Close()
	}()
	select {
	case err := <-waitErr:
		hint := "supervised process exited immediately"
		if tail := sanitizeProcessLog(readLogTail(stderrPath)); tail != "" {
			hint += ": " + tail
		} else if err != nil {
			hint += ": " + sanitizeProcessLog(err.Error())
		}
		return processIdentity{}, newHintedError(hint)
	case <-time.After(supervisedProcessSettle):
	}
	identity := processIdentity{
		PID:          command.Process.Pid,
		Executable:   canonicalPath(executable),
		ConfigPath:   configArgument(args),
		ConfigSHA256: configDigest,
		Revision:     revision,
	}
	startToken, err := linuxProcessStartToken(identity.PID)
	if err != nil {
		_ = killSupervisedProcess(identity.PID)
		return processIdentity{}, newHintedError("supervised process started but identity could not be recorded")
	}
	identity.StartToken = startToken
	return identity, nil
}

func (b *osDesktopBackend) openProcessLog(revision, name string) (string, *os.File, error) {
	dir := strings.TrimSpace(b.logDirectory)
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "xconnect-one-runtime-logs")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, newHintedError("create runtime log directory failed")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", nil, newHintedError("secure runtime log directory failed")
	}
	base := sanitizeLogName(revision) + "-" + sanitizeLogName(name) + "-" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".stderr"
	path := filepath.Join(dir, base)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", nil, newHintedError("open runtime stderr log failed")
	}
	return path, file, nil
}

func sanitizeLogName(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, strings.TrimSpace(value))
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return "runtime"
	}
	if len(cleaned) > 64 {
		return cleaned[:64]
	}
	return cleaned
}

func readLogTail(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return ""
	}
	if len(raw) > maxSurfacedLogBytes {
		raw = raw[len(raw)-maxSurfacedLogBytes:]
	}
	return string(raw)
}

func sanitizeProcessLog(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if secretLogLine.MatchString(trimmed) {
			lines = append(lines, "[redacted log line]")
			continue
		}
		if longToken.MatchString(trimmed) {
			trimmed = longToken.ReplaceAllString(trimmed, "[redacted]")
		}
		lines = append(lines, trimmed)
	}
	out := strings.Join(lines, " ")
	if len(out) > 512 {
		out = out[:512]
	}
	return out
}

var longToken = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}`)

func killSupervisedProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	if process, err := os.FindProcess(pid); err == nil {
		_ = process.Signal(syscall.SIGTERM)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	if process, err := os.FindProcess(pid); err == nil {
		_ = process.Signal(syscall.SIGKILL)
	}
	return nil
}
