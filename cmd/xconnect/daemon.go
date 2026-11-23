package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

const (
	daemonChildEnvVar   = "XCONNECT_ONE_DAEMON_CHILD"
	daemonReadyFileEnv  = "XCONNECT_ONE_READY_FILE"
	defaultReadyTimeout = 20 * time.Second
	daemonPollInterval  = 50 * time.Millisecond
	daemonLogTailLines  = 16
	daemonLogTailBytes  = 4096
)

var startDaemonProcessFunc = spawnDaemonUp

type daemonStartResult struct {
	Daemon         bool                `json:"daemon"`
	AlreadyRunning bool                `json:"already_running,omitempty"`
	Ready          bool                `json:"ready"`
	PID            int                 `json:"pid"`
	StateDir       string              `json:"state_dir"`
	LogFile        string              `json:"log_file"`
	RuntimeMode    string              `json:"runtime_mode,omitempty"`
	Sync           *usecase.SyncResult `json:"sync,omitempty"`
}

type daemonReadyPayload struct {
	Ready bool                `json:"ready"`
	Sync  *usecase.SyncResult `json:"sync,omitempty"`
}

type daemonUpOptions struct {
	StateDir        string
	LogFile         string
	RuntimeMode     string
	OrigArgs        []string
	Executable      string
	ChildArgsPrefix []string
	ReadyTimeout    time.Duration
}

func daemonRuntimeDir(stateDir string) string {
	return filepath.Join(stateDir, "runtime")
}

func daemonPIDPath(stateDir string) string {
	return filepath.Join(daemonRuntimeDir(stateDir), "daemon.pid")
}

func defaultDaemonLogPath(stateDir string) string {
	return filepath.Join(daemonRuntimeDir(stateDir), "xconnect-one.log")
}

func readDaemonPID(stateDir string) (int, error) {
	raw, err := os.ReadFile(daemonPIDPath(stateDir))
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return 0, fmt.Errorf("empty daemon pid file")
	}
	pid, err := strconv.Atoi(trimmed)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid daemon pid %q", trimmed)
	}
	return pid, nil
}

func writeDaemonPID(stateDir string, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid daemon pid %d", pid)
	}
	pidPath := daemonPIDPath(stateDir)
	runtimeDir := filepath.Dir(pidPath)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return err
	}
	tmpPath := pidPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, pidPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func removeDaemonPID(stateDir string) error {
	err := os.Remove(daemonPIDPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func removeDaemonPIDIfSelf(stateDir string) error {
	pid, err := readDaemonPID(stateDir)
	if err != nil || pid != os.Getpid() {
		return nil
	}
	return removeDaemonPID(stateDir)
}

func stopRecordedDaemon(stateDir string) (bool, error) {
	pid, err := readDaemonPID(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if errors.Is(err, os.ErrPermission) {
			return false, fault.New(fault.CodeRuntimePermission, "read background daemon pid", err)
		}
		_ = removeDaemonPID(stateDir)
		return false, nil
	}
	stopped := false
	if isDaemonProcessAlive(pid) {
		if stopErr := stopDaemonProcess(pid, 5*time.Second); stopErr != nil {
			if errors.Is(stopErr, os.ErrPermission) {
				return false, fault.New(fault.CodeRuntimePermission, "stop background daemon", stopErr)
			}
			return false, fault.New(fault.CodeRuntimeApplyFailed, "stop background daemon", stopErr)
		}
		stopped = true
	}
	_ = removeDaemonPID(stateDir)
	return stopped, nil
}

func stripDaemonFlags(args []string) []string {
	filtered := make([]string, 0, len(args))
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		switch {
		case arg == "-D" || arg == "--daemon" || arg == "-daemon" ||
			strings.HasPrefix(arg, "-D=") || strings.HasPrefix(arg, "--daemon=") || strings.HasPrefix(arg, "-daemon="):
			continue
		case arg == "--log-file" || arg == "-log-file":
			skipNext = true
			continue
		case strings.HasPrefix(arg, "--log-file=") || strings.HasPrefix(arg, "-log-file="):
			continue
		case arg == "--gateway" || arg == "-gateway":
			skipNext = true
			continue
		case strings.HasPrefix(arg, "--gateway=") || strings.HasPrefix(arg, "-gateway="):
			continue
		case arg == "--state-dir" || arg == "-state-dir":
			skipNext = true
			continue
		case strings.HasPrefix(arg, "--state-dir=") || strings.HasPrefix(arg, "-state-dir="):
			continue
		case arg == "--no-sudo" || arg == "-no-sudo" ||
			strings.HasPrefix(arg, "--no-sudo=") || strings.HasPrefix(arg, "-no-sudo="):
			continue
		case arg == "--foreground" || arg == "-foreground" ||
			strings.HasPrefix(arg, "--foreground=") || strings.HasPrefix(arg, "-foreground="):
			continue
		default:
			filtered = append(filtered, arg)
		}
	}
	return filtered
}

func spawnDaemonUp(ctx context.Context, opts daemonUpOptions) (daemonStartResult, error) {
	if strings.TrimSpace(opts.StateDir) == "" {
		return daemonStartResult{}, fault.New(fault.CodeInvalidInput, "daemon mode requires state directory", nil)
	}

	logPath := defaultDaemonLogPath(opts.StateDir)
	if trimmed := strings.TrimSpace(opts.LogFile); trimmed != "" {
		logPath = expandUserPath(trimmed)
	}

	runtimeDir := daemonRuntimeDir(opts.StateDir)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return daemonStartResult{}, fault.New(fault.CodeStateIO, "create daemon runtime directory", err)
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return daemonStartResult{}, fault.New(fault.CodeStateIO, "create daemon log directory", err)
	}

	if pid, err := readDaemonPID(opts.StateDir); err == nil && pid > 0 {
		if isDaemonProcessAlive(pid) {
			return daemonStartResult{
				Daemon:         true,
				AlreadyRunning: true,
				Ready:          true,
				PID:            pid,
				StateDir:       opts.StateDir,
				LogFile:        logPath,
				RuntimeMode:    opts.RuntimeMode,
			}, nil
		}
		_ = removeDaemonPID(opts.StateDir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, os.ErrPermission) {
			return daemonStartResult{}, fault.New(fault.CodeRuntimePermission, "read daemon pid", err)
		}
		_ = removeDaemonPID(opts.StateDir)
	}

	exePath := strings.TrimSpace(opts.Executable)
	if exePath == "" {
		resolved, err := os.Executable()
		if err != nil || strings.TrimSpace(resolved) == "" {
			exePath = os.Args[0]
		} else {
			exePath = resolved
		}
	}

	readyFilePath, err := uniqueDaemonReadyFilePath(runtimeDir)
	if err != nil {
		return daemonStartResult{}, fault.New(fault.CodeStateIO, "prepare daemon ready file", err)
	}
	_ = os.Remove(readyFilePath)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return daemonStartResult{}, fault.New(fault.CodeStateIO, "open daemon log file", err)
	}

	childArgs := make([]string, 0, len(opts.ChildArgsPrefix)+len(opts.OrigArgs)+8)
	childArgs = append(childArgs, opts.ChildArgsPrefix...)
	if mode := strings.ToLower(strings.TrimSpace(opts.RuntimeMode)); mode != "" {
		childArgs = append(childArgs, "--runtime", mode)
	}
	childArgs = append(childArgs, "up", "--state-dir", opts.StateDir, "--foreground", "--no-sudo")
	childArgs = append(childArgs, stripDaemonFlags(opts.OrigArgs)...)

	cmd := exec.Command(exePath, childArgs...)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = daemonChildEnv(readyFilePath)
	configureDetachedProcess(cmd)

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		_ = os.Remove(readyFilePath)
		return daemonStartResult{}, fault.New(fault.CodeRuntimeApplyFailed, "start daemon process", err)
	}
	_ = logFile.Close()

	pid := cmd.Process.Pid
	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()

	if err := writeDaemonPID(opts.StateDir, pid); err != nil {
		_ = stopDaemonProcess(pid, 2*time.Second)
		select {
		case <-exitCh:
		case <-time.After(500 * time.Millisecond):
		}
		_ = os.Remove(readyFilePath)
		return daemonStartResult{}, fault.New(fault.CodeStateIO, "write daemon pid file", err)
	}

	readyTimeout := opts.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = defaultReadyTimeout
	}

	ticker := time.NewTicker(daemonPollInterval)
	defer ticker.Stop()
	timer := time.NewTimer(readyTimeout)
	defer timer.Stop()

	for {
		if payload, ok := readDaemonReadyFile(readyFilePath); ok && payload.Ready {
			_ = os.Remove(readyFilePath)
			return daemonStartResult{
				Daemon:      true,
				Ready:       true,
				PID:         pid,
				StateDir:    opts.StateDir,
				LogFile:     logPath,
				RuntimeMode: opts.RuntimeMode,
				Sync:        payload.Sync,
			}, nil
		}

		select {
		case waitErr := <-exitCh:
			_ = removeDaemonPID(opts.StateDir)
			_ = os.Remove(readyFilePath)
			msg := "daemon exited before becoming ready"
			if waitErr != nil {
				msg = fmt.Sprintf("daemon exited before becoming ready (%v)", waitErr)
			}
			if tail := readLogTail(logPath, daemonLogTailLines, daemonLogTailBytes); tail != "" {
				msg += "\n" + tail
			}
			return daemonStartResult{}, fault.New(fault.CodeRuntimeApplyFailed, msg, waitErr)

		case <-ctx.Done():
			_ = stopDaemonProcess(pid, 2*time.Second)
			_ = removeDaemonPID(opts.StateDir)
			_ = os.Remove(readyFilePath)
			return daemonStartResult{}, ctx.Err()

		case <-timer.C:
			if payload, ok := readDaemonReadyFile(readyFilePath); ok && payload.Ready {
				_ = os.Remove(readyFilePath)
				return daemonStartResult{
					Daemon:      true,
					Ready:       true,
					PID:         pid,
					StateDir:    opts.StateDir,
					LogFile:     logPath,
					RuntimeMode: opts.RuntimeMode,
					Sync:        payload.Sync,
				}, nil
			}
			_ = os.Remove(readyFilePath)
			return daemonStartResult{
				Daemon:      true,
				Ready:       false,
				PID:         pid,
				StateDir:    opts.StateDir,
				LogFile:     logPath,
				RuntimeMode: opts.RuntimeMode,
			}, nil

		case <-ticker.C:
		}
	}
}

func uniqueDaemonReadyFilePath(runtimeDir string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return filepath.Join(runtimeDir, fmt.Sprintf("daemon-ready-%s.json", hex.EncodeToString(buf[:]))), nil
}

func daemonChildEnv(readyFilePath string) []string {
	base := os.Environ()
	env := make([]string, 0, len(base)+2)
	for _, entry := range base {
		if strings.HasPrefix(entry, daemonChildEnvVar+"=") || strings.HasPrefix(entry, daemonReadyFileEnv+"=") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, daemonChildEnvVar+"=1", daemonReadyFileEnv+"="+readyFilePath)
	return env
}

func writeDaemonReadyFile(path string, payload daemonReadyPayload) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func readDaemonReadyFile(path string) (daemonReadyPayload, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return daemonReadyPayload{}, false
	}
	var payload daemonReadyPayload
	if err := json.Unmarshal(raw, &payload); err != nil || !payload.Ready {
		return daemonReadyPayload{}, false
	}
	return payload, true
}

func readLogTail(path string, maxLines, maxBytes int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return ""
	}
	offset := int64(0)
	if maxBytes > 0 && info.Size() > int64(maxBytes) {
		offset = info.Size() - int64(maxBytes)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	raw, err := io.ReadAll(f)
	if err != nil || len(raw) == 0 {
		return ""
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
