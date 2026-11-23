//go:build linux

package runtime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type osDesktopBackend struct {
	logDirectory string
}

var systemdLookPath = exec.LookPath

func newOSDesktopBackend() *osDesktopBackend { return &osDesktopBackend{} }

func (b *osDesktopBackend) LookPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return canonicalPath(path), nil
}

func (b *osDesktopBackend) Privileged() bool { return os.Geteuid() == 0 }

// Modified for XConnect-One: inspect identity, distinguishing absence from errors.
func (b *osDesktopBackend) InterfaceIndex(name string) (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return iface.Index, nil
		}
	}
	return 0, nil
}

func (b *osDesktopBackend) Run(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func (b *osDesktopBackend) Start(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	if !shouldUseSystemd(os.Getenv("XCONNECT_LINUX_PROCESS_MODE"), systemSystemdLive, systemdLookPath) {
		return b.startDirectLinuxProcess(executable, args, revision, configDigest)
	}
	return b.startSystemdRun(executable, args, revision, configDigest)
}

func shouldUseSystemd(mode string, systemdLive func() bool, lookPath func(string) (string, error)) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "systemd":
		return true
	case "direct":
		return false
	default:
		if systemdLive == nil || lookPath == nil {
			return false
		}
		if !systemdLive() {
			return false
		}
		if _, err := lookPath("systemd-run"); err != nil {
			return false
		}
		if _, err := lookPath("systemctl"); err != nil {
			return false
		}
		return true
	}
}

func systemdRunArguments(unit, executable string, args []string) []string {
	result := []string{
		"--unit", unit,
		"--collect",
		"--quiet",
		"--property=Type=exec",
		"--property=Restart=no",
		"--property=StandardOutput=null",
		"--property=StandardError=null",
		"--",
		executable,
	}
	return append(result, args...)
}

func systemdMainPID(unit string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := exec.Command("systemctl", "show", "--property=MainPID", "--value", unit).Output()
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if parseErr == nil && pid > 0 {
				return pid, nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return 0, errors.New("systemd runtime did not publish a main PID")
}

func (b *osDesktopBackend) ProcessAlive(identity processIdentity) (bool, error) {
	if identity.PID <= 0 || identity.StartToken == "" || identity.Executable == "" || identity.ConfigPath == "" {
		return false, errors.New("incomplete process identity")
	}
	procDirectory := filepath.Join("/proc", strconv.Itoa(identity.PID))
	state, startToken, err := linuxProcessStat(identity.PID)
	if errors.Is(err, os.ErrNotExist) || (err == nil && (state == 'Z' || state == 'X')) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if startToken != identity.StartToken {
		return false, errors.New("process start identity mismatch")
	}
	executable, err := os.Readlink(filepath.Join(procDirectory, "exe"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if canonicalPath(executable) != canonicalPath(identity.Executable) {
		return false, errors.New("executable identity mismatch")
	}
	cmdline, err := os.ReadFile(filepath.Join(procDirectory, "cmdline"))
	if err != nil {
		return false, err
	}
	arguments := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if !containsConfigArgument(arguments, identity.ConfigPath) {
		return false, errors.New("process config identity mismatch")
	}
	return true, nil
}

func (b *osDesktopBackend) Stop(identity processIdentity) error {
	alive, err := b.ProcessAlive(identity)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	process, err := os.FindProcess(identity.PID)
	if err != nil {
		return err
	}
	_ = syscall.Kill(-identity.PID, syscall.SIGTERM)
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		alive, err = b.ProcessAlive(identity)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
	}
	alive, err = b.ProcessAlive(identity)
	if err != nil || !alive {
		return err
	}
	_ = syscall.Kill(-identity.PID, syscall.SIGKILL)
	if err := process.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func (b *osDesktopBackend) LoopbackAvailable(address string) (bool, error) {
	listener, err := net.ListenPacket("udp4", address)
	if err == nil {
		_ = listener.Close()
		return true, nil
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return false, nil
	}
	return false, err
}

func (b *osDesktopBackend) LoopbackOwned(identity processIdentity, address string) (bool, error) {
	_, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return false, err
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil {
		return false, err
	}
	inodes, err := processSocketInodes(identity.PID)
	if err != nil {
		return false, err
	}
	file, err := os.Open("/proc/net/udp")
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[1] == "local_address" {
			continue
		}
		addressParts := strings.Split(fields[1], ":")
		if len(addressParts) != 2 || addressParts[0] != "0100007F" {
			continue
		}
		candidatePort, parseErr := strconv.ParseUint(addressParts[1], 16, 16)
		if parseErr == nil && candidatePort == port {
			if _, ok := inodes[fields[9]]; ok {
				return true, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func processSocketInodes(pid int) (map[string]struct{}, error) {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, err
	}
	inodes := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	return inodes, nil
}

func linuxProcessStartToken(pid int) (string, error) {
	_, startToken, err := linuxProcessStat(pid)
	return startToken, err
}

func linuxProcessStat(pid int) (byte, string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, "", err
	}
	closingParenthesis := strings.LastIndexByte(string(raw), ')')
	if closingParenthesis < 0 || closingParenthesis+2 >= len(raw) {
		return 0, "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[closingParenthesis+2:]))
	if len(fields) <= 19 || len(fields[0]) == 0 {
		return 0, "", errors.New("incomplete process stat")
	}
	return fields[0][0], fields[19], nil
}

func (b *osDesktopBackend) WireGuardPublicKey(ctx context.Context, wgPath, logicalName string) (string, error) {
	if !isSafeLinuxInterfaceName(logicalName) {
		return "", errors.New("invalid WireGuard interface name")
	}
	command := exec.CommandContext(ctx, wgPath, "show", logicalName, "public-key")
	command.Stdin = nil
	raw, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (b *osDesktopBackend) ReclaimWireGuardInterface(ctx context.Context, logicalName string) error {
	if !isSafeLinuxInterfaceName(logicalName) {
		return errors.New("invalid WireGuard interface name")
	}
	ipBin, err := lookPathLinuxIP()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, ipBin, "link", "delete", "dev", logicalName)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func (b *osDesktopBackend) WireGuardPeerStats(ctx context.Context, wgPath, logicalName string) (WireGuardStats, error) {
	if !isSafeLinuxInterfaceName(logicalName) {
		return WireGuardStats{}, errors.New("invalid WireGuard interface name")
	}
	hsOut, err := exec.CommandContext(ctx, wgPath, "show", logicalName, "latest-handshakes").Output()
	if err != nil {
		return WireGuardStats{}, err
	}
	txOut, err := exec.CommandContext(ctx, wgPath, "show", logicalName, "transfer").Output()
	if err != nil {
		return WireGuardStats{}, err
	}
	rx, tx := parseWireGuardTransfer(string(txOut))
	return WireGuardStats{
		LatestHandshake: parseWireGuardHandshakes(string(hsOut)),
		RxBytes:         rx,
		TxBytes:         tx,
	}, nil
}

func (b *osDesktopBackend) NudgeWireGuardPeer(ctx context.Context, wgPath, logicalName, peerPublicKey, endpoint string) error {
	if !isSafeLinuxInterfaceName(logicalName) || strings.TrimSpace(peerPublicKey) == "" || strings.TrimSpace(endpoint) == "" {
		return errors.New("invalid WireGuard peer nudge parameters")
	}
	command := exec.CommandContext(ctx, wgPath, "set", logicalName, "peer", peerPublicKey, "endpoint", endpoint)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func isSafeLinuxInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 15 || strings.ContainsAny(name, "/\\ \t\n\r") {
		return false
	}
	return name != "." && name != ".."
}

func lookPathLinuxIP() (string, error) {
	if p, err := exec.LookPath("ip"); err == nil {
		return canonicalPath(p), nil
	}
	for _, candidate := range []string{"/usr/sbin/ip", "/sbin/ip"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return canonicalPath(candidate), nil
		}
	}
	return "", os.ErrNotExist
}

func containsConfigArgument(args []string, expected string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-config" && filepath.Clean(args[index+1]) == filepath.Clean(expected) {
			return true
		}
	}
	return false
}

func canonicalPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err == nil {
		path = absolute
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		path = resolved
	}
	return filepath.Clean(path)
}

func secureDirectoryPlatform(path string) error { return os.Chmod(path, 0o700) }

func secureFilePlatform(path string) error { return os.Chmod(path, 0o600) }

func replaceRuntimeFile(source, target string) error { return os.Rename(source, target) }

func privateDirectoryPlatform(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode().Perm() == 0o700
}

func privateRegularFilePlatform(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}
