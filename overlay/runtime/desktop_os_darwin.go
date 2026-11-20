//go:build darwin

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const darwinWireGuardRuntimeDir = "/var/run/wireguard"

var darwinInterfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_=+.-]{1,15}$`)
var darwinRealInterfaceNamePattern = regexp.MustCompile(`^utun[0-9]+$`)

// osDesktopBackend owns only the external CLI runtime. It deliberately does
// not invoke NetworkExtension or inspect XConnect APP state; the APP plugin is
// a separate optional composition mode.
type osDesktopBackend struct {
	wireGuardRuntimeDir string
	lstat               func(string) (os.FileInfo, error)
	readFile            func(string) ([]byte, error)
}

func newOSDesktopBackend() *osDesktopBackend {
	return &osDesktopBackend{wireGuardRuntimeDir: darwinWireGuardRuntimeDir}
}

func (b *osDesktopBackend) LookPath(name string) (string, error) {
	path, err := lookPathDarwinRuntime(name)
	if err != nil {
		return "", err
	}
	resolved := canonicalPath(path)
	if name == "xray" {
		if unwrapped := resolveHomebrewXrayWrapper(resolved); unwrapped != "" {
			return unwrapped, nil
		}
	}
	return resolved, nil
}

// resolveHomebrewXrayWrapper unwraps Homebrew's bin/xray shell shim to its
// underlying Mach-O binary in ../libexec/xray so Start and ProcessAlive
// observe the same executable identity without wrapper exec races.
func resolveHomebrewXrayWrapper(resolved string) string {
	if filepath.Base(resolved) != "xray" || filepath.Base(filepath.Dir(resolved)) != "bin" {
		return ""
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 4096 {
		return ""
	}
	raw, err := os.ReadFile(resolved)
	if err != nil || !strings.HasPrefix(string(raw), "#!") || !strings.Contains(string(raw), "libexec/xray") {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(filepath.Dir(resolved)), "libexec", "xray")
	cInfo, err := os.Stat(candidate)
	if err != nil || !cInfo.Mode().IsRegular() {
		return ""
	}
	return canonicalPath(candidate)
}

func (b *osDesktopBackend) Privileged() bool { return os.Geteuid() == 0 }

func (b *osDesktopBackend) InterfaceIndex(name string) (int, error) {
	if !darwinInterfaceNamePattern.MatchString(name) {
		return 0, errors.New("invalid WireGuard interface name")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return iface.Index, nil
		}
	}
	realName, err := b.WireGuardInterfaceName(name)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		if iface.Name == realName {
			return iface.Index, nil
		}
	}
	return 0, nil
}

func (b *osDesktopBackend) Run(ctx context.Context, name string, args ...string) error {
	translated, err := b.translateWireGuardShowArgs(name, args)
	if err != nil {
		return err
	}
	args = translated
	command := exec.CommandContext(ctx, name, args...)
	command.Env = darwinRuntimeCommandEnv(os.Environ(), name)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

// darwinRuntimeCommandEnv ensures Homebrew runtime directories (/opt/homebrew/bin,
// /usr/local/bin, and the executable's own directory) are present in PATH when
// elevated via sudo or LaunchDaemon, so scripts like wg-quick find bash 4+, wg,
// and wireguard-go instead of macOS /bin/bash 3.2.
func darwinRuntimeCommandEnv(base []string, commandPath string) []string {
	var extra []string
	if dir := filepath.Dir(commandPath); filepath.IsAbs(commandPath) && dir != "." && dir != "" {
		extra = append(extra, dir)
	}
	extra = append(extra, "/opt/homebrew/bin", "/usr/local/bin")

	existingPath := ""
	out := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if strings.HasPrefix(entry, "PATH=") {
			existingPath = strings.TrimPrefix(entry, "PATH=")
			continue
		}
		out = append(out, entry)
	}

	seen := make(map[string]struct{})
	merged := make([]string, 0, len(extra)+8)
	for _, dir := range extra {
		if dir == "" {
			continue
		}
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		merged = append(merged, dir)
	}
	for _, dir := range filepath.SplitList(existingPath) {
		if dir == "" {
			continue
		}
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		merged = append(merged, dir)
	}
	return append(out, "PATH="+strings.Join(merged, string(os.PathListSeparator)))
}

func (b *osDesktopBackend) WireGuardInterfaceName(logicalName string) (string, error) {
	if !darwinInterfaceNamePattern.MatchString(logicalName) {
		return "", errors.New("invalid WireGuard logical interface name")
	}
	runtimeDir := b.wireGuardRuntimeDir
	if runtimeDir == "" {
		runtimeDir = darwinWireGuardRuntimeDir
	}
	if err := validateDarwinRuntimeDirectory(b.lstatPath, runtimeDir); err != nil {
		return "", err
	}
	mappingPath := filepath.Join(runtimeDir, logicalName+".name")
	mappingInfo, err := b.lstatPath(mappingPath)
	if err != nil {
		return "", fmt.Errorf("read WireGuard interface mapping: %w", err)
	}
	if err := validateDarwinOwnedFile(mappingInfo, false); err != nil {
		return "", fmt.Errorf("validate WireGuard interface mapping: %w", err)
	}
	raw, err := b.readFilePath(mappingPath)
	if err != nil {
		return "", fmt.Errorf("read WireGuard interface mapping: %w", err)
	}
	realName, err := parseDarwinRealInterfaceName(raw)
	if err != nil {
		return "", err
	}
	socketPath := filepath.Join(runtimeDir, realName+".sock")
	socketInfo, err := b.lstatPath(socketPath)
	if err != nil {
		return "", fmt.Errorf("read WireGuard control socket: %w", err)
	}
	if err := validateDarwinOwnedFile(socketInfo, true); err != nil {
		return "", fmt.Errorf("validate WireGuard control socket: %w", err)
	}
	if !darwinMappingFresh(mappingInfo, socketInfo) {
		return "", errors.New("stale WireGuard interface mapping")
	}
	return realName, nil
}

func (b *osDesktopBackend) translateWireGuardShowArgs(name string, args []string) ([]string, error) {
	if filepath.Base(name) != "wg" || len(args) < 2 || args[0] != "show" || args[1] == "interfaces" || args[1] == "all" {
		return args, nil
	}
	realName, err := b.WireGuardInterfaceName(args[1])
	if err != nil {
		return nil, err
	}
	translated := append([]string(nil), args...)
	translated[1] = realName
	return translated, nil
}

func (b *osDesktopBackend) lstatPath(path string) (os.FileInfo, error) {
	if b.lstat != nil {
		return b.lstat(path)
	}
	return os.Lstat(path)
}

func (b *osDesktopBackend) readFilePath(path string) ([]byte, error) {
	if b.readFile != nil {
		return b.readFile(path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateDarwinOwnedFile(info, false); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return nil, err
	}
	if len(raw) == 64 {
		return nil, errors.New("WireGuard interface mapping is too large")
	}
	return raw, nil
}

func validateDarwinRuntimeDirectory(lstat func(string) (os.FileInfo, error), path string) error {
	info, err := lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !darwinRootOwned(info) || info.Mode().Perm()&0022 != 0 {
		return errors.New("WireGuard runtime directory is not root-controlled")
	}
	return nil
}

func validateDarwinOwnedFile(info os.FileInfo, socket bool) error {
	permissions := info.Mode().Perm()
	modesOK := permissions == 0o400 || permissions == 0o600
	if socket {
		modesOK = permissions == 0o600 || permissions == 0o700
	}
	if info.Mode()&os.ModeSymlink != 0 || !darwinRootOwned(info) || !modesOK {
		return errors.New("path is symlinked or has unsafe ownership/permissions")
	}
	if socket {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("WireGuard control path is not a socket")
		}
	} else if !info.Mode().IsRegular() {
		return errors.New("WireGuard mapping path is not a regular file")
	}
	return nil
}

func darwinRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func parseDarwinRealInterfaceName(raw []byte) (string, error) {
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	name := string(raw)
	if !darwinRealInterfaceNamePattern.MatchString(name) {
		return "", errors.New("invalid Darwin WireGuard real interface mapping")
	}
	return name, nil
}

func darwinMappingFresh(mapping, socket os.FileInfo) bool {
	delta := socket.ModTime().Unix() - mapping.ModTime().Unix()
	return delta >= -1 && delta <= 1
}

func (b *osDesktopBackend) Start(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	command := exec.Command(executable, args...)
	command.Env = darwinStartCommandEnv(os.Environ(), executable)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = detachedProcessAttributes()
	if err := command.Start(); err != nil {
		return processIdentity{}, err
	}
	identity := processIdentity{
		PID:          command.Process.Pid,
		Executable:   canonicalPath(executable),
		ConfigPath:   configArgument(args),
		ConfigSHA256: configDigest,
		Revision:     revision,
	}
	token, err := darwinProcessStartToken(identity.PID)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Process.Release()
		return processIdentity{}, err
	}
	identity.StartToken = token
	if err := command.Process.Release(); err != nil {
		_ = command.Process.Kill()
		return processIdentity{}, err
	}
	return identity, nil
}

func detachedProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func (b *osDesktopBackend) ProcessAlive(identity processIdentity) (bool, error) {
	if identity.PID <= 0 || identity.StartToken == "" || identity.Executable == "" || identity.ConfigPath == "" {
		return false, errors.New("incomplete process identity")
	}
	commandLine, err := darwinPS(identity.PID, "command=")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fields := strings.Fields(commandLine)
	if len(fields) == 0 || canonicalPath(fields[0]) != canonicalPath(identity.Executable) {
		return false, errors.New("executable identity mismatch")
	}
	started, err := darwinPS(identity.PID, "lstart=")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !darwinStartTokenMatches(identity.StartToken, darwinProcessStartTimes(identity.PID, started), commandLine) {
		return false, errors.New("process start identity mismatch")
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
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
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
	return process.Signal(syscall.SIGKILL)
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
	if _, _, err := net.SplitHostPort(address); err != nil {
		return false, err
	}
	// lsof is present on supported macOS releases. Its output is discarded: it
	// can contain user paths and is only used as an ownership predicate.
	command := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(identity.PID), "-iUDP@"+address)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err == nil {
		return true, nil
	} else if _, ok := err.(*exec.ExitError); ok {
		return false, nil
	} else {
		return false, err
	}
}

func darwinProcessStartToken(pid int) (string, error) {
	started, err := darwinPSLocale(pid, "lstart=", "C", "UTC")
	if err != nil {
		return "", err
	}
	command, err := darwinPS(pid, "command=")
	if err != nil {
		return "", err
	}
	return darwinStartToken(started, command), nil
}

// A runtime manifest can outlive the locale of the process that created it.
// macOS localizes `ps lstart` (including weekday, month and spacing), so the
// old token may differ even though the PID, executable, arguments and config
// digest still identify the exact same process. Write new tokens in a stable
// locale and accept the known legacy locale renderings for migration.
func darwinStartTokenMatches(want string, starts []string, command string) bool {
	for _, started := range starts {
		if darwinStartToken(started, command) == want {
			return true
		}
	}
	return false
}

func darwinProcessStartTimes(pid int, fallback string) []string {
	starts := []string{fallback}
	for _, candidate := range []struct{ locale, timezone string }{
		{"C", "UTC"}, {"C", "Asia/Shanghai"},
		{"zh_CN.UTF-8", "UTC"}, {"zh_CN.UTF-8", "Asia/Shanghai"},
		{"en_US.UTF-8", "UTC"}, {"en_US.UTF-8", "Asia/Shanghai"},
	} {
		started, err := darwinPSLocale(pid, "lstart=", candidate.locale, candidate.timezone)
		if err == nil && !containsString(starts, started) {
			starts = append(starts, started)
		}
	}
	return starts
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func darwinStartToken(started, command string) string {
	digest := sha256.Sum256([]byte(started + "\n" + command))
	return hex.EncodeToString(digest[:])
}

func darwinPS(pid int, field string) (string, error) {
	return darwinPSLocale(pid, field, "", "")
}

func darwinPSLocale(pid int, field, locale, timezone string) (string, error) {
	command := exec.Command("/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", field)
	command.Env = darwinCommandEnvironment(locale, timezone)
	raw, err := command.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", os.ErrNotExist
		}
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", os.ErrNotExist
	}
	return value, nil
}

func darwinCommandEnvironment(locale, timezone string) []string {
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "LC_ALL=") || strings.HasPrefix(entry, "TZ=") {
			continue
		}
		environment = append(environment, entry)
	}
	if locale != "" {
		environment = append(environment, "LC_ALL="+locale)
	}
	if timezone != "" {
		environment = append(environment, "TZ="+timezone)
	}
	return environment
}

func darwinStartCommandEnv(base []string, executable string) []string {
	env := darwinRuntimeCommandEnv(base, executable)
	if filepath.Base(executable) == "xray" && filepath.Base(filepath.Dir(executable)) == "libexec" {
		hasAssetEnv := false
		for _, entry := range env {
			if strings.HasPrefix(entry, "XRAY_LOCATION_ASSET=") {
				hasAssetEnv = true
				break
			}
		}
		if !hasAssetEnv {
			shareDir := filepath.Join(filepath.Dir(filepath.Dir(executable)), "share", "xray")
			if info, err := os.Stat(shareDir); err == nil && info.IsDir() {
				env = append(env, "XRAY_LOCATION_ASSET="+shareDir)
			}
		}
	}
	return env
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
