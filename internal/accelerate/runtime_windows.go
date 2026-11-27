//go:build windows

package accelerate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/proxy/tun"
	"golang.org/x/sys/windows"
)

type windowsControlInfo struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

func IsSupportedOS() bool { return true }

func IsPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func runtimeDirPath() string {
	base := strings.TrimSpace(os.Getenv("ProgramData"))
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "xconnect-accelerate")
}

func lockRuntime() (*os.File, error) {
	if !IsPrivileged() {
		return nil, errors.New("run from an elevated Administrator terminal to manage Windows TUN acceleration")
	}
	dir := runtimeDirPath()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("acceleration is already running or starting")
		}
		return nil, err
	}
	return file, nil
}

func controlFilePath() string {
	return filepath.Join(runtimeDirPath(), "control.json")
}

func randomHexToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func Run(ctx context.Context, _ uint32, load func(context.Context) ([]byte, error), output io.Writer) (result error) {
	lock, err := lockRuntime()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	profile, err := load(ctx)
	if err != nil {
		return err
	}
	cfg, err := decodeProfileWithSystemRoutes(profile, tunName, PublicRouteCIDRs())
	if err != nil {
		return err
	}

	token, err := randomHexToken()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	ctrlPath := controlFilePath()
	ctrlData, err := json.Marshal(windowsControlInfo{
		Addr:  listener.Addr().String(),
		Token: token,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(ctrlPath, ctrlData, 0o600); err != nil {
		return err
	}
	defer os.Remove(ctrlPath)

	instance, err := core.New(cfg)
	if err != nil {
		return errors.New("could not create the Xray TUN instance")
	}
	defer func() { result = errors.Join(result, instance.Close()) }()
	if err := instance.Start(); err != nil {
		return fmt.Errorf("could not start the Windows Wintun TUN: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go serveControlTCP(listener, token, cancel)
	fmt.Fprintln(output, "Acceleration on for Windows. Use Ctrl+C or xconnect accelerate down to stop.")
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-runCtx.Done():
			return nil
		case <-ticker.C:
			next, err := load(runCtx)
			if runCtx.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("acceleration stopped: %w", err)
			}
			if !bytes.Equal(profile, next) {
				return errors.New("acceleration profile changed; run xconnect accelerate up again")
			}
		}
	}
}

func serveControlTCP(listener net.Listener, token string, stop func()) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(io.LimitReader(conn, 256))
		line, err := reader.ReadString('\n')
		if err == nil {
			parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 2)
			if len(parts) == 2 && subtle.ConstantTimeCompare([]byte(parts[0]), []byte(token)) == 1 {
				switch parts[1] {
				case "s":
					_, _ = fmt.Fprintln(conn, "Acceleration on for Windows.")
				case "d":
					_, _ = fmt.Fprintln(conn, "Stopping acceleration.")
					stop()
				}
			}
		}
		_ = conn.Close()
	}
}

func Control(ctx context.Context, down bool, output io.Writer) error {
	if !IsPrivileged() {
		return errors.New("run from an elevated Administrator terminal to manage Windows TUN acceleration")
	}
	ctrlPath := controlFilePath()
	raw, err := os.ReadFile(ctrlPath)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(output, "Acceleration is off.")
		return nil
	}
	if err != nil {
		return err
	}
	var info windowsControlInfo
	if err := json.Unmarshal(raw, &info); err != nil || info.Addr == "" || info.Token == "" {
		return errors.New("invalid acceleration control state")
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", info.Addr)
	if err != nil {
		fmt.Fprintln(output, "Acceleration is off.")
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	action := "s"
	if down {
		action = "d"
	}
	if _, err := fmt.Fprintf(conn, "%s %s\n", info.Token, action); err != nil {
		return err
	}
	if _, err := io.Copy(output, conn); err != nil || !down {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		if _, err := os.Stat(ctrlPath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(output, "Acceleration is off.")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return errors.New("acceleration is still stopping")
		case <-ticker.C:
		}
	}
}
