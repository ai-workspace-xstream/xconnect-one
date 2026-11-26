//go:build linux

package accelerate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/tun"
	"golang.org/x/sys/unix"
)

const runtimeDir = "/run/xconnect-accelerate"

func lockRuntime() (*os.File, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("use sudo to manage Linux TUN acceleration")
	}
	if err := os.Mkdir(runtimeDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(runtimeDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return nil, errors.New("acceleration runtime directory must be root-owned with mode 0700")
	}
	path := filepath.Join(runtimeDir, "lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("acceleration is already running or starting")
		}
		return nil, err
	}
	return lock, nil
}

func controlAddress() *net.UnixAddr {
	return &net.UnixAddr{Name: filepath.Join(runtimeDir, "control.sock"), Net: "unix"}
}

func Run(ctx context.Context, uid uint32, load func(context.Context) ([]byte, error), output io.Writer) (result error) {
	if uid == 0 {
		return errors.New("acceleration requires a non-root Linux user")
	}
	if platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" }) != "" {
		return errors.New("acceleration requires its own TUN; remove the inherited Xray TUN descriptor")
	}
	lock, err := lockRuntime()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := reserveRoutes(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	profile, err := load(ctx)
	if err != nil {
		return err
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(profile))
	if err != nil {
		return errors.New("could not decode the selected Xray profile")
	}

	addr := controlAddress()
	if info, err := os.Lstat(addr.Name); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("acceleration control path is not a socket")
		}
		if err := os.Remove(addr.Name); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	instance, err := core.New(cfg)
	if err != nil {
		return errors.New("could not create the Xray TUN instance")
	}
	defer func() { result = errors.Join(result, instance.Close()) }()
	if err := instance.Start(); err != nil {
		return errors.New("could not start the Xray TUN; check /dev/net/tun and CAP_NET_ADMIN")
	}
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("find acceleration TUN: %w", err)
	}
	cleanup, err := installRoutes(link, uid)
	defer func() { result = errors.Join(result, cleanup()) }()
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go serveControl(listener, uid, cancel)
	fmt.Fprintf(output, "Acceleration on for Linux UID %d. Use Ctrl+C or xconnect accelerate down to stop.\n", uid)
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

func serveControl(listener *net.UnixListener, uid uint32, stop func()) {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var action [1]byte
		if _, err := io.ReadFull(conn, action[:]); err == nil {
			switch action[0] {
			case 's':
				_, _ = fmt.Fprintf(conn, "Acceleration on for Linux UID %d.\n", uid)
			case 'd':
				_, _ = fmt.Fprintln(conn, "Stopping acceleration.")
				stop()
			}
		}
		_ = conn.Close()
	}
}

func Control(ctx context.Context, down bool, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("use sudo to manage Linux TUN acceleration")
	}
	addr := controlAddress()
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "unix", addr.Name)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ECONNREFUSED) {
		fmt.Fprintln(output, "Acceleration is off.")
		return nil
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	action := byte('s')
	if down {
		action = 'd'
	}
	if _, err := conn.Write([]byte{action}); err != nil {
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
		if _, err := os.Lstat(addr.Name); errors.Is(err, os.ErrNotExist) {
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
