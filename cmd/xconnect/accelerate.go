package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-One/internal/accelerate"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func runAccelerate(ctx context.Context, args []string, stdout, stderr io.Writer, client *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: xconnect accelerate {login|up|status|down}")
		fmt.Fprintln(stdout, "On Linux: log in, then run sudo xconnect accelerate up. On a root shell, add --uid <non-root-user-id>.")
		return nil
	}
	action, args := args[0], args[1:]
	switch action {
	case "login":
		return runLoginFor(ctx, args, stdout, stderr, client, newRuntime, newCredentials, true)
	case "up", "status", "down":
	default:
		return fault.New(fault.CodeInvalidInput, "expected accelerate login, up, status, or down", nil)
	}
	flags := flag.NewFlagSet("xconnect accelerate "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDirectory(), "XConnect login state (shared with One)")
	var gateway, userID *string
	var foreground *bool
	if action == "up" {
		gateway = flags.String("gateway", "", "acceleration node ID, name or host (default: first supported node)")
		userID = flags.String("uid", "", "Linux UID to accelerate (default: sudo invoker)")
		foreground = flags.Bool("foreground", true, "run in the foreground")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse accelerate arguments", err)
	}
	if flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "unexpected positional arguments for accelerate", nil)
	}
	if runtime.GOOS != "linux" {
		return errors.New("TUN acceleration is available on Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("use sudo to manage Linux TUN acceleration")
	}
	if action != "up" {
		return accelerate.Control(ctx, action == "down", stdout)
	}
	if !*foreground {
		return errors.New("accelerate up runs in the foreground")
	}
	uid, ok := accelerationUID(*userID)
	if !ok {
		return fault.New(fault.CodeInvalidInput, "set --uid to the non-root Linux UID to accelerate", nil)
	}
	dir := expandUserPath(*stateDir)
	return accelerate.Run(ctx, uid, func(ctx context.Context) ([]byte, error) {
		session, err := credential.LoadUserSession(dir)
		if err != nil {
			return nil, errors.New("cannot load login session; run xconnect accelerate login")
		}
		return accelerate.Profile(ctx, client, session, strings.TrimSpace(*gateway))
	}, stdout)
}

func accelerationUID(override string) (uint32, bool) {
	if override != "" {
		uid, err := strconv.ParseUint(override, 10, 32)
		return uint32(uid), err == nil && uid > 0 && uid < 1<<32-1
	}
	uid, _, hasSudo := credential.ResolveSudoInvoker()
	return uid, hasSudo && uid > 0 && uid < 1<<32-1
}
