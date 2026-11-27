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
		fmt.Fprintln(stdout, "Usage: xconnect accelerate {login|join|up|status|down}")
		fmt.Fprintln(stdout, "On Linux/macOS: log in, join an acceleration node, then run sudo xconnect accelerate up (on a Linux root shell, add --uid <non-root-user-id>).")
		fmt.Fprintln(stdout, "On Windows: log in, join an acceleration node, then run xconnect accelerate up from an Administrator terminal.")
		return nil
	}
	action, args := args[0], args[1:]
	switch action {
	case "login":
		return runLoginFor(ctx, args, stdout, stderr, client, newRuntime, newCredentials, true)
	case "join", "up", "status", "down":
	default:
		return fault.New(fault.CodeInvalidInput, "expected accelerate login, join, up, status, or down", nil)
	}
	flags := flag.NewFlagSet("xconnect accelerate "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDirectory(), "XConnect login state (shared with One)")
	var nodeSelector, userID *string
	var foreground *bool
	if action == "join" {
		nodeSelector = flags.String("node", "", "acceleration node ID, name or host")
	}
	if action == "up" {
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
	if !accelerate.IsSupportedOS() {
		return errors.New("TUN acceleration is available on Linux, macOS, and Windows")
	}
	dir := expandUserPath(*stateDir)
	if action == "join" {
		return joinAcceleration(ctx, client, dir, strings.TrimSpace(*nodeSelector), os.Stdin, stdout, isTerminal(os.Stdin))
	}
	if !accelerate.IsPrivileged() {
		if runtime.GOOS == "windows" {
			return errors.New("run from an elevated Administrator terminal to manage Windows TUN acceleration")
		}
		return errors.New("use sudo to manage TUN acceleration")
	}
	if action != "up" {
		return accelerate.Control(ctx, action == "down", stdout)
	}
	if !*foreground {
		return errors.New("accelerate up runs in the foreground")
	}
	var uid uint32
	if runtime.GOOS == "linux" {
		var ok bool
		uid, ok = accelerationUID(*userID)
		if !ok {
			return fault.New(fault.CodeInvalidInput, "set --uid to the non-root Linux UID to accelerate", nil)
		}
	}
	return accelerate.Run(ctx, uid, func(ctx context.Context) ([]byte, error) {
		session, err := credential.LoadUserSession(dir)
		if err != nil {
			return nil, errors.New("cannot load login session; run xconnect accelerate login")
		}
		nodeKey, err := accelerate.LoadSelection(dir, session)
		if err != nil {
			return nil, err
		}
		return accelerate.Profile(ctx, client, session, nodeKey)
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

func joinAcceleration(ctx context.Context, client *http.Client, dir, selector string, input io.Reader, output io.Writer, interactive bool) error {
	session, err := credential.LoadUserSession(dir)
	if err != nil {
		return errors.New("cannot load login session; run xconnect accelerate login")
	}
	nodes, err := accelerate.Nodes(ctx, client, session)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return errors.New("no authorized VLESS/TLS acceleration nodes")
	}
	exact := false
	if selector == "" {
		for i, node := range nodes {
			fmt.Fprintf(output, "%d. %q (ID: %q)\n", i+1, node.Name, node.Key)
		}
		if !interactive {
			return errors.New("select a node with xconnect accelerate join --node <ID>")
		}
		fmt.Fprint(output, "Select node number: ")
		line, err := readLine(input)
		number, parseErr := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || parseErr != nil || number < 1 || number > len(nodes) {
			return errors.New("invalid acceleration node number")
		}
		selector, exact = nodes[number-1].Key, true
	}
	selected, err := accelerate.Select(nodes, selector, exact)
	if err != nil {
		return err
	}
	if err := accelerate.SaveSelection(dir, session, selected); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintf(output, "Selected acceleration node %q. Next: run xconnect accelerate up as Administrator.\n", selected.Name)
	} else {
		fmt.Fprintf(output, "Selected acceleration node %q. Next: sudo xconnect accelerate up.\n", selected.Name)
	}
	return nil
}
