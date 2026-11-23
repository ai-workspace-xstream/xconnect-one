// Modified for XConnect-One: standalone module imports.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/invite"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime/embedded"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

const (
	defaultAccountsServer = "https://accounts.svc.plus"
	defaultKnownGateway   = "https://ph-xconnect-gateway-01.svc.plus"
	// defaultConsoleBindingURL is where a logged-in user binds/authorizes a
	// gateway network (e.g. net-ph-xconnect) to their account.
	defaultConsoleBindingURL = "https://console.svc.plus/panel/xconnect-zero"
	defaultVersion           = "v0.1.22"
	defaultBuildNumber       = "28"
)

type exitStatusError int

func (e exitStatusError) Error() string {
	return fmt.Sprintf("exit status %d", int(e))
}

var (
	version     = defaultVersion
	buildNumber = defaultBuildNumber
	gitCommit   = "dev"
	buildDate   = ""
)

type runtimeFactory func(stateDirectory string) overlayruntime.Interface
type credentialFactory func(stateDirectory string) credential.Store

func main() {
	ctx, stop := notifyShutdownContext(context.Background())
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, controlplane.NewDefaultHTTPClient()); err != nil {
		var exitErr exitStatusError
		if errors.As(err, &exitErr) {
			os.Exit(int(exitErr))
		}
		fmt.Fprintf(os.Stderr, "error[%s]: %s\n", fault.Code(err), formatFaultError(err))
		os.Exit(1)
	}
}

func formatFaultError(err error) string {
	var faultErr *fault.Error
	if !errors.As(err, &faultErr) {
		return err.Error()
	}
	var ops []string
	for cur := error(faultErr); cur != nil; {
		var fe *fault.Error
		if !errors.As(cur, &fe) {
			break
		}
		raw := fe.Error()
		codeSuffix := ": " + fe.Code()
		op := strings.TrimSuffix(raw, codeSuffix)
		if op != "" && (len(ops) == 0 || ops[len(ops)-1] != op) {
			ops = append(ops, op)
		}
		cur = errors.Unwrap(fe)
	}
	if len(ops) == 0 {
		return appendSafeHint(faultErr.Error(), err)
	}
	return appendSafeHint(strings.Join(ops, " -> ")+": "+faultErr.Code(), err)
}

func appendSafeHint(message string, err error) string {
	var hinted interface{ SafeHint() string }
	if !errors.As(err, &hinted) {
		return message
	}
	hint := strings.TrimSpace(hinted.SafeHint())
	if hint == "" || strings.Contains(message, hint) {
		return message
	}
	return message + ": " + hint
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	runtimeMode, remaining, err := extractRuntimeMode(args, os.Getenv("XCONNECT_ONE_RUNTIME"))
	if err != nil {
		return err
	}
	return runWithFactories(ctx, remaining, stdout, stderr, httpClient, func(stateDirectory string) overlayruntime.Interface {
		return platformRuntimeWithMode(runtime.GOOS, stateDirectory, runtimeMode)
	}, credential.NewPlatformStore)
}

func extractRuntimeMode(args []string, envDefault string) (string, []string, error) {
	mode := strings.ToLower(strings.TrimSpace(envDefault))
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--runtime" || arg == "-runtime":
			if i+1 >= len(args) {
				return "", nil, fault.New(fault.CodeInvalidInput, "parse --runtime flag: missing value", nil)
			}
			mode = strings.ToLower(strings.TrimSpace(args[i+1]))
			i++
		case strings.HasPrefix(arg, "--runtime="):
			mode = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--runtime=")))
		case strings.HasPrefix(arg, "-runtime="):
			mode = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "-runtime=")))
		default:
			remaining = append(remaining, arg)
		}
	}
	if mode == "" {
		mode = "embedded"
	}
	switch mode {
	case "embedded", "external":
		_ = os.Setenv("XCONNECT_ONE_RUNTIME", mode)
		return mode, remaining, nil
	default:
		return "", nil, fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid --runtime %q (expected embedded or external)", mode), nil)
	}
}

func platformRuntime(goos, stateDirectory string) overlayruntime.Interface {
	return platformRuntimeWithMode(goos, stateDirectory, "external")
}

func platformRuntimeWithMode(goos, stateDirectory, runtimeMode string) overlayruntime.Interface {
	if strings.EqualFold(strings.TrimSpace(runtimeMode), "embedded") {
		switch goos {
		case "linux", "darwin", "windows":
			return embedded.New(stateDirectory)
		}
	}
	if goos == "linux" {
		return overlayruntime.NewLinuxDesktop(stateDirectory)
	}
	switch goos {
	case "darwin":
		return overlayruntime.NewMacOSDesktop(stateDirectory)
	case "windows":
		return overlayruntime.NewWindowsDesktop(stateDirectory)
	case "ios", "android":
		return overlayruntime.NewProtectedHost("mobile_protected_tunnel_host_required", nil)
	}
	return overlayruntime.NewUnavailable()
}

func runWithRuntimeFactory(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory) error {
	return runWithFactories(ctx, args, stdout, stderr, httpClient, newRuntime, func(string) credential.Store { return &credential.MemoryStore{} })
}

func runWithFactories(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	// Strip out non-positional global flags like --state-dir if passed ahead or trailing
	filteredArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-v" || arg == "-V" || arg == "--version" || arg == "version" {
			return runVersion(args[i+1:], stdout, stderr)
		}
		filteredArgs = append(filteredArgs, arg)
	}

	if len(filteredArgs) == 0 {
		return fault.New(fault.CodeInvalidInput, "expected login, logout, gateway, register, join, sync, up, down, leave, status, diagnose, runtime, credential, admin, policy, or version", nil)
	}
	switch filteredArgs[0] {
	case "version":
		return runVersion(filteredArgs[1:], stdout, stderr)
	case "login":
		return runLogin(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "logout":
		return runLogout(ctx, args[1:], stdout, stderr)
	case "gateway", "gateways":
		return runGateway(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "path-manager":
		return overlayruntime.RunPathManager(ctx, args[1:])
	case "register":
		return runRegister(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "join":
		return runJoin(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "sync":
		return runSync(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "up":
		return runUpWithDependencies(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "down":
		return runDown(ctx, args[1:], stdout, stderr, newRuntime)
	case "leave":
		return runLeave(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr, newRuntime, newCredentials)
	case "diagnose":
		return runDiagnose(ctx, args[1:], stdout, stderr, newRuntime, newCredentials)
	case "runtime":
		return runRuntime(ctx, args[1:], stdout, stderr)
	case "credential":
		return runCredential(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "admin":
		return runAdmin(ctx, args[1:], stdout, stderr, httpClient)
	case "policy":
		return runPolicy(ctx, args[1:], stdout, stderr, httpClient)
	default:
		return fault.New(fault.CodeInvalidInput, "unknown command", nil)
	}
}

func runVersion(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("xconnect version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	short := flags.Bool("short", false, "print only the version string")
	if err := flags.Parse(args); err != nil {
		return fault.New(fault.CodeInvalidInput, "parse version arguments", err)
	}
	if *short {
		if gitCommit != "" && gitCommit != "dev" {
			fmt.Fprintf(stdout, "%s+%s\n", version, gitCommit)
		} else {
			fmt.Fprintln(stdout, version)
		}
		return nil
	}
	if gitCommit != "" && gitCommit != "dev" {
		fmt.Fprintf(stdout, "xconnect-one %s (build %s, %s, %s/%s)\n", version, buildNumber, gitCommit, runtime.GOOS, runtime.GOARCH)
	} else {
		fmt.Fprintf(stdout, "xconnect-one %s (build %s, %s/%s)\n", version, buildNumber, runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

func runRegister(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect register", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controller := flags.String("controller", "", "HTTPS accounts controller base URL")
	networkID := flags.String("network", "", "public overlay network ID")
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	deviceID := flags.String("device-id", "", "stable local device ID")
	regenerateDeviceID := flags.Bool("regenerate-device-id", false, "regenerate a brand-new global device ID and persist it to /etc/xconnect-one/device-id")
	deviceName := flags.String("name", "", "device display name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse register arguments", err)
	}
	if strings.TrimSpace(*controller) == "" || strings.TrimSpace(*networkID) == "" {
		return fault.New(fault.CodeInvalidInput, "register requires controller and network", nil)
	}
	client, err := controlplane.New(*controller, "", httpClient)
	if err != nil {
		return err
	}
	explicitFlags := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})
	*stateDirectory = expandUserPath(*stateDirectory)
	if *regenerateDeviceID {
		newID, regenErr := RegenerateDeviceID(*stateDirectory)
		if regenErr != nil {
			return regenErr
		}
		*deviceID = newID
	} else {
		*deviceID = resolveOrCreateDeviceID(*stateDirectory, *deviceID, explicitFlags["device-id"])
	}
	hostname, _ := os.Hostname()
	store := state.NewStore(*stateDirectory)
	registrar := usecase.NewRegistrar(client, store, newCredentials(*stateDirectory), newRuntime(*stateDirectory)).WithProgress(func(progress usecase.RegistrationProgress) {
		_, _ = fmt.Fprintf(stderr, "xconnect: registration %s; registration_id=%s device_id=%s network_id=%s expires_at=%s wireguard_public_key_fingerprint=%s; approve this device in Zero\n", progress.Status, progress.RegistrationID, progress.DeviceID, progress.NetworkID, progress.ExpiresAt.UTC().Format(time.RFC3339), progress.WireGuardPublicKeyFingerprint)
	})
	result, err := registrar.Register(ctx, usecase.RegisterRequest{
		Controller: *controller, DeviceID: *deviceID, DeviceName: *deviceName, NetworkID: *networkID, Platform: runtime.GOOS, Hostname: hostname,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runJoin(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	args = moveLeadingJoinTargetAfterFlags(args)
	flags := flag.NewFlagSet("xconnect join", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	gatewayTarget := flags.String("gateway", "", "preferred gateway ID, endpoint host, or URL (e.g. "+defaultKnownGateway+")")
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	deviceID := flags.String("device-id", "", "stable local device ID")
	regenerateDeviceID := flags.Bool("regenerate-device-id", false, "regenerate a brand-new global device ID and persist it to /etc/xconnect-one/device-id")
	deviceName := flags.String("name", "", "device display name")
	networkID := flags.String("network-id", "", "requested overlay network ID")
	nodeID := flags.String("node-id", "", "preferred gateway node ID")
	configContract := flags.String("config-contract", string(usecase.ConfigContractAuto), "config contract: auto, signed, or legacy")
	bootstrapRuntime := flags.Bool("bootstrap", false, "install or repair the approved managed runtime before joining")
	runtimeReleaseBaseURL := flags.String("runtime-release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	allowInsecureLocalhost := flags.Bool("allow-insecure-localhost", false, "allow HTTP localhost controller for invite development")
	inviteFile := flags.String("invite-file", "", "path to a protected file containing one XConnect join URI")
	tokenFile := flags.String("token-file", "", "path to a file containing the accounts access token")
	consoleURL := flags.String("console-url", defaultConsoleBindingURL, "console page used to bind/authorize a gateway network to the logged-in account")
	noBrowser := flags.Bool("no-browser", false, "print the console binding URL instead of opening a browser")
	waitFor := flags.Duration("wait", 10*time.Minute, "how long to wait for the console binding to complete (0 = do not wait)")
	pollInterval := flags.Duration("poll-interval", 5*time.Second, "how often to re-check gateway authorization while waiting")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse join arguments", err)
	}
	if flags.NArg() > 1 {
		return fault.New(fault.CodeInvalidInput, "parse join target", nil)
	}
	targetValue := ""
	if flags.NArg() == 1 {
		targetValue = flags.Arg(0)
	}
	if strings.TrimSpace(*inviteFile) != "" {
		if targetValue != "" {
			return fault.New(fault.CodeInvalidInput, "join accepts either an invite argument or --invite-file", nil)
		}
		var err error
		targetValue, err = readJoinInvite(*inviteFile)
		if err != nil {
			return err
		}
	}

	explicitFlags := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})
	*stateDirectory = expandUserPath(*stateDirectory)
	if *regenerateDeviceID {
		newID, regenErr := RegenerateDeviceID(*stateDirectory)
		if regenErr != nil {
			return regenErr
		}
		*deviceID = newID
	} else {
		*deviceID = resolveOrCreateDeviceID(*stateDirectory, *deviceID, explicitFlags["device-id"])
	}
	if targetValue == "" && strings.TrimSpace(*tokenFile) == "" {
		session, sessErr := credential.LoadUserSession(*stateDirectory)
		if sessErr != nil && !errors.Is(sessErr, credential.ErrNotFound) {
			return sessErr
		}
		if sessErr == nil && strings.TrimSpace(session.AccessToken) != "" {
			return runJoinWithSession(ctx, session, sessionJoinOptions{
				StateDirectory: *stateDirectory,
				DeviceID:       *deviceID,
				DeviceName:     *deviceName,
				Gateway:        *gatewayTarget,
				NetworkID:      *networkID,
				ConsoleURL:     *consoleURL,
				OpenBrowser:    !*noBrowser,
				Wait:           *waitFor,
				PollInterval:   *pollInterval,
			}, os.Stdin, stdout, stderr, httpClient, newCredentials)
		}
		if errors.Is(sessErr, credential.ErrNotFound) {
			return fault.New(fault.CodeAuthenticationFailed, "not logged in: run 'xconnect-one login' first, then 'xconnect-one join' (or pass an invite: xconnect-one join 'xconnect://join/...')", nil)
		}
	}
	target, err := resolveJoinTarget(targetValue, *server, *allowInsecureLocalhost)
	if err != nil {
		return err
	}
	if *bootstrapRuntime {
		if _, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
			StateDirectory:        *stateDirectory,
			ReleaseBaseURL:        *runtimeReleaseBaseURL,
			InstallSystemPackages: true,
		}); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "xconnect: managed runtime ready")
	}
	if *networkID == "" {
		*networkID = target.NetworkID
	}
	if *nodeID == "" {
		*nodeID = target.NodeID
	}
	token := ""
	if target.JoinToken == "" {
		token, err = readToken(*tokenFile)
		if err != nil {
			return err
		}
	}
	contract, err := usecase.ParseConfigContract(*configContract)
	if err != nil {
		return err
	}
	if target.JoinToken != "" {
		if contract == usecase.ConfigContractLegacy {
			return fault.New(fault.CodeConfigDowngradeBlocked, "join invite requires signed config", nil)
		}
		contract = usecase.ConfigContractSigned
	}
	client, err := controlplane.New(target.Controller, token, httpClient)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	store := state.NewStore(*stateDirectory)
	operation, err := store.AcquireOperation(ctx, "join")
	if err != nil {
		return err
	}
	defer operation.Release()
	tunnelRuntime := newRuntime(*stateDirectory)
	result, err := usecase.NewJoiner(client, store, tunnelRuntime).WithCredentialStore(newCredentials(*stateDirectory)).WithConfigContract(contract).Join(ctx, usecase.JoinRequest{
		Server:     target.Controller,
		DeviceID:   *deviceID,
		DeviceName: *deviceName,
		Platform:   runtime.GOOS,
		Hostname:   hostname,
		NetworkID:  *networkID,
		NodeID:     *nodeID,
		JoinToken:  target.JoinToken,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runSync(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect sync", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	signedConfigV2 := flags.Bool("signed-config-v2", false, "request the policy-bound SignedConfig v2 contract")
	bootstrapRuntime := flags.Bool("bootstrap", false, "install or repair the approved managed runtime before synchronizing")
	runtimeReleaseBaseURL := flags.String("runtime-release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	watch := flags.Bool("watch", false, "run sync periodically in a watch loop")
	foreground := flags.Bool("foreground", false, "run in foreground daemon mode with auto-recovery and graceful cleanup on SIGINT/SIGTERM (implies --watch)")
	processMode := flags.String("process-mode", os.Getenv("XCONNECT_LINUX_PROCESS_MODE"), "Linux process supervision mode: auto, systemd, or direct")
	interval := flags.Duration("interval", usecase.DefaultSyncInterval, "sync interval for watch loop (15s to 100s)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse sync arguments", err)
	}
	if flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse sync arguments", nil)
	}
	if _, err := normalizeProcessMode(*processMode); err != nil {
		return err
	}
	if *foreground {
		*watch = true
	}
	if *watch {
		if err := usecase.ValidateSyncInterval(*interval); err != nil {
			return err
		}
	}
	credentials := newCredentials(*stateDirectory)
	record, err := credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return fault.New(fault.CodeCredentialMissing, "load device credential for sync", nil)
	}
	if err != nil {
		return err
	}
	if *bootstrapRuntime {
		if _, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
			StateDirectory:        *stateDirectory,
			ReleaseBaseURL:        *runtimeReleaseBaseURL,
			InstallSystemPackages: true,
		}); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "xconnect: managed runtime ready")
	}
	client, err := controlplane.New(record.Controller, "", httpClient)
	if err != nil {
		return err
	}
	stStore := state.NewStore(*stateDirectory)
	runtimeInstance := newRuntime(*stateDirectory)
	manager := usecase.NewDeviceSessionManager(client, stStore, credentials, runtimeInstance)
	if *signedConfigV2 {
		manager.WithSignedConfigV2()
	}
	if *watch {
		if firstResult, err := manager.Sync(ctx); err != nil {
			if fault.Code(err) == fault.CodeAuthenticationFailed || fault.Code(err) == fault.CodeAccessDenied || fault.Code(err) == fault.CodeCredentialExpired || fault.Code(err) == fault.CodeCredentialMissing || fault.Code(err) == fault.CodeNotJoined {
				return err
			}
			_, _ = fmt.Fprintf(stderr, "xconnect: initial sync warning: %v\n", err)
		} else {
			_ = writeJSON(stdout, firstResult)
		}
		return runSupervisedSyncLoop(ctx, client, stStore, runtimeInstance, manager.Sync, *interval, *foreground, stdout, stderr)
	}
	result, err := manager.Sync(ctx)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func normalizeProcessMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", "auto", "systemd", "direct":
		if mode != "" {
			_ = os.Setenv("XCONNECT_LINUX_PROCESS_MODE", mode)
		}
		return mode, nil
	default:
		return "", fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid --process-mode %q (expected auto, systemd, or direct)", raw), nil)
	}
}

func resolveManagedInterfaceName(store *state.Store) string {
	if store == nil {
		return ""
	}
	lk, err := store.LoadLastKnown()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(lk.Config.WireGuard.Interface)
}

func policyExpiryFunc(store *state.Store) func() (time.Time, bool) {
	return func() (time.Time, bool) {
		if store == nil {
			return time.Time{}, false
		}
		ps, err := store.LoadPolicyState()
		if err != nil || ps.ExpiresAt.IsZero() {
			return time.Time{}, false
		}
		return ps.ExpiresAt, true
	}
}

func runSupervisedSyncLoop(
	ctx context.Context,
	client *controlplane.Client,
	store *state.Store,
	runtimeInstance overlayruntime.Interface,
	syncFn func(context.Context) (usecase.SyncResult, error),
	interval time.Duration,
	foreground bool,
	stdout, stderr io.Writer,
) error {
	netMon := overlayruntime.NewNetworkMonitor(resolveManagedInterfaceName(store))
	events := netMon.Start(ctx)
	loop := &usecase.SyncLoop{
		Interval:            interval,
		Runtime:             runtimeInstance,
		Sync:                syncFn,
		Events:              events,
		HealthCheckInterval: 5 * time.Second,
		PolicyExpiry:        policyExpiryFunc(store),
		ShutdownOnCancel:    foreground,
		OnNetworkEvent: func(ev overlayruntime.NetworkEvent) {
			client.CloseIdleConnections()
			_, _ = fmt.Fprintf(stderr, "xconnect: host event (%s); refreshing transport and control plane\n", ev.Kind)
		},
		OnRecovery: func(level, reason string) {
			_, _ = fmt.Fprintf(stderr, "xconnect: recovery (%s): %s\n", level, reason)
		},
		OnResult: func(res usecase.SyncResult) {
			_ = writeJSON(stdout, res)
		},
		OnError: func(err error) {
			_, _ = fmt.Fprintf(stderr, "xconnect: sync warning: %v\n", err)
		},
	}
	return loop.Run(ctx)
}

func runUp(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory) error {
	flags := flag.NewFlagSet("xconnect up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse up arguments", err)
	}
	result, err := usecase.Up(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runDown(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory) error {
	defaultStateDir, primaryStateDir, fallbackReason := resolveDefaultStateDirectory()
	flags := flag.NewFlagSet("xconnect down", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDir, "local XConnect-One state directory")
	logout := flags.Bool("logout", false, "also clear local user login session after stopping the tunnel")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse down arguments", err)
	}
	explicitStateDir := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "state-dir" {
			explicitStateDir = true
		}
	})
	*stateDirectory = expandUserPath(*stateDirectory)
	if !explicitStateDir && fallbackReason != "" {
		fmt.Fprintf(stderr, "Note: default state directory %q is %s; using %q (or pass --state-dir)\n", primaryStateDir, fallbackReason, *stateDirectory)
	}
	result, err := usecase.Down(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory))
	if err == nil {
		var stoppedDaemon bool
		stoppedDaemon, err = stopRecordedDaemon(*stateDirectory)
		if stoppedDaemon {
			result.AlreadyInState = false
		}
	}
	if err != nil {
		if fault.Code(err) == fault.CodeRuntimePermission {
			if canAutoElevateWithSudo() {
				_, _ = fmt.Fprintln(stderr, "xconnect: administrator privileges required to stop network interface; requesting sudo...")
				return execSudoSelf(ctx, "down", *stateDirectory, args)
			}
			_, _ = fmt.Fprintf(stderr, "xconnect: root/administrator privileges required to stop network interface.\n")
			_, _ = fmt.Fprintf(stderr, "Run: sudo xconnect-one down --state-dir %s\n", *stateDirectory)
		}
		return err
	}
	if *logout {
		if delErr := credential.DeleteUserSession(*stateDirectory); delErr != nil {
			return delErr
		}
	}
	return writeJSON(stdout, result)
}

func runLeave(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect leave", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	localOnly := flags.Bool("local-only", false, "remove only local XConnect-owned state without server revocation")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse leave arguments", err)
	}
	credentials := newCredentials(*stateDirectory)
	var client *controlplane.Client
	var err error
	if !*localOnly {
		record, loadErr := credentials.Load(ctx)
		if loadErr == nil {
			client, err = controlplane.New(record.Controller, "", httpClient)
			if err != nil {
				return err
			}
		} else if !errors.Is(loadErr, credential.ErrNotFound) {
			return loadErr
		}
	}
	result, err := usecase.LeaveWithDeviceCredential(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory), credentials, client, *localOnly)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runCredential(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	if len(args) > 0 && args[0] == "migrate-to-protected" {
		flags := flag.NewFlagSet("xconnect credential migrate-to-protected", flag.ContinueOnError)
		flags.SetOutput(stderr)
		stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return fault.New(fault.CodeInvalidInput, "parse protected credential migration arguments", err)
		}
		record, err := newCredentials(*stateDirectory).Load(ctx)
		if err != nil {
			return fault.New(fault.CodeCredentialStorage, "read existing protected device credential", err)
		}
		if os.Geteuid() != 0 {
			return fault.New(fault.CodeRuntimePermission, "write root protected device credential", nil)
		}
		if err := credential.SaveProtectedRecord(ctx, *stateDirectory, record); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"migrated": true, "backend": "root-protected-file", "device_id": record.DeviceID})
	}
	if len(args) == 0 || args[0] != "rotate" {
		return fault.New(fault.CodeInvalidInput, "expected credential rotate or migrate-to-protected", nil)
	}
	flags := flag.NewFlagSet("xconnect credential rotate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse credential rotate arguments", err)
	}
	credentials := newCredentials(*stateDirectory)
	record, err := credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return fault.New(fault.CodeCredentialMissing, "load device credential for rotation", nil)
	}
	if err != nil {
		return err
	}
	client, err := controlplane.New(record.Controller, "", httpClient)
	if err != nil {
		return err
	}
	result, err := usecase.NewDeviceSessionManager(client, state.NewStore(*stateDirectory), credentials, newRuntime(*stateDirectory)).Rotate(ctx)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runAdmin(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	if len(args) < 2 || args[0] != "invite" || args[1] != "create" {
		return fault.New(fault.CodeInvalidInput, "expected admin invite create", nil)
	}
	flags := flag.NewFlagSet("xconnect admin invite create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	tokenFile := flags.String("token-file", "", "path to a file containing the accounts access token")
	networkID := flags.String("network-id", "", "overlay network ID")
	deviceID := flags.String("device-id", "", "optional constrained device ID")
	platform := flags.String("platform", "", "optional constrained platform")
	expiresIn := flags.Int64("expires-in", 900, "one-time invite lifetime in seconds")
	output := flags.String("output", "json", "output format: json or uri")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse invite create arguments", err)
	}
	if *output != "json" && *output != "uri" {
		return fault.New(fault.CodeInvalidInput, "select invite output", nil)
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	client, err := controlplane.New(*server, token, httpClient)
	if err != nil {
		return err
	}
	response, err := client.CreateJoinToken(ctx, controlplane.CreateJoinTokenRequest{NetworkID: *networkID, DeviceID: *deviceID, Platform: *platform, ExpiresInSeconds: *expiresIn})
	if err != nil {
		return err
	}
	if *output == "uri" {
		_, err = fmt.Fprintln(stdout, response.JoinToken.JoinURI)
		return err
	}
	return writeJSON(stdout, response)
}

func runPolicy(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	if len(args) < 1 || args[0] != "explain" {
		return fault.New(fault.CodeInvalidInput, "expected policy explain", nil)
	}
	flags := flag.NewFlagSet("xconnect policy explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	tokenFile := flags.String("token-file", "", "path to a file containing the accounts access token")
	networkID := flags.String("network-id", "", "overlay network ID")
	revision := flags.Uint64("revision", 0, "policy revision")
	source := flags.String("source", "", "source selector")
	destination := flags.String("destination", "", "destination selector")
	protocol := flags.String("protocol", "", "tcp, udp, or icmp")
	port := flags.Int("port", 0, "destination port; zero only for ICMP")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse policy explain arguments", err)
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	client, err := controlplane.New(*server, token, httpClient)
	if err != nil {
		return err
	}
	result, err := client.ExplainPolicy(ctx, *revision, controlplane.PolicyExplainRequest{NetworkID: *networkID, Source: *source, Destination: *destination, Protocol: *protocol, Port: *port})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func moveLeadingJoinTargetAfterFlags(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	reordered := append([]string(nil), args[1:]...)
	return append(reordered, args[0])
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse status arguments", err)
	}
	store := state.NewStore(*stateDirectory)
	result, err := usecase.StatusWithCredential(ctx, store, newRuntime(*stateDirectory), newCredentials(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runDiagnose(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect diagnose", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse diagnose arguments", err)
	}
	store := state.NewStore(*stateDirectory)
	result, err := usecase.DiagnoseWithCredential(ctx, store, newRuntime(*stateDirectory), newCredentials(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runRuntime(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "bootstrap" {
		return fault.New(fault.CodeInvalidInput, "expected runtime bootstrap", nil)
	}
	flags := flag.NewFlagSet("xconnect runtime bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	releaseBaseURL := flags.String("release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	installSystemPackages := flags.Bool("install-system-packages", true, "install required WireGuard packages using the supported platform package manager")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse runtime bootstrap arguments", err)
	}
	result, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
		StateDirectory:        *stateDirectory,
		ReleaseBaseURL:        *releaseBaseURL,
		InstallSystemPackages: *installSystemPackages,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return strings.TrimSpace(os.Getenv("XCONNECT_TOKEN")), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fault.New(fault.CodeAuthenticationFailed, "read access token", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return "", fault.New(fault.CodeAuthenticationFailed, "read access token", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// readJoinInvite keeps a short-lived join URI out of the process argument
// list. Deployment automation creates this file with 0600 permissions and
// removes it immediately after a successful exchange.
func readJoinInvite(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fault.New(fault.CodeJoinInviteInvalid, "read join invite", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16<<10))
	if err != nil {
		return "", fault.New(fault.CodeJoinInviteInvalid, "read join invite", err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fault.New(fault.CodeJoinInviteInvalid, "read join invite", nil)
	}
	return value, nil
}

type joinTarget struct {
	Controller string
	NetworkID  string
	NodeID     string
	JoinToken  string
}

func resolveJoinTarget(value, fallbackController string, allowInsecureLocalhost bool) (joinTarget, error) {
	if strings.HasPrefix(value, "xconnect:") {
		target, err := invite.Parse(value, allowInsecureLocalhost)
		if err != nil {
			return joinTarget{}, err
		}
		return joinTarget{Controller: target.Controller, JoinToken: target.JoinToken}, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return joinTarget{Controller: strings.TrimRight(strings.TrimSpace(fallbackController), "/")}, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse join target", err)
	}
	query := parsed.Query()
	for _, sensitiveKey := range []string{"token", "access_token", "refresh_token", "private_key"} {
		if query.Has(sensitiveKey) {
			return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse invite URL", nil)
		}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse join target", nil)
	}
	if parsed.RawQuery != "" {
		return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse join target", nil)
	}
	return joinTarget{Controller: strings.TrimRight(value, "/")}, nil
}

func defaultStateDirectory() string {
	selected, _, _ := resolveDefaultStateDirectory()
	return selected
}

func resolveDefaultStateDirectory() (selected, primary, fallbackReason string) {
	home, err := os.UserHomeDir()
	sudoUID, sudoHome, hasSudo := credential.ResolveSudoInvoker()
	if hasSudo && sudoHome != "" {
		if err != nil || strings.TrimSpace(home) == "" || home == "/root" || home == "/var/root" {
			home = sudoHome
			err = nil
		}
	}
	return resolveDefaultStateDirectoryFor(os.Geteuid(), home, err, sudoUID, hasSudo)
}

func resolveDefaultStateDirectoryFor(euid int, home string, homeErr error, sudoUID uint32, hasSudo bool) (selected, primary, fallbackReason string) {
	if homeErr != nil || strings.TrimSpace(home) == "" {
		return ".xconnect-one", ".xconnect-one", ""
	}
	primary = filepath.Join(home, ".xconnect-one")
	candidates := []string{
		filepath.Join(home, ".xconnect-one-user"),
		filepath.Join(home, ".config", "xconnect-one"),
		filepath.Join(os.TempDir(), fmt.Sprintf("xconnect-one-%d", effectiveUIDForState(euid, sudoUID, hasSudo))),
	}
	if euid == 0 {
		if !hasSudo || sudoUID == 0 {
			return primary, primary, ""
		}
		reason := credential.CheckStateDirectoryUsabilityForUID(primary, sudoUID)
		if reason == "" {
			return primary, primary, ""
		}
		for _, candidate := range candidates {
			if credential.CheckStateDirectoryUsabilityForUID(candidate, sudoUID) == "" {
				return candidate, primary, reason
			}
		}
		return primary, primary, reason
	}
	reason := credential.CheckStateDirectoryUsability(primary)
	if reason == "" {
		return primary, primary, ""
	}
	for _, candidate := range candidates {
		if credential.CheckStateDirectoryUsability(candidate) == "" {
			return candidate, primary, reason
		}
	}
	return primary, primary, reason
}

func effectiveUIDForState(euid int, sudoUID uint32, hasSudo bool) int {
	if euid == 0 && hasSudo && sudoUID > 0 {
		return int(sudoUID)
	}
	return euid
}

func expandUserPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "~" || strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if trimmed == "~" {
				return home
			}
			return filepath.Join(home, trimmed[2:])
		}
	}
	return trimmed
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fault.New(fault.CodeInvalidResponse, "write command output", err)
	}
	return nil
}
