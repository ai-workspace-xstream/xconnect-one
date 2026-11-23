package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime/embedded"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

func TestHelperDaemonProcess(t *testing.T) {
	if os.Getenv("GO_WANT_DAEMON_HELPER") != "1" {
		return
	}

	// Find arguments after "--".
	var cmdArgs []string
	for i, arg := range os.Args {
		if arg == "--" && i+1 <= len(os.Args) {
			cmdArgs = os.Args[i+1:]
			break
		}
	}

	mode := os.Getenv("GO_DAEMON_HELPER_MODE")
	if mode == "" {
		mode = "ready"
	}

	if mode == "fail_early" {
		for i := 1; i <= 20; i++ {
			fmt.Fprintf(os.Stderr, "line-%02d: diagnostic message\n", i)
		}
		fmt.Fprintln(os.Stderr, "line-21: fatal auth check failed")
		os.Exit(1)
	}

	if os.Getenv(daemonChildEnvVar) != "1" {
		fmt.Fprintf(os.Stderr, "missing %s=1\n", daemonChildEnvVar)
		os.Exit(2)
	}

	var stateDir string
	hasForeground := false
	hasNoSudo := false
	for i := 0; i < len(cmdArgs); i++ {
		switch cmdArgs[i] {
		case "--state-dir":
			if i+1 < len(cmdArgs) {
				stateDir = cmdArgs[i+1]
				i++
			}
		case "--foreground":
			hasForeground = true
		case "--no-sudo":
			hasNoSudo = true
		case "-D", "--daemon", "-daemon", "--log-file", "-log-file", "--gateway", "-gateway":
			fmt.Fprintf(os.Stderr, "unexpected stripped flag %q in args: %v\n", cmdArgs[i], cmdArgs)
			os.Exit(3)
		}
	}
	if !hasForeground || !hasNoSudo || stateDir == "" {
		fmt.Fprintf(os.Stderr, "missing expected child args in %v\n", cmdArgs)
		os.Exit(4)
	}
	if expectArg := os.Getenv("GO_DAEMON_EXPECT_ARG"); expectArg != "" && !slices.Contains(cmdArgs, expectArg) {
		fmt.Fprintf(os.Stderr, "expected arg %q not found in %v\n", expectArg, cmdArgs)
		os.Exit(5)
	}

	if mode == "ready" {
		readyFile := os.Getenv(daemonReadyFileEnv)
		if readyFile == "" {
			fmt.Fprintf(os.Stderr, "missing %s\n", daemonReadyFileEnv)
			os.Exit(6)
		}
		fmt.Fprintln(os.Stdout, "daemon child ready")
		if err := writeDaemonReadyFile(readyFile, daemonReadyPayload{
			Ready: true,
			Sync: &usecase.SyncResult{
				DeviceID:   "dev-helper",
				NetworkID:  "net-helper",
				Revision:   "rev-helper",
				Generation: 7,
			},
		}); err != nil {
			fmt.Fprintf(os.Stderr, "write ready file: %v\n", err)
			os.Exit(7)
		}
	}

	ctx, stop := notifyShutdownContext(context.Background())
	defer stop()
	<-ctx.Done()
	_ = removeDaemonPIDIfSelf(stateDir)
	os.Exit(0)
}

func TestStripDaemonFlags(t *testing.T) {
	in := []string{
		"-D",
		"--daemon",
		"-daemon",
		"--daemon=true",
		"-D=true",
		"--log-file", "/tmp/xconnect.log",
		"-log-file", "/tmp/xconnect2.log",
		"--log-file=/tmp/xconnect3.log",
		"-log-file=/tmp/xconnect4.log",
		"--gateway", "gw-1",
		"-gateway", "gw-2",
		"--gateway=gw-3",
		"-gateway=gw-4",
		"--state-dir", "/tmp/state1",
		"-state-dir", "/tmp/state2",
		"--state-dir=/tmp/state3",
		"-state-dir=/tmp/state4",
		"--no-sudo",
		"-no-sudo",
		"--foreground",
		"-foreground",
		"--interval", "30s",
		"--process-mode=direct",
		"--bootstrap",
		"--runtime-release-base-url", "https://mirror.example",
		"--device-id", "dev-1",
		"--name", "macbook",
	}
	want := []string{
		"--interval", "30s",
		"--process-mode=direct",
		"--bootstrap",
		"--runtime-release-base-url", "https://mirror.example",
		"--device-id", "dev-1",
		"--name", "macbook",
	}
	got := stripDaemonFlags(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stripDaemonFlags:\n got: %v\nwant: %v", got, want)
	}
}

func TestDaemonPIDHelpers(t *testing.T) {
	stateDir := t.TempDir()
	wantPath := filepath.Join(stateDir, "runtime", "daemon.pid")
	if got := daemonPIDPath(stateDir); got != wantPath {
		t.Fatalf("daemonPIDPath=%q, want %q", got, wantPath)
	}

	if _, err := readDaemonPID(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist for missing pid file, got %v", err)
	}

	selfPID := os.Getpid()
	otherPID := selfPID + 100000
	if err := writeDaemonPID(stateDir, otherPID); err != nil {
		t.Fatalf("writeDaemonPID(other): %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(wantPath)
		if err != nil {
			t.Fatalf("stat daemon.pid: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("daemon.pid perm=%04o, want 0600", perm)
		}
	}
	if got, err := readDaemonPID(stateDir); err != nil || got != otherPID {
		t.Fatalf("readDaemonPID=%d err=%v, want %d", got, err, otherPID)
	}

	// Must not remove PID belonging to another process.
	if err := removeDaemonPIDIfSelf(stateDir); err != nil {
		t.Fatalf("removeDaemonPIDIfSelf(other): %v", err)
	}
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected daemon.pid to remain when owned by another pid: %v", err)
	}

	// Must remove PID matching os.Getpid().
	if err := writeDaemonPID(stateDir, selfPID); err != nil {
		t.Fatalf("writeDaemonPID(self): %v", err)
	}
	if err := removeDaemonPIDIfSelf(stateDir); err != nil {
		t.Fatalf("removeDaemonPIDIfSelf(self): %v", err)
	}
	if _, err := os.Stat(wantPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected daemon.pid removed for self pid, stat err=%v", err)
	}
	if err := removeDaemonPID(stateDir); err != nil {
		t.Fatalf("removeDaemonPID idempotent: %v", err)
	}
}

func TestUpDaemonFlagsValidationHelpAndHook(t *testing.T) {
	// 1. --help exposes -D, -daemon, -log-file
	{
		var stdout, stderr bytes.Buffer
		err := runWithFactories(t.Context(), []string{"up", "--help"}, &stdout, &stderr, http.DefaultClient,
			func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
			func(string) credential.Store { return &credential.MemoryStore{} },
		)
		if err != nil {
			t.Fatalf("up --help failed: %v", err)
		}
		for _, flagName := range []string{"-D", "-daemon", "-log-file"} {
			if !strings.Contains(stderr.String(), flagName) {
				t.Fatalf("up --help missing %q: %s", flagName, stderr.String())
			}
		}
	}

	// 2. Reject -D/--daemon combined with --foreground
	for _, flag := range []string{"-D", "--daemon"} {
		var stdout, stderr bytes.Buffer
		err := runWithFactories(t.Context(), []string{"up", flag, "--foreground", "--state-dir", t.TempDir()}, &stdout, &stderr, http.DefaultClient,
			func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
			func(string) credential.Store { return &credential.MemoryStore{} },
		)
		if fault.Code(err) != fault.CodeInvalidInput {
			t.Fatalf("expected CodeInvalidInput for %s --foreground, got code=%q err=%v", flag, fault.Code(err), err)
		}
	}

	// 3. Hook invocation for -D and --daemon --log-file
	stateDir, creds, _ := seedTestDeviceCredential(t)
	origStart := startDaemonProcessFunc
	t.Cleanup(func() { startDaemonProcessFunc = origStart })

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "short -D", args: []string{"up", "-D", "--state-dir", stateDir}},
		{name: "long --daemon with --log-file", args: []string{"up", "--daemon", "--log-file", filepath.Join(stateDir, "custom.log"), "--interval", "30s", "--state-dir", stateDir}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XCONNECT_ONE_RUNTIME", "external")
			var captured daemonUpOptions
			startDaemonProcessFunc = func(_ context.Context, opts daemonUpOptions) (daemonStartResult, error) {
				captured = opts
				logOut := opts.LogFile
				if logOut == "" {
					logOut = defaultDaemonLogPath(opts.StateDir)
				}
				return daemonStartResult{
					Daemon:      true,
					Ready:       true,
					PID:         4242,
					StateDir:    opts.StateDir,
					LogFile:     logOut,
					RuntimeMode: opts.RuntimeMode,
					Sync:        &usecase.SyncResult{DeviceID: "dev_cli", NetworkID: "net_private", Revision: "rev-1", Generation: 1},
				}, nil
			}

			var stdout, stderr bytes.Buffer
			err := runWithFactories(t.Context(), tc.args, &stdout, &stderr, http.DefaultClient,
				func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
				func(string) credential.Store { return creds },
			)
			if err != nil {
				t.Fatalf("runWithFactories(%v) failed: %v stderr=%s", tc.args, err, stderr.String())
			}
			if captured.StateDir != stateDir || captured.RuntimeMode != "external" {
				t.Fatalf("unexpected captured opts: %+v", captured)
			}
			var got daemonStartResult
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("decode daemonStartResult JSON: %v (stdout=%s)", err, stdout.String())
			}
			if !got.Daemon || !got.Ready || got.PID != 4242 || got.StateDir != stateDir {
				t.Fatalf("unexpected daemonStartResult: %+v", got)
			}
			if !strings.Contains(stderr.String(), "running in background (pid=4242") {
				t.Fatalf("expected stderr hint, got: %s", stderr.String())
			}
		})
	}
}

func TestUpDaemonEmbeddedRequiresRootBeforeDetaching(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires non-root POSIX process")
	}
	stateDir, creds, _ := seedTestDeviceCredential(t)

	origStart := startDaemonProcessFunc
	origIsTerminal := isTerminalFD
	origExecSudo := execSudoCommand
	t.Cleanup(func() {
		startDaemonProcessFunc = origStart
		isTerminalFD = origIsTerminal
		execSudoCommand = origExecSudo
	})

	hookCalled := false
	startDaemonProcessFunc = func(context.Context, daemonUpOptions) (daemonStartResult, error) {
		hookCalled = true
		return daemonStartResult{}, nil
	}

	// Case 1: --no-sudo fails closed with CodeRuntimePermission before spawning daemon.
	var stdout, stderr bytes.Buffer
	err := runWithFactories(t.Context(), []string{"up", "-D", "--no-sudo", "--state-dir", stateDir}, &stdout, &stderr, http.DefaultClient,
		func(dir string) overlayruntime.Interface { return embedded.New(dir) },
		func(string) credential.Store { return creds },
	)
	if fault.Code(err) != fault.CodeRuntimePermission {
		t.Fatalf("expected CodeRuntimePermission, got code=%q err=%v", fault.Code(err), err)
	}
	if hookCalled {
		t.Fatal("must not call startDaemonProcessFunc without root privileges on embedded runtime")
	}
	if !strings.Contains(stderr.String(), "Run: sudo xconnect-one up --state-dir "+stateDir) {
		t.Fatalf("expected sudo guidance, got stderr=%s", stderr.String())
	}

	// Case 2: Interactive TTY auto-elevates with sudo and preserves -D flag.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	oldStdin := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = pr.Close()
	})
	isTerminalFD = func(fd int) bool { return fd == int(pr.Fd()) }
	t.Setenv("XCONNECT_NO_SUDO", "")

	var recordedSudo []string
	execSudoCommand = func(_ context.Context, args []string) error {
		recordedSudo = append([]string(nil), args...)
		return nil
	}
	stdout.Reset()
	stderr.Reset()
	err = runWithFactories(t.Context(), []string{"up", "-D", "--state-dir", stateDir}, &stdout, &stderr, http.DefaultClient,
		func(dir string) overlayruntime.Interface { return embedded.New(dir) },
		func(string) credential.Store { return creds },
	)
	if err != nil {
		t.Fatalf("expected sudo auto-elevation to succeed, got %v stderr=%s", err, stderr.String())
	}
	if hookCalled {
		t.Fatal("parent process must delegate to sudo instead of spawning unprivileged child")
	}
	if !slices.Contains(recordedSudo, "-D") || !slices.Contains(recordedSudo, stateDir) {
		t.Fatalf("expected sudo args to preserve -D and stateDir, got: %v", recordedSudo)
	}
}

func TestUpDaemonChildWritesReadyFileAndCleansOwnPID(t *testing.T) {
	stateDir, creds, signingPriv := seedTestDeviceCredential(t)
	stateStore := state.NewStore(stateDir)
	if err := stateStore.SaveLastKnown(state.LastKnown{
		Server:              "https://accounts.example",
		DeviceID:            "dev_cli",
		NetworkID:           "net_private",
		WireGuardPrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		WireGuardPublicKey:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Phase:               state.PhaseAcknowledged,
		Config:              cliTestConfig(),
		ConfigContract:      "signed",
		SignedConfigID:      "cfg_cli",
		SignedGeneration:    1,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	policyRaw := []byte(`{"schema_version":1,"compiler_version":"xconnect-acl-v1alpha1.1","network_id":"net_private","revision":7,"default_action":"deny","protected_flows":["control:controller-session","control:gateway-apply-result","control:gateway-heartbeat","control:gateway-policy-artifact","control:gateway-snapshot"],"rules":[]}`)
	sum := sha256.Sum256(policyRaw)
	policyDigest := hex.EncodeToString(sum[:])

	syncConfig := signedconfig.Config{
		SchemaVersion: signedconfig.SchemaVersionV2,
		ConfigID:      "cfg_cli_daemon_v2",
		NetworkID:     "net_private",
		DeviceID:      "dev_cli",
		Generation:    2,
		IssuedAt:      signedconfig.CanonicalTime{Time: now.Add(-time.Minute)},
		ExpiresAt:     signedconfig.CanonicalTime{Time: now.Add(time.Hour)},
		ProxyCore:     signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{
			Kind:     signedconfig.TransportVLESS,
			Loopback: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
			Remote:   signedconfig.RemoteEndpoint{Host: "gateway.example.net", Port: 443, ServerName: "gateway.example.net"},
			AuthID:   "11111111-1111-4111-8111-111111111111",
		},
		WireGuard: signedconfig.WireGuard{
			InterfaceName: "wg-xco",
			Addresses:     []string{"10.77.0.20/32"},
			MTU:           1280,
			Peers: []signedconfig.Peer{{
				GatewayID:                  "gw_cli",
				PublicKey:                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				AllowedIPs:                 []string{"10.77.0.0/16"},
				Endpoint:                   signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
				PersistentKeepaliveSeconds: 25,
			}},
		},
		Policy: &signedconfig.Policy{
			Generation: 9,
			Digest:     policyDigest,
			Path:       signedconfig.PolicyPath(9, policyDigest),
			MediaType:  signedconfig.PolicyMediaType,
		},
		Signature: signedconfig.Signature{Algorithm: signedconfig.SignatureEd25519, KeyID: "signing_key_01"},
	}
	payloadBytes, err := syncConfig.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	syncConfig.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(signingPriv, payloadBytes))

	enrollmentToken := "xenr_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	signingPub := base64.StdEncoding.EncodeToString(signingPriv.Public().(ed25519.PublicKey))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/api/overlay/v1/device/session":
			var req controlplane.DeviceSessionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(controlplane.DeviceSessionResponse{
				ClientNonce:     req.ClientNonce,
				EnrollmentToken: enrollmentToken,
				TokenType:       "Bearer",
				IssuedAt:        now,
				ExpiresAt:       now.Add(10 * time.Minute),
				Scope:           []string{"overlay:config:read", "overlay:config:ack"},
				DeviceID:        "dev_cli",
				NetworkID:       "net_private",
				SigningKeys: []signedconfig.SigningKey{{
					KeyID:     "signing_key_01",
					Algorithm: signedconfig.SignatureEd25519,
					PublicKey: signingPub,
					Status:    "current",
					NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)},
				}},
			})
		case "/api/overlay/v1/enrollment/signed-config":
			w.Header().Set("Content-Type", controlplane.SignedConfigV2MediaType)
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("Vary", "Accept")
			w.Header().Set("ETag", `"cfg_cli_daemon_v2"`)
			_ = json.NewEncoder(w).Encode(syncConfig)
		case signedconfig.PolicyPath(9, policyDigest):
			w.Header().Set("Content-Type", signedconfig.PolicyMediaType)
			w.Header().Set("Cache-Control", "private, no-store")
			_, _ = w.Write(policyRaw)
		case "/api/overlay/v1/enrollment/signed-config/2/ack":
			_ = json.NewEncoder(w).Encode(controlplane.SignedConfigAckResponse{
				Acked: true,
				Ack: controlplane.SignedConfigAck{
					DeviceID:   "dev_cli",
					ConfigID:   "cfg_cli_daemon_v2",
					Generation: 2,
					AppliedAt:  now,
					ReceivedAt: now,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Update credential & last-known to point to our TLS test server.
	rec, err := creds.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rec.Controller = server.URL
	if err := creds.Save(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	lk, err := stateStore.LoadLastKnown()
	if err != nil {
		t.Fatal(err)
	}
	lk.Server = server.URL
	if err := stateStore.SaveLastKnown(lk); err != nil {
		t.Fatal(err)
	}

	readyFile := filepath.Join(daemonRuntimeDir(stateDir), "ready.json")
	if err := writeDaemonPID(stateDir, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	t.Setenv(daemonChildEnvVar, "1")
	t.Setenv(daemonReadyFileEnv, readyFile)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var stdout, stderr bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWithFactories(ctx, []string{"up", "--state-dir", stateDir, "--foreground", "--no-sudo"}, &stdout, &stderr, server.Client(),
			func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
			func(string) credential.Store { return creds },
		)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var readyPayload daemonReadyPayload
	for {
		if p, ok := readDaemonReadyFile(readyFile); ok {
			readyPayload = p
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("timed out waiting for ready file; err=%v stderr=%s", <-errCh, stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !readyPayload.Ready || readyPayload.Sync == nil || readyPayload.Sync.Generation != 2 {
		t.Fatalf("unexpected readyPayload: %+v", readyPayload)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("daemon child returned unexpected error: %v", err)
	}
	if _, err := os.Stat(daemonPIDPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected daemon.pid cleaned up on child exit, stat err=%v", err)
	}
}

func TestSpawnDaemonUpRealDetachedLifecycleAndDuplicateGuard(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	customLog := filepath.Join(stateDir, "logs", "daemon.log")

	t.Setenv("GO_WANT_DAEMON_HELPER", "1")
	t.Setenv("GO_DAEMON_HELPER_MODE", "ready")
	t.Setenv("GO_DAEMON_EXPECT_ARG", "--interval=30s")

	// Seed a stale dead PID first to verify stale PID cleanup.
	if err := writeDaemonPID(stateDir, 99999999); err != nil {
		t.Fatal(err)
	}

	res, err := spawnDaemonUp(t.Context(), daemonUpOptions{
		StateDir:        stateDir,
		LogFile:         customLog,
		RuntimeMode:     "embedded",
		OrigArgs:        []string{"-D", "--log-file", customLog, "--gateway", "gw-1", "--interval=30s"},
		Executable:      exe,
		ChildArgsPrefix: []string{"-test.run=^TestHelperDaemonProcess$", "--"},
		ReadyTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("spawnDaemonUp failed: %v", err)
	}
	t.Cleanup(func() {
		_ = stopDaemonProcess(res.PID, 2*time.Second)
	})

	if !res.Daemon || !res.Ready || res.AlreadyRunning || res.PID <= 0 {
		t.Fatalf("unexpected spawnDaemonUp result: %+v", res)
	}
	if res.LogFile != customLog || res.RuntimeMode != "embedded" || res.Sync == nil || res.Sync.Revision != "rev-helper" {
		t.Fatalf("unexpected metadata/sync in result: %+v", res)
	}
	if !isDaemonProcessAlive(res.PID) {
		t.Fatalf("expected spawned daemon pid %d to be alive", res.PID)
	}
	if pid, err := readDaemonPID(stateDir); err != nil || pid != res.PID {
		t.Fatalf("readDaemonPID=%d err=%v, want %d", pid, err, res.PID)
	}

	// Duplicate start must return AlreadyRunning without spawning a new process.
	res2, err := spawnDaemonUp(t.Context(), daemonUpOptions{
		StateDir:        stateDir,
		LogFile:         customLog,
		RuntimeMode:     "embedded",
		Executable:      exe,
		ChildArgsPrefix: []string{"-test.run=^TestHelperDaemonProcess$", "--"},
		ReadyTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("duplicate spawnDaemonUp failed: %v", err)
	}
	if !res2.AlreadyRunning || !res2.Ready || res2.PID != res.PID {
		t.Fatalf("expected AlreadyRunning with same PID %d, got %+v", res.PID, res2)
	}

	// Stop the helper cleanly and confirm it exits and removes daemon.pid.
	if err := stopDaemonProcess(res.PID, 5*time.Second); err != nil {
		t.Fatalf("stopDaemonProcess failed: %v", err)
	}
	if isDaemonProcessAlive(res.PID) {
		t.Fatalf("expected daemon pid %d to be dead after stopDaemonProcess", res.PID)
	}

	logBytes, err := os.ReadFile(customLog)
	if err != nil || !strings.Contains(string(logBytes), "daemon child ready") {
		t.Fatalf("expected helper stdout in log file %s, err=%v content=%q", customLog, err, string(logBytes))
	}
}

func TestSpawnDaemonUpEarlyFailureReturnsLogTail(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()

	t.Setenv("GO_WANT_DAEMON_HELPER", "1")
	t.Setenv("GO_DAEMON_HELPER_MODE", "fail_early")

	_, err = spawnDaemonUp(t.Context(), daemonUpOptions{
		StateDir:        stateDir,
		Executable:      exe,
		ChildArgsPrefix: []string{"-test.run=^TestHelperDaemonProcess$", "--"},
		ReadyTimeout:    5 * time.Second,
	})
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("expected CodeRuntimeApplyFailed, got code=%q err=%v", fault.Code(err), err)
	}
	if !strings.Contains(err.Error(), "line-21: fatal auth check failed") {
		t.Fatalf("expected log tail in error message, got: %v", err)
	}
	if strings.Contains(err.Error(), "line-01:") {
		t.Fatalf("expected log tail truncated to last 16 lines, got: %v", err)
	}
	if _, statErr := os.Stat(daemonPIDPath(stateDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected daemon.pid removed after early failure, stat err=%v", statErr)
	}
}

func TestSpawnDaemonUpTimeoutLeavesDaemonRunningWithReadyFalse(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()

	t.Setenv("GO_WANT_DAEMON_HELPER", "1")
	t.Setenv("GO_DAEMON_HELPER_MODE", "slow_ready")

	res, err := spawnDaemonUp(t.Context(), daemonUpOptions{
		StateDir:        stateDir,
		Executable:      exe,
		ChildArgsPrefix: []string{"-test.run=^TestHelperDaemonProcess$", "--"},
		ReadyTimeout:    150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected non-fatal Ready:false result on slow init, got err=%v", err)
	}
	t.Cleanup(func() {
		_ = stopDaemonProcess(res.PID, 2*time.Second)
	})
	if !res.Daemon || res.Ready || res.PID <= 0 {
		t.Fatalf("expected Daemon=true Ready=false with PID, got %+v", res)
	}
	if !isDaemonProcessAlive(res.PID) {
		t.Fatalf("expected timed-out daemon pid %d to remain alive", res.PID)
	}
}

func TestRunDownStopsDaemonProcessAndPreservesJSONSchema(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()

	t.Setenv("GO_WANT_DAEMON_HELPER", "1")
	t.Setenv("GO_DAEMON_HELPER_MODE", "ready")

	res, err := spawnDaemonUp(t.Context(), daemonUpOptions{
		StateDir:        stateDir,
		Executable:      exe,
		ChildArgsPrefix: []string{"-test.run=^TestHelperDaemonProcess$", "--"},
		ReadyTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("spawnDaemonUp failed: %v", err)
	}
	t.Cleanup(func() {
		_ = stopDaemonProcess(res.PID, 2*time.Second)
	})

	fakeRuntime := &overlayruntime.Fake{
		StatusResult: overlayruntime.Status{Available: true},
	}
	var stdout, stderr bytes.Buffer
	err = runWithRuntimeFactory(t.Context(), []string{"down", "--state-dir", stateDir}, &stdout, &stderr, http.DefaultClient, func(string) overlayruntime.Interface {
		return fakeRuntime
	})
	if err != nil {
		t.Fatalf("down failed: %v stderr=%s", err, stderr.String())
	}
	if isDaemonProcessAlive(res.PID) {
		t.Fatalf("expected runDown to stop daemon pid %d", res.PID)
	}
	if _, statErr := os.Stat(daemonPIDPath(stateDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected daemon.pid removed by runDown, stat err=%v", statErr)
	}

	var lifecycle usecase.LifecycleResult
	if err := json.Unmarshal(stdout.Bytes(), &lifecycle); err != nil {
		t.Fatalf("decode LifecycleResult: %v (stdout=%s)", err, stdout.String())
	}
	if lifecycle.State != "down" || lifecycle.AlreadyInState {
		t.Fatalf("unexpected down lifecycle output: %+v", lifecycle)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rawMap); err != nil {
		t.Fatal(err)
	}
	if _, hasExtra := rawMap["daemon_pid_stopped"]; hasExtra {
		t.Fatalf("unexpected extra field in down output: %v", rawMap)
	}
}

func seedTestDeviceCredential(t *testing.T) (string, *credential.MemoryStore, ed25519.PrivateKey) {
	t.Helper()
	stateDir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	secret, err := credential.GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x44}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	creds := &credential.MemoryStore{}
	err = creds.Save(t.Context(), credential.Record{
		SchemaVersion:      credential.SchemaVersion,
		Controller:         "https://accounts.example",
		DeviceID:           "dev_cli",
		NetworkID:          "net_private",
		Platform:           "linux",
		WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		CredentialID:       secret.CredentialID,
		Credential:         secret.Value,
		IssuedAt:           now.Add(-time.Minute),
		ExpiresAt:          now.Add(24 * time.Hour),
		Scope:              []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke},
		SigningKeys: signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{
			KeyID:     "signing_key_01",
			Algorithm: signedconfig.SignatureEd25519,
			PublicKey: pubB64,
			Status:    "current",
			NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return stateDir, creds, priv
}
