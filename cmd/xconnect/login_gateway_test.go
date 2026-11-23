package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

func TestLoginLogoutGatewayFlow(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pub)

	cfg := signedconfig.Config{
		SchemaVersion: 1,
		ConfigID:      "cfg-user-enroll",
		NetworkID:     "net_uat",
		DeviceID:      "one-test-device",
		Generation:    1,
		IssuedAt:      signedconfig.CanonicalTime{Time: now.Add(-time.Minute)},
		ExpiresAt:     signedconfig.CanonicalTime{Time: now.Add(time.Hour)},
		ProxyCore:     signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{
			Kind: signedconfig.TransportVLESS,
			Loopback: signedconfig.Endpoint{
				Host: "127.0.0.1",
				Port: 51830,
			},
			Remote: signedconfig.RemoteEndpoint{
				Host:       "tw-xconnect.svc.plus",
				Port:       443,
				ServerName: "tw-xconnect.svc.plus",
			},
			AuthID: "11111111-1111-1111-1111-111111111111",
		},
		WireGuard: signedconfig.WireGuard{
			InterfaceName: "xconzero0",
			Addresses:     []string{"10.77.0.2/32"},
			MTU:           1280,
			Peers: []signedconfig.Peer{
				{
					GatewayID:                  "gw-uat-tw-xconnect",
					PublicKey:                  pubKeyB64,
					AllowedIPs:                 []string{"10.77.0.0/24"},
					Endpoint:                   signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
					PersistentKeepaliveSeconds: 25,
				},
			},
		},
		Signature: signedconfig.Signature{
			Algorithm: signedconfig.SignatureEd25519,
			KeyID:     "key-gw-test",
		},
	}
	payload, err := cfg.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	// Mock accounts server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["identifier"] == "user@example.test" && req["password"] == "correct-pass" {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"message":      "login successful",
					"token":        "jwt-session-token-999",
					"access_token": "jwt-session-token-999",
					"user": map[string]any{
						"id":    "user-uuid-1",
						"email": "user@example.test",
					},
				})
				return
			}
			http.Error(w, `{"error":"invalid_credentials","message":"invalid credentials"}`, http.StatusUnauthorized)
		case "/api/overlay/v1/gateways":
			if r.Header.Get("Authorization") != "Bearer jwt-session-token-999" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(controlplane.GatewaysResponse{
				Gateways: []controlplane.GatewayEndpoint{
					{
						NetworkID:           "net_uat",
						GatewayID:           "gw-uat-tw-xconnect",
						DisplayName:         "Taiwan Gateway",
						EndpointHost:        "tw-xconnect.svc.plus",
						EndpointPort:        51820,
						TransportServerName: "tw-xconnect.svc.plus",
						TransportPort:       443,
						ConnectionMode:      "wg_vless_l3",
						RuntimeHealthy:      true,
					},
				},
			})
		case "/api/overlay/v1/devices/enroll":
			if r.Header.Get("Authorization") != "Bearer jwt-session-token-999" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			var req controlplane.DeviceEnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(controlplane.JoinTokenExchangeResponse{
				EnrollmentToken: "test-enrollment-tok-1",
				TokenType:       "Bearer",
				ExpiresAt:       now.Add(time.Hour),
				DeviceCredential: controlplane.DeviceCredential{
					CredentialID: "xdcid_11111111111111111111111111111111",
					Credential:   "xdc_11111111111111111111111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Device: model.Device{
					ID: req.DeviceID,
				},
				Network: model.Network{
					ID: req.NetworkID,
				},
				SigningKeys: []signedconfig.SigningKey{
					{
						KeyID:     "key-gw-test",
						Algorithm: "Ed25519",
						PublicKey: pubKeyB64,
						Status:    "current",
						NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)},
					},
				},
			})
		case "/api/overlay/v1/enrollment/signed-config":
			if r.Header.Get("Authorization") != "Bearer test-enrollment-tok-1" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(cfg)
		case "/api/overlay/v1/enrollment/signed-config/1/ack":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(controlplane.SignedConfigAckResponse{
				Acked: true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fakeRuntime := &overlayruntime.Fake{}
	newRuntime := func(dir string) overlayruntime.Interface { return fakeRuntime }
	memCreds := &credential.MemoryStore{}
	newCreds := func(dir string) credential.Store { return memCreds }

	// 1. Login with password stdin
	stdinBuffer := bytes.NewBufferString("correct-pass\n")
	oldStdin := os.Stdin
	pr, pw, _ := os.Pipe()
	os.Stdin = pr
	go func() {
		_, _ = io.Copy(pw, stdinBuffer)
		_ = pw.Close()
	}()
	defer func() { os.Stdin = oldStdin }()

	var stdout, stderr bytes.Buffer
	err = runWithFactories(context.Background(), []string{
		"login", "--server", server.URL, "--email", "user@example.test", "--password-stdin", "--state-dir", stateDir,
	}, &stdout, &stderr, server.Client(), newRuntime, newCreds)
	if err != nil {
		t.Fatalf("login failed: %v stderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Login successful") {
		t.Fatalf("unexpected login output: %s", stdout.String())
	}

	// 2. Login status
	stdout.Reset()
	err = runWithFactories(context.Background(), []string{
		"login", "--status", "--state-dir", stateDir,
	}, &stdout, &stderr, server.Client(), newRuntime, newCreds)
	if err != nil || !strings.Contains(stdout.String(), "Logged in as user@example.test") {
		t.Fatalf("login status failed: %v out: %s", err, stdout.String())
	}

	// 3. Gateway list
	stdout.Reset()
	err = runWithFactories(context.Background(), []string{
		"gateway", "list", "--json", "--state-dir", stateDir,
	}, &stdout, &stderr, server.Client(), newRuntime, newCreds)
	if err != nil || !strings.Contains(stdout.String(), "gw-uat-tw-xconnect") {
		t.Fatalf("gateway list failed: %v out: %s", err, stdout.String())
	}

	// 4. Test app-bridge method calls
	bridgeReq := fmt.Sprintf(`{"protocol_version":"1","request_id":"br-1","method":"login-state","params":{"state_dir":%q}}`, stateDir)
	resp := handleAppBridgeRequest(context.Background(), []byte(bridgeReq), func(ctx context.Context, args []string, out, err io.Writer, client *http.Client) error {
		return runWithFactories(ctx, args, out, err, client, newRuntime, newCreds)
	})
	if resp.Error != nil {
		t.Fatalf("app-bridge login-state error: %+v", resp.Error)
	}

	// 5. Logout
	stdout.Reset()
	err = runWithFactories(context.Background(), []string{
		"logout", "--state-dir", stateDir,
	}, &stdout, &stderr, server.Client(), newRuntime, newCreds)
	if err != nil || !strings.Contains(stdout.String(), "Logged out successfully") {
		t.Fatalf("logout failed: %v out: %s", err, stdout.String())
	}

	// Verify logged out
	stdout.Reset()
	err = runWithFactories(context.Background(), []string{
		"login", "--status", "--state-dir", stateDir,
	}, &stdout, &stderr, server.Client(), newRuntime, newCreds)
	if err != nil || !strings.Contains(stdout.String(), "Not logged in") {
		t.Fatalf("expected not logged in after logout: %s", stdout.String())
	}
}

func TestLoginWithMFATicketFlow(t *testing.T) {
	stateDir := t.TempDir()
	var mfaVerifyCalled bool

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message":      "mfa required",
				"mfa_required": true,
				"mfa_ticket":   "ticket-12345",
			})
		case "/api/auth/mfa/verify":
			mfaVerifyCalled = true
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["mfa_ticket"] != "ticket-12345" || req["totpCode"] != "654321" {
				http.Error(w, `{"error":"invalid_mfa"}`, http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "jwt-mfa-token",
				"user": map[string]any{
					"id":    "user-mfa-1",
					"email": "mfa@example.test",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	err := loginCredentials(context.Background(), server.URL, "mfa@example.test", "secret", "654321", stateDir, &stdout, &stderr, server.Client())
	if err != nil {
		t.Fatalf("loginCredentials with MFA failed: %v stderr=%s", err, stderr.String())
	}
	if !mfaVerifyCalled {
		t.Fatal("expected /api/auth/mfa/verify to be called")
	}
	if !strings.Contains(stdout.String(), "Login successful! Logged in as mfa@example.test") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestMatchOrSelectGatewayFourTier(t *testing.T) {
	gws := []controlplane.GatewayEndpoint{
		{
			NetworkID:           "net-ph-xconnect",
			GatewayID:           "ph-xconnect-gateway-01",
			EndpointHost:        "ph-xconnect-gateway-01.svc.plus",
			TransportServerName: "ph-xconnect-gateway-01.svc.plus",
			RuntimeHealthy:      true,
		},
		{
			NetworkID:           "net-tw-xconnect",
			GatewayID:           "tw-xconnect-gateway-01",
			EndpointHost:        "tw-xconnect-gateway-01.svc.plus",
			TransportServerName: "tw-xconnect-gateway-01.svc.plus",
			RuntimeHealthy:      false,
		},
	}

	// 1. Explicit match by GatewayID
	var stderr bytes.Buffer
	gw, err := matchOrSelectGateway(gws, "tw-xconnect-gateway-01", strings.NewReader(""), &stderr)
	if err != nil || gw.GatewayID != "tw-xconnect-gateway-01" {
		t.Fatalf("expected match by gateway ID, got %+v err=%v", gw, err)
	}

	// 2. Explicit match by EndpointHost
	gw, err = matchOrSelectGateway(gws, "ph-xconnect-gateway-01.svc.plus", strings.NewReader(""), &stderr)
	if err != nil || gw.GatewayID != "ph-xconnect-gateway-01" {
		t.Fatalf("expected match by endpoint host, got %+v err=%v", gw, err)
	}

	// 3. Single gateway auto-select
	gw, err = matchOrSelectGateway(gws[:1], "", strings.NewReader(""), &stderr)
	if err != nil || gw.GatewayID != "ph-xconnect-gateway-01" {
		t.Fatalf("expected single gateway auto-select, got %+v err=%v", gw, err)
	}

	// 4. Non-TTY multiple gateways without --gateway returns actionable error
	_, err = matchOrSelectGateway(gws, "", strings.NewReader(""), &stderr)
	if err == nil || !strings.Contains(err.Error(), "pass --gateway") {
		t.Fatalf("expected error prompting --gateway, got %v", err)
	}

	// 5. Explicit match by full gateway URL (e.g. https://ph-xconnect-gateway-01.svc.plus)
	gw, err = matchOrSelectGateway(gws, "https://ph-xconnect-gateway-01.svc.plus/", strings.NewReader(""), &stderr)
	if err != nil || gw.GatewayID != "ph-xconnect-gateway-01" {
		t.Fatalf("expected match by gateway URL, got %+v err=%v", gw, err)
	}
}

func TestReadPasswordHidesInTerminalAndSupportsShowPassword(t *testing.T) {
	origIsTerminal := isTerminalFD
	origReadTermPwd := readTerminalPassword
	t.Cleanup(func() {
		isTerminalFD = origIsTerminal
		readTerminalPassword = origReadTermPwd
	})

	// Case 1: TTY without --show-password uses readTerminalPassword and prints newline to stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	defer pr.Close()

	isTerminalFD = func(fd int) bool { return fd == int(pr.Fd()) }
	var termCalled bool
	var capturedFD int
	readTerminalPassword = func(fd int) ([]byte, error) {
		termCalled = true
		capturedFD = fd
		return []byte("hidden-secret"), nil
	}

	var stderr bytes.Buffer
	got, err := readPassword(pr, &stderr, false)
	if err != nil {
		t.Fatalf("readPassword failed: %v", err)
	}
	if !termCalled || capturedFD != int(pr.Fd()) {
		t.Fatalf("expected term.ReadPassword to be called with fd %d, called=%v fd=%d", pr.Fd(), termCalled, capturedFD)
	}
	if got != "hidden-secret" {
		t.Fatalf("unexpected password %q", got)
	}
	if stderr.String() != "\n" {
		t.Fatalf("expected newline written to stderr after hidden input, got %q", stderr.String())
	}

	// Case 2: TTY with --show-password=true falls back to visible line read (does not call term.ReadPassword)
	pr2, pw2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw2.WriteString("visible-secret\n")
	_ = pw2.Close()
	defer pr2.Close()

	isTerminalFD = func(fd int) bool { return fd == int(pr2.Fd()) }
	termCalled = false
	stderr.Reset()
	got, err = readPassword(pr2, &stderr, true)
	if err != nil {
		t.Fatalf("readPassword with showPassword failed: %v", err)
	}
	if termCalled {
		t.Fatal("expected term.ReadPassword NOT to be called when showPassword=true")
	}
	if got != "visible-secret" {
		t.Fatalf("unexpected visible password %q", got)
	}

	// Case 3: Non-TTY safely falls back to line read
	isTerminalFD = func(int) bool { return false }
	termCalled = false
	got, err = readPassword(strings.NewReader("piped-secret\r\n"), &stderr, false)
	if err != nil {
		t.Fatalf("readPassword non-TTY failed: %v", err)
	}
	if termCalled || got != "piped-secret" {
		t.Fatalf("expected non-TTY fallback, termCalled=%v got=%q", termCalled, got)
	}
}

func TestDefaultStateDirectoryFallbackWhenPrimaryUnwritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission modes do not restrict directory creation on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission bits")
	}

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	primary := filepath.Join(homeDir, ".xconnect-one")
	if err := os.MkdirAll(primary, 0o700); err != nil {
		t.Fatal(err)
	}

	// Writable primary is selected directly
	selected, gotPrimary, reason := resolveDefaultStateDirectory()
	if selected != primary || gotPrimary != primary || reason != "" {
		t.Fatalf("expected primary %q without fallback, got selected=%q primary=%q reason=%q", primary, selected, gotPrimary, reason)
	}

	// Make primary read-only -> should safely fall back to ~/.xconnect-one-user
	if err := os.Chmod(primary, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(primary, 0o700) })

	selected, gotPrimary, reason = resolveDefaultStateDirectory()
	wantFallback := filepath.Join(homeDir, ".xconnect-one-user")
	if selected != wantFallback || gotPrimary != primary || reason == "" {
		t.Fatalf("expected fallback %q with reason, got selected=%q primary=%q reason=%q", wantFallback, selected, gotPrimary, reason)
	}
}

func TestLoginRejectsExplicitUnwritableStateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission modes do not restrict directory creation on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission bits")
	}

	roDir := filepath.Join(t.TempDir(), "ro-state")
	if err := os.MkdirAll(roDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.WriteString("ignored-pass\n")
	_ = pw.Close()
	oldStdin := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = pr.Close()
	})

	var stdout, stderr bytes.Buffer
	err = runWithFactories(context.Background(), []string{
		"login", "--server", "https://accounts.svc.plus", "--email", "user@example.test", "--password-stdin", "--state-dir", roDir,
	}, &stdout, &stderr, http.DefaultClient, func(string) overlayruntime.Interface { return &overlayruntime.Fake{} }, func(string) credential.Store { return &credential.MemoryStore{} })
	if fault.Code(err) != fault.CodeCredentialStorage {
		t.Fatalf("expected CodeCredentialStorage, got code=%q err=%v", fault.Code(err), err)
	}
	if !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "--state-dir") {
		t.Fatalf("expected actionable permission denied message, got: %v", err)
	}
}

func TestLoginInteractivePromptsServerStateDirPasswordAndGateway(t *testing.T) {
	origIsTerminal := isTerminalFD
	origReadTermPwd := readTerminalPassword
	t.Cleanup(func() {
		isTerminalFD = origIsTerminal
		readTerminalPassword = origReadTermPwd
	})

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	customStateDir := filepath.Join(homeDir, "custom-state")

	now := time.Now().UTC().Truncate(time.Second)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pub)

	cfg := signedconfig.Config{
		SchemaVersion: signedconfig.SchemaVersionV2,
		ConfigID:      "cfg-interactive",
		NetworkID:     "net-ph-xconnect",
		DeviceID:      defaultDeviceID(),
		Generation:    1,
		IssuedAt:      signedconfig.CanonicalTime{Time: now.Add(-time.Minute)},
		ExpiresAt:     signedconfig.CanonicalTime{Time: now.Add(time.Hour)},
		ProxyCore:     signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{
			Kind:     signedconfig.TransportVLESS,
			Loopback: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
			Remote:   signedconfig.RemoteEndpoint{Host: "ph-xconnect-gateway-01.svc.plus", Port: 443, ServerName: "ph-xconnect-gateway-01.svc.plus"},
			AuthID:   "11111111-1111-1111-1111-111111111111",
		},
		WireGuard: signedconfig.WireGuard{
			InterfaceName: "xconzero0",
			Addresses:     []string{"10.77.0.2/32"},
			MTU:           1280,
			Peers: []signedconfig.Peer{
				{
					GatewayID:                  "ph-xconnect-gateway-01",
					PublicKey:                  pubKeyB64,
					AllowedIPs:                 []string{"10.77.0.0/24"},
					Endpoint:                   signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
					PersistentKeepaliveSeconds: 25,
				},
			},
		},
		Policy: &signedconfig.Policy{
			Generation: 9,
			Digest:     "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c",
			Path:       "/api/overlay/v1/enrollment/policy-artifacts/9/58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c",
			MediaType:  "application/vnd.xconnect.policy.v1+json",
		},
		Signature: signedconfig.Signature{Algorithm: signedconfig.SignatureEd25519, KeyID: "key-gw-test"},
	}
	payload, err := cfg.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["identifier"] == "interactive@example.test" && req["password"] == "term-secret-pass" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "jwt-interactive-tok",
					"user":         map[string]any{"id": "u-1", "email": "interactive@example.test"},
				})
				return
			}
			http.Error(w, `{"message":"bad creds"}`, http.StatusUnauthorized)
		case "/api/overlay/v1/gateways":
			_ = json.NewEncoder(w).Encode(controlplane.GatewaysResponse{
				Gateways: []controlplane.GatewayEndpoint{
					{
						NetworkID:           "net-ph-xconnect",
						GatewayID:           "ph-xconnect-gateway-01",
						DisplayName:         "PH Gateway",
						EndpointHost:        "ph-xconnect-gateway-01.svc.plus",
						EndpointPort:        51820,
						TransportServerName: "ph-xconnect-gateway-01.svc.plus",
						RuntimeHealthy:      true,
					},
				},
			})
		case "/api/overlay/v1/devices/enroll":
			var req controlplane.DeviceEnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(controlplane.JoinTokenExchangeResponse{
				EnrollmentToken: "xenr_" + strings.Repeat("A", 43),
				TokenType:       "Bearer",
				ExpiresAt:       now.Add(time.Hour),
				DeviceCredential: controlplane.DeviceCredential{
					CredentialID: "xdcid_11111111111111111111111111111111",
					Credential:   "xdc_11111111111111111111111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					IssuedAt:     now,
					ExpiresAt:    now.Add(24 * time.Hour),
					Scope:        []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke},
				},
				Device:      model.Device{ID: req.DeviceID},
				Network:     model.Network{ID: req.NetworkID},
				SigningKeys: []signedconfig.SigningKey{{KeyID: "key-gw-test", Algorithm: "Ed25519", PublicKey: pubKeyB64, Status: "current", NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)}}},
			})
		case "/api/overlay/v1/enrollment/signed-config":
			w.Header().Set("Content-Type", controlplane.SignedConfigV2MediaType)
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("Vary", "Accept")
			w.Header().Set("ETag", `"cfg-v2"`)
			_ = json.NewEncoder(w).Encode(cfg)
		case "/api/overlay/v1/enrollment/signed-config/1/ack":
			_ = json.NewEncoder(w).Encode(controlplane.SignedConfigAckResponse{Acked: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Interactive TTY input sequence is now streamlined: only Email and Password
	// (no prompts for State directory, Accounts server, or Gateway selection).
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.WriteString("interactive@example.test\n")
	_ = pw.Close()

	oldStdin := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = pr.Close()
	})

	isTerminalFD = func(fd int) bool { return fd == int(pr.Fd()) }
	var termPasswordCalled bool
	readTerminalPassword = func(fd int) ([]byte, error) {
		termPasswordCalled = true
		return []byte("term-secret-pass"), nil
	}

	var stdout, stderr bytes.Buffer
	err = runWithFactories(context.Background(), []string{
		"login", "--server", server.URL, "--state-dir", customStateDir,
	}, &stdout, &stderr, server.Client(),
		func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
		func(string) credential.Store { return &credential.MemoryStore{} },
	)
	if err != nil {
		t.Fatalf("interactive login failed: %v stderr=%s", err, stderr.String())
	}
	if !termPasswordCalled {
		t.Fatal("expected hidden terminal password reader to be used")
	}
	if strings.Contains(stderr.String(), "Accounts server [") || strings.Contains(stderr.String(), "State directory [") || strings.Contains(stderr.String(), "Select gateway") {
		t.Fatalf("did not expect redundant interactive prompts on login, stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Login successful! Logged in as interactive@example.test") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "xconnect-one join") {
		t.Fatalf("expected next-step join instruction, stdout=%s", stdout.String())
	}
	if _, err := credential.LoadUserSession(customStateDir); err != nil {
		t.Fatalf("expected session saved in custom state dir %q: %v", customStateDir, err)
	}
}

func TestLoginAndUpHelpFlagsReturnNil(t *testing.T) {
	for _, sub := range []string{"login", "join", "up"} {
		var stdout, stderr bytes.Buffer
		err := runWithFactories(context.Background(), []string{sub, "--help"}, &stdout, &stderr, http.DefaultClient,
			func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
			func(string) credential.Store { return &credential.MemoryStore{} },
		)
		if err != nil {
			t.Fatalf("%s --help returned unexpected error: %v", sub, err)
		}
		if !strings.Contains(stderr.String(), "-state-dir") || !strings.Contains(stderr.String(), "-gateway") {
			t.Fatalf("%s --help missing expected flags: %s", sub, stderr.String())
		}
		if sub == "login" && (!strings.Contains(stderr.String(), "-show-password") || !strings.Contains(stderr.String(), "-server")) {
			t.Fatalf("login --help missing -show-password or -server: %s", stderr.String())
		}
	}
}

func TestLoginWithEmptyGatewayListDoesNotShowBrokenOption(t *testing.T) {
	origIsTerminal := isTerminalFD
	origReadTermPwd := readTerminalPassword
	t.Cleanup(func() {
		isTerminalFD = origIsTerminal
		readTerminalPassword = origReadTermPwd
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "jwt-empty-gw-tok",
				"user":         map[string]any{"id": "u-empty", "email": "empty@example.test"},
			})
		case "/api/overlay/v1/gateways":
			_ = json.NewEncoder(w).Encode(controlplane.GatewaysResponse{Gateways: []controlplane.GatewayEndpoint{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// 1. Interactive login without --gateway when server returns {"gateways":[]}
	stateDir := t.TempDir()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.WriteString("empty@example.test\n")
	_ = pw.Close()
	oldStdin := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = pr.Close()
	})
	isTerminalFD = func(fd int) bool { return fd == int(pr.Fd()) }
	readTerminalPassword = func(int) ([]byte, error) { return []byte("secret-pass"), nil }

	var stdout, stderr bytes.Buffer
	err = runWithFactories(context.Background(), []string{
		"login", "--server", server.URL, "--state-dir", stateDir,
	}, &stdout, &stderr, server.Client(),
		func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
		func(string) credential.Store { return &credential.MemoryStore{} },
	)
	if err != nil {
		t.Fatalf("expected interactive login with empty gateways to succeed, got %v stderr=%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "Gateway options:") || strings.Contains(stderr.String(), "Select gateway") {
		t.Fatalf("must not prompt gateway options on login: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "xconnect-one join") {
		t.Fatalf("expected join guidance on stdout, got: %s", stdout.String())
	}
	if _, err := credential.LoadUserSession(stateDir); err != nil {
		t.Fatalf("expected saved session to remain intact: %v", err)
	}

	// 2. Explicit --gateway when server returns {"gateways":[]} returns clear not_joined guidance
	isTerminalFD = func(int) bool { return false }
	stdout.Reset()
	stderr.Reset()
	err = runWithFactories(context.Background(), []string{
		"login", "--server", server.URL, "--email", "empty@example.test", "--password-stdin",
		"--state-dir", stateDir, "--gateway", "https://ph-xconnect-gateway-01.svc.plus",
	}, &stdout, &stderr, server.Client(),
		func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
		func(string) credential.Store { return &credential.MemoryStore{} },
	)
	if fault.Code(err) != fault.CodeNotJoined {
		t.Fatalf("expected CodeNotJoined, got code=%q err=%v", fault.Code(err), err)
	}
	if !strings.Contains(err.Error(), "no gateways are bound to your account") || !strings.Contains(err.Error(), "xconnect-one join") {
		t.Fatalf("expected clear actionable error message, got: %v", err)
	}
}

func TestJoinSessionOpensConsolePollsAndEnrollsGateway(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pub)

	cfg := signedconfig.Config{
		SchemaVersion: signedconfig.SchemaVersionV2,
		ConfigID:      "cfg-ph-enroll",
		NetworkID:     "net-ph-xconnect",
		DeviceID:      "ph-device-1",
		Generation:    1,
		IssuedAt:      signedconfig.CanonicalTime{Time: now.Add(-time.Minute)},
		ExpiresAt:     signedconfig.CanonicalTime{Time: now.Add(time.Hour)},
		ProxyCore:     signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{
			Kind:     signedconfig.TransportVLESS,
			Loopback: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
			Remote: signedconfig.RemoteEndpoint{
				Host:       "ph-xconnect-gateway-01.svc.plus",
				Port:       443,
				ServerName: "ph-xconnect-gateway-01.svc.plus",
			},
			AuthID: "11111111-1111-1111-1111-111111111111",
		},
		WireGuard: signedconfig.WireGuard{
			InterfaceName: "xconzero0",
			Addresses:     []string{"10.77.0.3/32"},
			MTU:           1280,
			Peers: []signedconfig.Peer{
				{
					GatewayID:                  "ph-xconnect-gateway-01",
					PublicKey:                  pubKeyB64,
					AllowedIPs:                 []string{"10.77.0.0/24"},
					Endpoint:                   signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830},
					PersistentKeepaliveSeconds: 25,
				},
			},
		},
		Policy: &signedconfig.Policy{
			Generation: 9,
			Digest:     "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c",
			Path:       "/api/overlay/v1/enrollment/policy-artifacts/9/58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c",
			MediaType:  "application/vnd.xconnect.policy.v1+json",
		},
		Signature: signedconfig.Signature{
			Algorithm: signedconfig.SignatureEd25519,
			KeyID:     "key-ph-test",
		},
	}
	payload, err := cfg.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	var gatewayCalls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/overlay/v1/gateways":
			gatewayCalls++
			if gatewayCalls == 1 {
				_ = json.NewEncoder(w).Encode(controlplane.GatewaysResponse{Gateways: []controlplane.GatewayEndpoint{}})
				return
			}
			_ = json.NewEncoder(w).Encode(controlplane.GatewaysResponse{
				Gateways: []controlplane.GatewayEndpoint{
					{
						NetworkID:           "net-ph-xconnect",
						GatewayID:           "ph-xconnect-gateway-01",
						DisplayName:         "Philippines Gateway 01",
						EndpointHost:        "ph-xconnect-gateway-01.svc.plus",
						EndpointPort:        51820,
						TransportServerName: "ph-xconnect-gateway-01.svc.plus",
						TransportPort:       443,
						ConnectionMode:      "wg_vless_l3",
						RuntimeHealthy:      true,
					},
				},
			})
		case "/api/overlay/v1/devices/enroll":
			var req controlplane.DeviceEnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(controlplane.JoinTokenExchangeResponse{
				EnrollmentToken: "xenr_" + strings.Repeat("A", 43),
				TokenType:       "Bearer",
				ExpiresAt:       now.Add(time.Hour),
				DeviceCredential: controlplane.DeviceCredential{
					CredentialID: "xdcid_11111111111111111111111111111111",
					Credential:   "xdc_11111111111111111111111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					IssuedAt:     now,
					ExpiresAt:    now.Add(24 * time.Hour),
					Scope:        []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke},
				},
				Device:  model.Device{ID: req.DeviceID},
				Network: model.Network{ID: req.NetworkID},
				SigningKeys: []signedconfig.SigningKey{
					{
						KeyID:     "key-ph-test",
						Algorithm: "Ed25519",
						PublicKey: pubKeyB64,
						Status:    "current",
						NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)},
					},
				},
			})
		case "/api/overlay/v1/enrollment/signed-config":
			w.Header().Set("Content-Type", controlplane.SignedConfigV2MediaType)
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("Vary", "Accept")
			w.Header().Set("ETag", `"cfg-v2"`)
			_ = json.NewEncoder(w).Encode(cfg)
		case "/api/overlay/v1/enrollment/signed-config/1/ack":
			_ = json.NewEncoder(w).Encode(controlplane.SignedConfigAckResponse{Acked: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := credential.SaveUserSession(stateDir, credential.UserSession{
		Server:      server.URL,
		Email:       "156405189@qq.com",
		UserID:      "u-156405189",
		AccessToken: "jwt-tok-156",
		UpdatedAt:   now,
	}); err != nil {
		t.Fatal(err)
	}

	var openedURL string
	origOpenBrowser := openBrowserFunc
	openBrowserFunc = func(u string) error {
		openedURL = u
		return nil
	}
	t.Cleanup(func() { openBrowserFunc = origOpenBrowser })

	memCreds := &credential.MemoryStore{}
	var stdout, stderr bytes.Buffer
	err = runWithFactories(context.Background(), []string{
		"join",
		"--state-dir", stateDir,
		"--device-id", "ph-device-1",
		"--gateway", "ph-xconnect-gateway-01",
		"--network-id", "net-ph-xconnect",
		"--poll-interval", "20ms",
		"--wait", "2s",
	}, &stdout, &stderr, server.Client(),
		func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
		func(string) credential.Store { return memCreds },
	)
	if err != nil {
		t.Fatalf("join failed: %v stderr=%s", err, stderr.String())
	}
	if !strings.HasPrefix(openedURL, "https://console.svc.plus/panel/xconnect-zero") {
		t.Fatalf("expected console URL to be opened, got %q", openedURL)
	}
	if !strings.Contains(openedURL, "network=net-ph-xconnect") || !strings.Contains(openedURL, "gateway=ph-xconnect-gateway-01") {
		t.Fatalf("expected network and gateway hints in console URL, got %q", openedURL)
	}
	if !strings.Contains(stdout.String(), "Joined network net-ph-xconnect via gateway ph-xconnect-gateway-01") ||
		!strings.Contains(stdout.String(), "xconnect-one up") {
		t.Fatalf("unexpected join stdout: %s", stdout.String())
	}
	rec, err := memCreds.Load(context.Background())
	if err != nil || rec.NetworkID != "net-ph-xconnect" {
		t.Fatalf("expected enrolled credential for net-ph-xconnect, got rec=%+v err=%v", rec, err)
	}
}

func TestResolveDefaultStateDirectoryForSudoFallsBackToUserDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission modes do not restrict directory creation on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission bits")
	}

	homeDir := t.TempDir()
	primary := filepath.Join(homeDir, ".xconnect-one")
	if err := os.MkdirAll(primary, 0o700); err != nil {
		t.Fatal(err)
	}

	// Pure root daemon (no SUDO_UID) stays on primary.
	selected, gotPrimary, reason := resolveDefaultStateDirectoryFor(0, homeDir, nil, 0, false)
	if selected != primary || gotPrimary != primary || reason != "" {
		t.Fatalf("expected pure root to use primary %q, got selected=%q primary=%q reason=%q", primary, selected, gotPrimary, reason)
	}

	// Sudo invocation when primary is unusable (e.g. root-owned/unwritable by user)
	// resolves to ~/.xconnect-one-user so sudo up shares credentials with login/join.
	if err := os.Chmod(primary, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(primary, 0o700) })

	selected, gotPrimary, reason = resolveDefaultStateDirectoryFor(0, homeDir, nil, uint32(os.Geteuid()), true)
	wantFallback := filepath.Join(homeDir, ".xconnect-one-user")
	if selected != wantFallback || gotPrimary != primary || reason == "" {
		t.Fatalf("expected sudo fallback %q with reason, got selected=%q primary=%q reason=%q", wantFallback, selected, gotPrimary, reason)
	}
}

func TestHandleRuntimePermissionErrorAndStripStateDirFlag(t *testing.T) {
	origIsTerminal := isTerminalFD
	origExecSudo := execSudoCommand
	t.Cleanup(func() {
		isTerminalFD = origIsTerminal
		execSudoCommand = origExecSudo
	})

	stateDir := t.TempDir()
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

	permErr := fault.New(fault.CodeRuntimePermission, "apply desktop runtime", nil)
	var recordedArgs []string
	execSudoCommand = func(_ context.Context, args []string) error {
		recordedArgs = append([]string(nil), args...)
		return nil
	}

	var stderr bytes.Buffer
	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		if got := handleRuntimePermissionError(context.Background(), "up", stateDir, []string{"--watch", "--state-dir", "/tmp/old"}, false, &stderr, permErr); got != nil {
			t.Fatalf("expected nil after sudo elevation, got %v", got)
		}
		joined := strings.Join(recordedArgs, " ")
		if !strings.Contains(joined, " up --state-dir "+stateDir+" --watch") || strings.Contains(joined, "/tmp/old") {
			t.Fatalf("unexpected sudo args: %v", recordedArgs)
		}
	}

	// Verify --no-sudo skips elevation and prints manual command.
	stderr.Reset()
	recordedArgs = nil
	got := handleRuntimePermissionError(context.Background(), "up", stateDir, []string{"--no-sudo"}, true, &stderr, permErr)
	if fault.Code(got) != fault.CodeRuntimePermission {
		t.Fatalf("expected CodeRuntimePermission with noSudo, got %v", got)
	}
	if len(recordedArgs) != 0 {
		t.Fatalf("expected no sudo call when noSudo=true, got %v", recordedArgs)
	}
	if !strings.Contains(stderr.String(), "Run: sudo xconnect-one up --state-dir "+stateDir) {
		t.Fatalf("expected manual sudo hint, got stderr=%s", stderr.String())
	}
}

func TestJoinRejectsExpiredSessionWithActionableLoginHint(t *testing.T) {
	stateDir := t.TempDir()
	if err := credential.SaveUserSession(stateDir, credential.UserSession{
		Server:      "https://accounts.svc.plus",
		Email:       "user@example.test",
		UserID:      "u-expired",
		AccessToken: "expired-jwt",
		ExpiresAt:   time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runWithFactories(context.Background(), []string{"join", "--state-dir", stateDir, "--no-browser"}, &stdout, &stderr, http.DefaultClient,
		func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
		func(string) credential.Store { return &credential.MemoryStore{} },
	)
	if fault.Code(err) != fault.CodeAuthenticationFailed {
		t.Fatalf("expected CodeAuthenticationFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "xconnect-one login") {
		t.Fatalf("expected xconnect-one login guidance, got %v", err)
	}
}

func TestFormatFaultErrorPreservesOperationChain(t *testing.T) {
	inner := fault.New(fault.CodeRuntimeApplyFailed, "start WireGuard runtime", os.ErrPermission)
	middle := fault.New(fault.CodeRuntimeApplyFailed, "apply desktop runtime", inner)
	outer := fault.New(fault.CodeRuntimeApplyFailed, "apply synchronized runtime", middle)
	got := formatFaultError(outer)
	want := "apply synchronized runtime -> apply desktop runtime -> start WireGuard runtime: runtime_apply_failed"
	if got != want {
		t.Fatalf("formatFaultError=%q, want %q", got, want)
	}
	if strings.Contains(got, "permission") {
		t.Fatalf("must not leak raw non-fault cause error: %q", got)
	}

	hinted := fault.New(fault.CodeRuntimeApplyFailed, "start Xray runtime", &overlayruntime.HintedError{Hint: "systemd is not the init system"})
	got = formatFaultError(hinted)
	if !strings.Contains(got, "start Xray runtime") || !strings.Contains(got, "systemd is not the init system") {
		t.Fatalf("expected safe hint, got %q", got)
	}
	if !strings.Contains(got, "runtime_apply_failed") {
		t.Fatalf("expected fault code, got %q", got)
	}
}

func TestUpAndSyncHelpIncludeForegroundAndProcessModeFlags(t *testing.T) {
	for _, sub := range []string{"up", "sync"} {
		var stdout, stderr bytes.Buffer
		err := runWithFactories(context.Background(), []string{sub, "--help"}, &stdout, &stderr, http.DefaultClient,
			func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
			func(string) credential.Store { return &credential.MemoryStore{} },
		)
		if err != nil {
			t.Fatalf("%s --help returned error: %v", sub, err)
		}
		if !strings.Contains(stderr.String(), "-foreground") || !strings.Contains(stderr.String(), "-process-mode") {
			t.Fatalf("%s --help missing -foreground or -process-mode: %s", sub, stderr.String())
		}
	}
}

func TestNormalizeProcessModeValidation(t *testing.T) {
	t.Setenv("XCONNECT_LINUX_PROCESS_MODE", "")
	for _, valid := range []string{"", "auto", "systemd", "direct"} {
		mode, err := normalizeProcessMode(valid)
		if err != nil {
			t.Fatalf("normalizeProcessMode(%q) unexpected error: %v", valid, err)
		}
		if mode != valid {
			t.Fatalf("got %q want %q", mode, valid)
		}
	}
	var stdout, stderr bytes.Buffer
	err := runWithFactories(context.Background(), []string{"up", "--process-mode", "invalid-mode"}, &stdout, &stderr, http.DefaultClient,
		func(string) overlayruntime.Interface { return &overlayruntime.Fake{} },
		func(string) credential.Store { return &credential.MemoryStore{} },
	)
	if fault.Code(err) != fault.CodeInvalidInput {
		t.Fatalf("expected CodeInvalidInput for invalid --process-mode, got %v", err)
	}
}
