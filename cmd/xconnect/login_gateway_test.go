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
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	newCreds := func(dir string) credential.Store { return credential.NewFileStore(dir) }

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
