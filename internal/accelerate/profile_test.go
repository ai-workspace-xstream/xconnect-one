package accelerate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
)

func TestProfileUsesAccountsSessionAndSelectsManagedNode(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != nodesPath || r.Header.Get("Authorization") != "Bearer test-session" {
			t.Error("request did not use the managed node endpoint and login session")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode([]node{
			{ID: "local", VLESS: "vless://test@first.example:443?security=tls"},
			{ID: "selected", XHTTP: "vless://test@second.example:443?security=tls&type=xhttp&path=%2Fconnect&mode=packet-up"},
		})
	}))
	defer server.Close()
	profile, err := Profile(context.Background(), server.Client(), credential.UserSession{
		Server: server.URL, AccessToken: "test-session",
	}, "selected")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`"address":"second.example"`, `"protocol":"tun"`, `"path":"/connect"`} {
		if !strings.Contains(string(profile), value) {
			t.Fatalf("generated profile is missing %s", value)
		}
	}
	for _, value := range []string{"first.example", "autoSystemRoutingTable", "allowInsecure", "test-session"} {
		if strings.Contains(string(profile), value) {
			t.Fatalf("generated profile unexpectedly includes %s", value)
		}
	}
}

func TestProfileRejectsPlaintextAndAmbiguousSelection(t *testing.T) {
	bad := []node{{ID: "bad", VLESS: "vless://test@example.org:443?security=none"}}
	if len(supportedNodes(bad)) != 0 {
		t.Fatal("accepted plaintext profile")
	}
	n := node{ID: "same", VLESS: "vless://test@example.org:443?security=tls"}
	if _, err := Select(supportedNodes([]node{n, n}), "same", true); err == nil {
		t.Fatal("accepted an ambiguous gateway")
	}
}

func TestNodesFallsBackToLegacyEndpointAndWrappedPayload(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nodesPath:
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
		case legacyNodesPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"nodes": []node{
					{
						ID:    "jp-01",
						Name:  "jp-01.example",
						XHTTP: "vless://00000000-0000-0000-0000-000000000001@jp-01.example:443?encryption=none&type=xhttp&security=tls&host=jp-01.example&path=%2Fsplit&mode=auto&sni=jp-01.example&fp=chrome&alpn=h2%2Chttp%2F1.1%2Ch3#jp-01.example",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	profile, err := Profile(context.Background(), server.Client(), credential.UserSession{
		Server: server.URL, AccessToken: "opaque-session-token",
	}, "jp-01")
	if err != nil {
		t.Fatalf("expected fallback to succeed: %v", err)
	}
	for _, want := range []string{`"path":"/split"`, `"mode":"auto"`, `"fingerprint":"chrome"`} {
		if !strings.Contains(string(profile), want) {
			t.Fatalf("profile missing %s: %s", want, string(profile))
		}
	}
}
