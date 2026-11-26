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
