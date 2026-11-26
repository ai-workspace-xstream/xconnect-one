package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/internal/accelerate"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
)

func TestAccelerateLoginUsesSharedSession(t *testing.T) {
	dir := t.TempDir()
	if err := credential.SaveUserSession(dir, credential.UserSession{
		Server: "https://example.com", Email: "user@example.com", AccessToken: "test-token",
	}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	args := []string{"--state-dir", dir, "accelerate", "login", "--status", "--json"}
	if err := runWithFactories(context.Background(), args, &out, &errOut, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"logged_in": true`) || strings.Contains(out.String(), "test-token") {
		t.Fatalf("unexpected login status: %s", out.String())
	}
	if files, err := os.ReadDir(filepath.Join(dir, "protected")); err != nil || len(files) != 1 {
		t.Fatalf("acceleration login status modified One state: %v", err)
	}
}

func TestAccelerateLoginDoesNotEnrollGateway(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"accelerate", "login", "--gateway", "example.com"}
	err := runWithFactories(context.Background(), args, &out, &errOut, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "accelerate join") {
		t.Fatalf("expected acceleration login to reject One enrollment flags, got %v", err)
	}
}

func TestAccelerateJoinSelectsAndStoresOnlyNodeKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent-server/v1/nodes" || r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[
			{"address":"one.example","name":"First","uri_scheme_tcp":"vless://node-secret@one.example:443?security=tls"},
			{"address":"two.example","name":"Second","uri_scheme_xhttp":"vless://node-secret@two.example:443?security=tls&type=xhttp"}
		]`))
	}))
	defer server.Close()
	dir := t.TempDir()
	session := credential.UserSession{Server: server.URL, UserID: "user", AccessToken: "test-token"}
	if err := credential.SaveUserSession(dir, session); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := joinAcceleration(context.Background(), server.Client(), dir, "", strings.NewReader("2\n"), &out, true); err != nil {
		t.Fatal(err)
	}
	if key, err := accelerate.LoadSelection(dir, session); err != nil || key != "two.example" {
		t.Fatalf("unexpected selected node: %q (%v)", key, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "protected", "acceleration-node.json"))
	if err != nil || strings.Contains(string(data), "node-secret") ||
		strings.Contains(string(data), "test-token") || strings.Contains(out.String(), "node-secret") {
		t.Fatal("join failed to save a credential-free selection")
	}
	session.UserID = "another-user"
	if _, err := accelerate.LoadSelection(dir, session); err == nil {
		t.Fatal("accepted a selection made by another account")
	}
}
