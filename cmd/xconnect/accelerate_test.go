package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err == nil || !strings.Contains(err.Error(), "accelerate up --gateway") {
		t.Fatalf("expected acceleration login to reject One enrollment flags, got %v", err)
	}
}
