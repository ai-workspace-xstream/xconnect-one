package credential_test

import (
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
)

func TestUserSessionLifecycle(t *testing.T) {
	stateDir := t.TempDir()

	// Initial load should fail with not found
	_, err := credential.LoadUserSession(stateDir)
	if err == nil {
		t.Fatal("expected ErrNotFound for missing session")
	}

	now := time.Now().UTC().Truncate(time.Second)
	sess := credential.UserSession{
		Server:      "https://accounts.svc.plus",
		Email:       "alice@example.test",
		AccessToken: "test-token-12345",
		ExpiresAt:   now.Add(time.Hour),
	}

	if err := credential.SaveUserSession(stateDir, sess); err != nil {
		t.Fatalf("save user session failed: %v", err)
	}

	loaded, err := credential.LoadUserSession(stateDir)
	if err != nil {
		t.Fatalf("load user session failed: %v", err)
	}
	if loaded.Server != sess.Server || loaded.Email != sess.Email || loaded.AccessToken != sess.AccessToken {
		t.Fatalf("unexpected loaded session: %+v", loaded)
	}

	if err := credential.DeleteUserSession(stateDir); err != nil {
		t.Fatalf("delete user session failed: %v", err)
	}

	_, err = credential.LoadUserSession(stateDir)
	if err == nil {
		t.Fatal("expected ErrNotFound after deletion")
	}
}
