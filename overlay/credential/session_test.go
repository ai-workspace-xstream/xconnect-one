package credential_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
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

func TestSaveUserSessionReadOnlyAndUnwritableDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission modes do not restrict directory creation on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission bits")
	}

	sess := credential.UserSession{
		Server:      "https://accounts.svc.plus",
		Email:       "alice@example.test",
		AccessToken: "test-token-12345",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}

	t.Run("read-only state directory", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "ro-state")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stateDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

		if reason := credential.CheckStateDirectoryUsability(stateDir); reason == "" {
			t.Fatal("expected usability check to report non-writable directory")
		}
		if err := credential.EnsureWritableStateDir(stateDir); fault.Code(err) != fault.CodeCredentialStorage {
			t.Fatalf("expected CodeCredentialStorage from EnsureWritableStateDir, got %v", err)
		}

		err := credential.SaveUserSession(stateDir, sess)
		if err == nil {
			t.Fatal("expected permission error saving session into read-only stateDir")
		}
		if fault.Code(err) != fault.CodeCredentialStorage {
			t.Fatalf("unexpected fault code %q: %v", fault.Code(err), err)
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("expected wrapped os.ErrPermission, got %v", err)
		}
		if !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "--state-dir") {
			t.Fatalf("expected actionable permission denied guidance, got: %s", err.Error())
		}
	})

	t.Run("read-only protected subdirectory", func(t *testing.T) {
		stateDir := t.TempDir()
		protectedDir := filepath.Join(stateDir, "protected")
		if err := os.MkdirAll(protectedDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(protectedDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(protectedDir, 0o700) })

		err := credential.SaveUserSession(stateDir, sess)
		if err == nil {
			t.Fatal("expected permission error saving session into read-only protected dir")
		}
		if fault.Code(err) != fault.CodeCredentialStorage {
			t.Fatalf("unexpected fault code %q: %v", fault.Code(err), err)
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("expected wrapped os.ErrPermission, got %v", err)
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("expected permission denied message, got: %s", err.Error())
		}
	})

	t.Run("inaccessible state directory on load", func(t *testing.T) {
		stateDir := t.TempDir()
		protectedDir := filepath.Join(stateDir, "protected")
		if err := os.MkdirAll(protectedDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(protectedDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(protectedDir, 0o700) })

		_, err := credential.LoadUserSession(stateDir)
		if err == nil {
			t.Fatal("expected permission error on LoadUserSession")
		}
		if errors.Is(err, credential.ErrNotFound) {
			t.Fatalf("expected storage permission error instead of ErrNotFound: %v", err)
		}
		if fault.Code(err) != fault.CodeCredentialStorage {
			t.Fatalf("unexpected fault code %q: %v", fault.Code(err), err)
		}
	})
}
