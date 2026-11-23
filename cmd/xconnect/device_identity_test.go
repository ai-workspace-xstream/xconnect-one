package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

var (
	validEnrollmentDeviceIDRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	expectedFormatRegex          = regexp.MustCompile(`^xconnect-[a-z0-9-]+-[0-9a-f]{8}$`)
)

func TestResolveOrCreateDeviceID_GlobalSystemPersistenceAndFormat(t *testing.T) {
	sysDir := t.TempDir()
	sysPath := filepath.Join(sysDir, "device-id")
	t.Setenv("XCONNECT_SYSTEM_DEVICE_ID_PATH", sysPath)

	stateDir := t.TempDir()

	id1 := resolveOrCreateDeviceID(stateDir, "", false)
	if !validEnrollmentDeviceIDRegex.MatchString(id1) {
		t.Fatalf("generated device ID %q does not match enrollment pattern", id1)
	}
	if !expectedFormatRegex.MatchString(id1) {
		t.Fatalf("generated device ID %q does not match expected xconnect-<os>-<host>-<8hex> format", id1)
	}

	// Verify it was immediately persisted to /etc/xconnect-one/device-id (simulated by sysPath).
	rawSys, err := os.ReadFile(sysPath)
	if err != nil {
		t.Fatalf("expected global device-id file at %s: %v", sysPath, err)
	}
	if strings.TrimSpace(string(rawSys)) != id1 {
		t.Fatalf("global device-id file has %q, want %q", strings.TrimSpace(string(rawSys)), id1)
	}

	// Subsequent calls reuse the global /etc/xconnect-one/device-id.
	id2 := resolveOrCreateDeviceID(stateDir, "", false)
	if id1 != id2 {
		t.Fatalf("expected persisted global device ID %q on repeat lookup, got %q", id1, id2)
	}
}

func TestResolveOrCreateDeviceID_DeletingGlobalFileOrRegeneratingYieldsNewDeviceID(t *testing.T) {
	sysDir := t.TempDir()
	sysPath := filepath.Join(sysDir, "device-id")
	t.Setenv("XCONNECT_SYSTEM_DEVICE_ID_PATH", sysPath)

	stateDir := t.TempDir()

	id1 := resolveOrCreateDeviceID(stateDir, "", false)
	stStore := state.NewStore(stateDir)
	_, pub1, err := ensureWireGuardKeyPair(stStore)
	if err != nil {
		t.Fatalf("ensureWireGuardKeyPair: %v", err)
	}

	// Removing /etc/xconnect-one/device-id when stateDir already had a device
	// rotates the WireGuard keypair and produces a brand-new device_id.
	if err := os.Remove(sysPath); err != nil {
		t.Fatalf("remove global device-id: %v", err)
	}

	id2 := resolveOrCreateDeviceID(stateDir, "", false)
	if id2 == id1 {
		t.Fatalf("expected brand-new device_id after removing global device-id file, both were %q", id1)
	}
	_, pub2, err := ensureWireGuardKeyPair(stStore)
	if err != nil {
		t.Fatalf("ensureWireGuardKeyPair after removal: %v", err)
	}
	if pub1 == pub2 {
		t.Fatalf("expected WireGuard public key to rotate when regenerating brand-new device_id")
	}

	// Explicit RegenerateDeviceID also produces a brand-new device_id and updates global file.
	id3, err := RegenerateDeviceID(stateDir)
	if err != nil {
		t.Fatalf("RegenerateDeviceID: %v", err)
	}
	if id3 == id2 || id3 == id1 {
		t.Fatalf("expected RegenerateDeviceID to produce a new ID, got %q (prev %q, %q)", id3, id2, id1)
	}
	rawSys, err := os.ReadFile(sysPath)
	if err != nil {
		t.Fatalf("read global device-id: %v", err)
	}
	if strings.TrimSpace(string(rawSys)) != id3 {
		t.Fatalf("global device-id file not updated after RegenerateDeviceID: got %q, want %q", strings.TrimSpace(string(rawSys)), id3)
	}
}

func TestResolveOrCreateDeviceID_ExplicitFlagOverridesAndPersistsGlobal(t *testing.T) {
	sysDir := t.TempDir()
	sysPath := filepath.Join(sysDir, "device-id")
	t.Setenv("XCONNECT_SYSTEM_DEVICE_ID_PATH", sysPath)

	dir := t.TempDir()
	_ = resolveOrCreateDeviceID(dir, "", false)

	explicit := resolveOrCreateDeviceID(dir, "custom-device-01", true)
	if explicit != "custom-device-01" {
		t.Fatalf("expected explicit --device-id 'custom-device-01', got %q", explicit)
	}
	if got := loadSystemDeviceID(); got != "custom-device-01" {
		t.Fatalf("expected global device-id to be updated to 'custom-device-01', got %q", got)
	}
}
