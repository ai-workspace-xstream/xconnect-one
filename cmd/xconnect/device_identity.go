package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

const (
	deviceIDFileName   = "device-id"
	wireGuardKeysFile  = "wireguard-keypair.json"
	systemDeviceIDPath = "/etc/xconnect-one/device-id"
)

type persistedWireGuardKeyPair struct {
	PrivateKey string `json:"wireguard_private_key"`
	PublicKey  string `json:"wireguard_public_key"`
}

// resolveOrCreateDeviceID returns a deterministic, collision-free device ID for
// the machine, using `/etc/xconnect-one/device-id` as the global source of truth.
//
// Resolution & Regeneration semantics:
//  1. If explicitFlag is true (`--device-id <id>`), use the requested ID and
//     persist it to `/etc/xconnect-one/device-id` (and `<stateDirectory>/device-id`).
//  2. If `/etc/xconnect-one/device-id` exists:
//     use it as the authoritative global device ID. If `<stateDirectory>` had
//     an older/different `device_id` in LastKnown/Checkpoint, sync the state dir
//     to the new global ID.
//  3. If `/etc/xconnect-one/device-id` does NOT exist:
//     - If `/etc/xconnect-one` (or custom system device-id parent dir) was
//     present or the user deleted `/etc/xconnect-one/device-id` to regenerate
//     a brand-new identity, generate a new device ID from:
//     OS Machine ID + First Physical NIC MAC + Local WireGuard Public Key
//     (rotating the local WireGuard keypair if a previous state existed so the
//     new device_id registers cleanly without a public-key conflict on the
//     control plane), and immediately persist it to `/etc/xconnect-one/device-id`.
func resolveOrCreateDeviceID(stateDirectory, requestedDeviceID string, explicitFlag bool) string {
	trimmedRequested := strings.TrimSpace(requestedDeviceID)
	stateDirectory = strings.TrimSpace(stateDirectory)
	var dirExisted bool
	if stateDirectory != "" {
		if info, err := os.Stat(stateDirectory); err == nil && info.IsDir() {
			dirExisted = true
		}
	}

	if explicitFlag && trimmedRequested != "" {
		_ = trySaveSystemDeviceID(trimmedRequested)
		if stateDirectory != "" && dirExisted {
			_ = savePersistedDeviceIDToStateDir(stateDirectory, trimmedRequested)
		}
		return trimmedRequested
	}

	// 1. Global /etc/xconnect-one/device-id is the primary source of truth.
	if sysID := loadSystemDeviceID(); sysID != "" {
		if stateDirectory != "" && dirExisted {
			_ = savePersistedDeviceIDToStateDir(stateDirectory, sysID)
		}
		return sysID
	}

	// 2. If /etc/xconnect-one/device-id is missing:
	// Check if system path is configured/accessible vs unprivileged fallback.
	// When /etc/xconnect-one/device-id is missing (first run, or deleted to
	// regenerate a brand-new device_id), check if we can write to the system path.
	canWriteSys := canUseSystemDeviceIDPath()

	// If not writable by current unprivileged user and no custom override is set,
	// fall back to stateDirectory/device-id if present.
	if !canWriteSys && stateDirectory != "" {
		if persisted := loadPersistedDeviceIDFromStateDir(stateDirectory); persisted != "" {
			return persisted
		}
		stStore := state.NewStore(stateDirectory)
		if lk, err := stStore.LoadLastKnown(); err == nil && isValidDeviceID(lk.DeviceID) {
			if dirExisted {
				_ = savePersistedDeviceIDToStateDir(stateDirectory, lk.DeviceID)
			}
			return lk.DeviceID
		}
		if cp, err := stStore.LoadCheckpoint(); err == nil && isValidDeviceID(cp.DeviceID) {
			if dirExisted {
				_ = savePersistedDeviceIDToStateDir(stateDirectory, cp.DeviceID)
			}
			return cp.DeviceID
		}
	}

	// 3. Brand-new machine first run OR /etc/xconnect-one/device-id was removed to
	// force regenerating a brand-new device_id.
	// If stateDirectory previously had a different device_id, rotate the local
	// WireGuard keypair so the newly generated device_id gets a fresh keypair and
	// never triggers a WireGuard public-key 409 conflict on the control plane.
	var wgPubKey string
	if stateDirectory != "" {
		stStore := state.NewStore(stateDirectory)
		hadPriorDevice := hasPriorEnrolledDevice(stateDirectory, stStore)
		if hadPriorDevice && canWriteSys {
			if _, pub, err := rotateWireGuardKeyPair(stStore, dirExisted); err == nil {
				wgPubKey = pub
			}
		} else {
			if _, pub, err := ensureWireGuardKeyPairWithPersistence(stStore, dirExisted); err == nil {
				wgPubKey = pub
			}
		}
	}
	if wgPubKey == "" {
		if _, pub, err := usecase.GenerateWireGuardKeyPair(); err == nil {
			wgPubKey = pub
		}
	}

	generated := generateUniqueDeviceIDWithPublicKey(wgPubKey)
	_ = trySaveSystemDeviceID(generated)
	if stateDirectory != "" && dirExisted {
		_ = savePersistedDeviceIDToStateDir(stateDirectory, generated)
	}
	return generated
}

// RegenerateDeviceID forces generating a brand-new WireGuard keypair and a new
// device ID (`xconnect-<os>-<hostname>-<8hex>`), persisting it immediately to
// `/etc/xconnect-one/device-id` and `<stateDirectory>/device-id`.
func RegenerateDeviceID(stateDirectory string) (string, error) {
	stateDirectory = strings.TrimSpace(stateDirectory)
	var dirExisted bool
	if stateDirectory != "" {
		if info, err := os.Stat(stateDirectory); err == nil && info.IsDir() {
			dirExisted = true
		}
	}
	var wgPubKey string
	if stateDirectory != "" {
		stStore := state.NewStore(stateDirectory)
		if _, pub, err := rotateWireGuardKeyPair(stStore, dirExisted); err == nil {
			wgPubKey = pub
		}
	}
	if wgPubKey == "" {
		_, pub, err := usecase.GenerateWireGuardKeyPair()
		if err != nil {
			return "", err
		}
		wgPubKey = pub
	}
	// Mix fresh CSPRNG salt into regeneration so even on the exact same machine
	// regenerating always yields a brand-new 8-hex suffix.
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	generated := generateUniqueDeviceIDWithPublicKey(wgPubKey + ":" + hex.EncodeToString(salt))
	_ = trySaveSystemDeviceID(generated)
	if stateDirectory != "" && dirExisted {
		_ = savePersistedDeviceIDToStateDir(stateDirectory, generated)
	}
	return generated, nil
}

func hasPriorEnrolledDevice(stateDirectory string, stStore *state.Store) bool {
	if loadPersistedDeviceIDFromStateDir(stateDirectory) != "" {
		return true
	}
	if stStore != nil {
		if lk, err := stStore.LoadLastKnown(); err == nil && lk.DeviceID != "" {
			return true
		}
		if cp, err := stStore.LoadCheckpoint(); err == nil && cp.DeviceID != "" {
			return true
		}
	}
	return false
}

func rotateWireGuardKeyPair(stStore *state.Store, persist bool) (string, string, error) {
	priv, pub, err := usecase.GenerateWireGuardKeyPair()
	if err != nil {
		return "", "", err
	}
	if persist && stStore != nil {
		if dir := strings.TrimSpace(stStore.Directory()); dir != "" {
			_ = savePersistedWireGuardKeyPair(dir, priv, pub)
		}
	}
	return priv, pub, nil
}

func defaultDeviceID() string {
	return resolveOrCreateDeviceID(defaultStateDirectory(), "", false)
}

func ensureWireGuardKeyPair(stStore *state.Store) (string, string, error) {
	return ensureWireGuardKeyPairWithPersistence(stStore, true)
}

func ensureWireGuardKeyPairWithPersistence(stStore *state.Store, persistIfMissing bool) (string, string, error) {
	if stStore != nil {
		if dir := strings.TrimSpace(stStore.Directory()); dir != "" {
			if priv, pub := loadPersistedWireGuardKeyPair(dir); priv != "" && pub != "" {
				return priv, pub, nil
			}
		}
		if lk, err := stStore.LoadLastKnown(); err == nil && lk.WireGuardPrivateKey != "" && lk.WireGuardPublicKey != "" {
			return lk.WireGuardPrivateKey, lk.WireGuardPublicKey, nil
		}
		if cp, err := stStore.LoadCheckpoint(); err == nil && cp.WireGuardPrivateKey != "" && cp.WireGuardPublicKey != "" {
			return cp.WireGuardPrivateKey, cp.WireGuardPublicKey, nil
		}
	}
	priv, pub, err := usecase.GenerateWireGuardKeyPair()
	if err != nil {
		return "", "", err
	}
	if persistIfMissing && stStore != nil {
		if dir := strings.TrimSpace(stStore.Directory()); dir != "" {
			_ = savePersistedWireGuardKeyPair(dir, priv, pub)
		}
	}
	return priv, pub, nil
}

func loadPersistedWireGuardKeyPair(stateDirectory string) (string, string) {
	raw, err := os.ReadFile(filepath.Join(stateDirectory, wireGuardKeysFile))
	if err != nil {
		return "", ""
	}
	var kp persistedWireGuardKeyPair
	if err := json.Unmarshal(raw, &kp); err != nil {
		return "", ""
	}
	return strings.TrimSpace(kp.PrivateKey), strings.TrimSpace(kp.PublicKey)
}

func savePersistedWireGuardKeyPair(stateDirectory, privKey, pubKey string) error {
	if stateDirectory == "" || privKey == "" || pubKey == "" {
		return nil
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(persistedWireGuardKeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDirectory, wireGuardKeysFile), append(raw, '\n'), 0o600)
}

func generateUniqueDeviceIDWithPublicKey(wgPubKey string) string {
	hostPart := sanitizeDeviceIDSegment(shortHostname(), 32)
	prefix := "xconnect-" + sanitizeDeviceIDSegment(runtime.GOOS, 16)
	if hostPart != "" {
		prefix += "-" + hostPart
	}
	suffix := computeUniqueDeviceFingerprint(wgPubKey)
	candidate := fmt.Sprintf("%s-%s", prefix, suffix)
	if len(candidate) > 128 {
		candidate = candidate[:128]
	}
	return strings.Trim(candidate, "-.")
}

func shortHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	hostname = strings.TrimSpace(hostname)
	if idx := strings.IndexByte(hostname, '.'); idx > 0 {
		hostname = hostname[:idx]
	}
	return hostname
}

func sanitizeDeviceIDSegment(raw string, maxLen int) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	lastHyphen := false
	for _, ch := range raw {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
			lastHyphen = false
		} else if !lastHyphen && b.Len() > 0 {
			b.WriteByte('-')
			lastHyphen = true
		}
		if maxLen > 0 && b.Len() >= maxLen {
			break
		}
	}
	return strings.Trim(b.String(), "-.")
}

// computeUniqueDeviceFingerprint derives an 8-hex-char fingerprint from:
// 1. OS Machine ID (/etc/machine-id, /var/lib/dbus/machine-id, /etc/hostid)
// 2. First physical network interface MAC address
// 3. Local WireGuard public key
func computeUniqueDeviceFingerprint(wgPubKey string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("xconnect-device-id-v1\x00"))
	_, _ = h.Write([]byte("machine-id:" + readOSMachineID() + "\x00"))
	_, _ = h.Write([]byte("primary-mac:" + firstPhysicalMAC() + "\x00"))
	if strings.TrimSpace(wgPubKey) != "" {
		_, _ = h.Write([]byte("wg-pub:" + strings.TrimSpace(wgPubKey) + "\x00"))
	} else {
		entropy := make([]byte, 16)
		_, _ = rand.Read(entropy)
		_, _ = h.Write(entropy)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:4]) // 8 hex characters (e.g. 8f3a1c9d)
}

func readOSMachineID() string {
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/etc/hostid",
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err == nil {
			if id := strings.TrimSpace(string(raw)); id != "" {
				return id
			}
		}
	}
	return ""
}

func firstPhysicalMAC() string {
	macs := collectPhysicalMACs()
	if len(macs) == 0 {
		return ""
	}
	return macs[0]
}

func collectPhysicalMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Index < ifaces[j].Index
	})
	var macs []string
	seen := make(map[string]bool)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) < 6 {
			continue
		}
		if isVirtualInterfaceName(iface.Name) {
			continue
		}
		mac := strings.ToLower(iface.HardwareAddr.String())
		if mac == "" || mac == "00:00:00:00:00:00" || seen[mac] {
			continue
		}
		seen[mac] = true
		macs = append(macs, mac)
	}
	return macs
}

func isVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	prefixes := []string{
		"lo", "utun", "tun", "tap", "wg", "xcon", "docker", "veth",
		"br-", "virbr", "vmnet", "vboxnet", "tailscale", "zt", "flannel", "cni",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isValidDeviceID(id string) bool {
	id = strings.TrimSpace(id)
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i, ch := range id {
		validChar := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'
		if !validChar {
			return false
		}
		if i == 0 && !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func resolveSystemDeviceIDPath() string {
	if override := strings.TrimSpace(os.Getenv("XCONNECT_SYSTEM_DEVICE_ID_PATH")); override != "" {
		return override
	}
	return systemDeviceIDPath
}

func canUseSystemDeviceIDPath() bool {
	if strings.TrimSpace(os.Getenv("XCONNECT_SYSTEM_DEVICE_ID_PATH")) != "" {
		return true
	}
	if os.Geteuid() == 0 {
		return true
	}
	path := resolveSystemDeviceIDPath()
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		testFile := filepath.Join(dir, ".xconnect-write-check")
		if f, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
			_ = f.Close()
			_ = os.Remove(testFile)
			return true
		}
	}
	return false
}

func loadSystemDeviceID() string {
	path := resolveSystemDeviceIDPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(raw))
	if !isValidDeviceID(id) {
		return ""
	}
	return id
}

func trySaveSystemDeviceID(deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if !isValidDeviceID(deviceID) {
		return nil
	}
	path := resolveSystemDeviceIDPath()
	if existing, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(existing)) == deviceID {
			return nil
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(deviceID+"\n"), 0o644)
}

func loadPersistedDeviceIDFromStateDir(stateDirectory string) string {
	path := filepath.Join(stateDirectory, deviceIDFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(raw))
	if !isValidDeviceID(id) {
		return ""
	}
	return id
}

func savePersistedDeviceIDToStateDir(stateDirectory, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if stateDirectory == "" || !isValidDeviceID(deviceID) {
		return nil
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(stateDirectory, deviceIDFileName)
	return os.WriteFile(path, []byte(deviceID+"\n"), 0o600)
}
