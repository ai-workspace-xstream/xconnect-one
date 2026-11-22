package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestDesktopRecoversMissingWireGuardWithOwnedXray(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex = 0
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if len(backend.stops) != 1 || len(backend.starts) != 2 {
		t.Fatalf("stops=%v starts=%v", backend.stops, backend.starts)
	}
	status, err := runtime.Status(t.Context())
	if err != nil || !status.Applied {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestDesktopMissingWireGuardStillRejectsUnownedXray(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	active, err := runtime.loadManifest(runtime.activeManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex = 0
	backend.stale[active.Xray.PID] = true
	_, err = runtime.Apply(t.Context(), request)
	if fault.Code(err) != fault.CodeRuntimeProcessStale || len(backend.stops) != 0 {
		t.Fatalf("err=%v stops=%v", err, backend.stops)
	}
}

func TestDesktopRejectsReplacedWireGuardInterface(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex++
	_, err := runtime.Apply(t.Context(), request)
	if fault.Code(err) != fault.CodeRuntimeProcessStale || len(backend.stops) != 0 {
		t.Fatalf("err=%v stops=%v", err, backend.stops)
	}
}

type reclaimableFakeBackend struct {
	*fakeDesktopBackend
	livePublicKey string
	reclaimed     []string
	stats         WireGuardStats
	nudges        []string
}

func (r *reclaimableFakeBackend) WireGuardPublicKey(_ context.Context, _ string, _ string) (string, error) {
	return r.livePublicKey, nil
}

func (r *reclaimableFakeBackend) ReclaimWireGuardInterface(_ context.Context, logicalName string) error {
	r.reclaimed = append(r.reclaimed, logicalName)
	r.interfaceIndex = 0
	return nil
}

func (r *reclaimableFakeBackend) WireGuardPeerStats(_ context.Context, _ string, _ string) (WireGuardStats, error) {
	return r.stats, nil
}

func (r *reclaimableFakeBackend) NudgeWireGuardPeer(_ context.Context, _, logicalName, peerPublicKey, endpoint string) error {
	r.nudges = append(r.nudges, logicalName+":"+peerPublicKey+"@"+endpoint)
	return nil
}

func TestDesktopReclaimsOrphanInterfaceOnlyWhenPublicKeyMatches(t *testing.T) {
	request := desktopApplyRequest("revision-reclaim")
	expectedPubKey, err := deriveWireGuardPublicKey(request.WireGuardPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	// Mismatched public key must NOT reclaim an unrelated interface.
	mismatchBackend := &reclaimableFakeBackend{
		fakeDesktopBackend: newFakeDesktopBackend(),
		livePublicKey:      "unrelated-public-key=",
	}
	mismatchBackend.interfaceIndex = 77
	mismatchRuntime := newDesktop(t.TempDir(), mismatchBackend)
	if _, err := mismatchRuntime.Apply(t.Context(), request); fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("expected apply refusal on foreign interface, got err=%v", err)
	}
	if len(mismatchBackend.reclaimed) != 0 || mismatchBackend.interfaceIndex != 77 {
		t.Fatalf("foreign interface was touched: reclaimed=%v index=%d", mismatchBackend.reclaimed, mismatchBackend.interfaceIndex)
	}

	// Matching public key proves our own orphan interface -> cleanly reclaims and brings up tunnel.
	ownedBackend := &reclaimableFakeBackend{
		fakeDesktopBackend: newFakeDesktopBackend(),
		livePublicKey:      expectedPubKey,
	}
	ownedBackend.interfaceIndex = 77
	ownedRuntime := newDesktop(t.TempDir(), ownedBackend)
	if _, err := ownedRuntime.Apply(t.Context(), request); err != nil {
		t.Fatalf("expected clean reclaim and apply on matching key, got %v", err)
	}
	if len(ownedBackend.reclaimed) != 1 || ownedBackend.reclaimed[0] != request.Config.WireGuard.Interface {
		t.Fatalf("reclaimed=%v want [%s]", ownedBackend.reclaimed, request.Config.WireGuard.Interface)
	}
}

func TestDesktopRestartTransportKeepsInterfaceAndNudgesPeer(t *testing.T) {
	backend := &reclaimableFakeBackend{
		fakeDesktopBackend: newFakeDesktopBackend(),
		stats: WireGuardStats{
			LatestHandshake: time.Now().UTC().Add(-10 * time.Second),
			RxBytes:         1024,
			TxBytes:         2048,
		},
	}
	tunnel := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-restart")
	if _, err := tunnel.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	initialRuns := len(backend.runs)

	health, err := tunnel.DataPlaneHealth(t.Context())
	if err != nil || !health.Applied || !health.HasStats || health.TxBytes != 2048 {
		t.Fatalf("health=%+v err=%v", health, err)
	}

	if err := tunnel.RestartTransport(t.Context()); err != nil {
		t.Fatalf("RestartTransport failed: %v", err)
	}
	if len(backend.stops) != 1 || len(backend.starts) != 2 {
		t.Fatalf("expected Xray stop+restart without touching wg-quick: stops=%v starts=%v", backend.stops, backend.starts)
	}
	if len(backend.runs) != initialRuns {
		t.Fatalf("RestartTransport unexpectedly invoked wg-quick: new runs=%v", backend.runs[initialRuns:])
	}
	if len(backend.nudges) != 1 {
		t.Fatalf("expected peer nudge after transport restart, got %v", backend.nudges)
	}
}
