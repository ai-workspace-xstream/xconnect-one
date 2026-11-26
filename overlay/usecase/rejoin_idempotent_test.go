package usecase_test

import (
	"os"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

func TestJoinWithFreshInviteRejoinsAlreadyBoundDevicePreservingKeyAndClearingStaleState(t *testing.T) {
	controlPlane := newInviteControlPlaneFixture(t)
	now := controlPlane.config.IssuedAt.Time.Add(time.Minute)
	stateStore := state.NewStore(t.TempDir())
	lastKnown := lifecycleLastKnown()
	if err := stateStore.SaveLastKnown(lastKnown); err != nil {
		t.Fatal(err)
	}
	// Seed stale policy floor and signing-key cache as would remain after a control-plane restart.
	if err := os.WriteFile(stateStore.PolicyStatePath(), []byte(`{"generation":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateStore.SigningKeyCachePath(), []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	credentials := &credential.MemoryStore{}
	runtimeFake := &overlayruntime.Fake{}
	joiner := usecase.NewJoiner(controlPlane, stateStore, runtimeFake).
		WithCredentialStore(credentials).
		WithConfigContract(usecase.ConfigContractSigned).
		WithClock(func() time.Time { return now })

	result, err := joiner.Join(t.Context(), usecase.JoinRequest{
		Server:     lastKnown.Server,
		DeviceID:   lastKnown.DeviceID,
		DeviceName: "MacBook Pro",
		Platform:   "darwin",
		Hostname:   "macbook.local",
		NetworkID:  lastKnown.NetworkID,
		JoinToken:  "xjt_fresh_rejoin_token_1234567890",
	})
	if err != nil {
		t.Fatalf("re-join with fresh invite failed: %v", err)
	}
	if result.AlreadyJoined {
		t.Fatalf("expected fresh invite re-join to execute exchange, got AlreadyJoined=true")
	}
	if controlPlane.exchangeCalls != 1 {
		t.Fatalf("expected exactly 1 ExchangeJoinToken call, got %d", controlPlane.exchangeCalls)
	}
	savedCred, err := credentials.Load(t.Context())
	if err != nil {
		t.Fatalf("load refreshed credential: %v", err)
	}
	if savedCred.DeviceID != lastKnown.DeviceID || savedCred.WireGuardPublicKey != lastKnown.WireGuardPublicKey {
		t.Fatalf("unexpected saved credential after re-join: %#v", savedCred)
	}
	updatedLastKnown, err := stateStore.LoadLastKnown()
	if err != nil {
		t.Fatalf("load updated lastKnown: %v", err)
	}
	if updatedLastKnown.WireGuardPublicKey != lastKnown.WireGuardPublicKey || updatedLastKnown.WireGuardPrivateKey != lastKnown.WireGuardPrivateKey {
		t.Fatalf("expected WireGuard keypair preserved across re-join")
	}
	if _, err := os.Stat(stateStore.PolicyStatePath()); !os.IsNotExist(err) {
		t.Fatalf("expected stale policy-state.json cleared on re-join, stat err=%v", err)
	}
}
