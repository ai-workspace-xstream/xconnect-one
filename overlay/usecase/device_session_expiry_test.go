package usecase_test

import (
	"context"
	"errors"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
	"testing"
	"time"
)

type expiredOnceControlPlane struct {
	*inviteControlPlaneFixture
	expired bool
}

func (f *expiredOnceControlPlane) GetEnrollmentSignedConfig(ctx context.Context, token string, request controlplane.SignedConfigRequest) (signedconfig.Config, error) {
	if !f.expired {
		f.expired = true
		return signedconfig.Config{}, fault.New(fault.CodeEnrollmentExpired, "use enrollment session", nil)
	}
	return f.inviteControlPlaneFixture.GetEnrollmentSignedConfig(ctx, token, request)
}

func TestExpiredSessionClearedAndRemintedWithoutLosingDeviceCredential(t *testing.T) {
	base := newInviteControlPlaneFixture(t)
	controlPlane := &expiredOnceControlPlane{inviteControlPlaneFixture: base}
	now := base.config.IssuedAt.Time.Add(time.Minute)
	store := state.NewStore(t.TempDir())
	if err := store.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	original := durableRecord(t, base.keys, now)
	if err := credentials.Save(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	runtime := &overlayruntime.Fake{}
	manager := usecase.NewDeviceSessionManager(controlPlane, store, credentials, runtime).WithClock(func() time.Time { return now })
	if _, err := manager.Sync(t.Context()); fault.Code(err) != fault.CodeEnrollmentExpired {
		t.Fatalf("err=%v", err)
	}
	if _, err := store.LoadEnrollmentSecret(original.Controller, original.DeviceID, original.WireGuardPublicKey); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expired session retained: %v", err)
	}
	if _, err := manager.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if base.deviceSessionCalls != 2 || runtime.ApplyCalls != 1 {
		t.Fatalf("mint=%d apply=%d", base.deviceSessionCalls, runtime.ApplyCalls)
	}
	retained, err := credentials.Load(t.Context())
	if err != nil || retained.Credential != original.Credential {
		t.Fatal("durable credential changed")
	}
}
