package usecase_test

import (
	"context"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
	"testing"
	"time"
)

func TestSyncLoopRetriesExpiredSessionWithoutExiting(t *testing.T) {
	clock := newFakeLoopClock(time.Now())
	clock.Tick()
	clock.Tick()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	loop := usecase.SyncLoop{Clock: clock, Sync: func(context.Context) (usecase.SyncResult, error) {
		calls++
		if calls == 1 {
			return usecase.SyncResult{}, fault.New(fault.CodeEnrollmentExpired, "use enrollment session", nil)
		}
		cancel()
		return usecase.SyncResult{}, nil
	}}
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}
