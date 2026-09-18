package usecase_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

// fakeLoopClock allows deterministic control over timer ticks in sync loop tests.
type fakeLoopClock struct {
	now       time.Time
	afterChan chan time.Time
	afterDurs []time.Duration
}

func newFakeLoopClock(start time.Time) *fakeLoopClock {
	return &fakeLoopClock{
		now:       start,
		afterChan: make(chan time.Time, 10),
	}
}

func (c *fakeLoopClock) Now() time.Time {
	return c.now
}

func (c *fakeLoopClock) After(d time.Duration) <-chan time.Time {
	c.afterDurs = append(c.afterDurs, d)
	return c.afterChan
}

func (c *fakeLoopClock) Tick() {
	c.afterChan <- c.now
}

// 1. 每个 tick 恰好调用一次 Sync；配置未变化时也要发 ACK。
func TestSyncLoopTicksPeriodicallyAndAcksEveryTick(t *testing.T) {
	clock := newFakeLoopClock(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	var syncCalls int32

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	loop := &usecase.SyncLoop{
		Interval: 60 * time.Second,
		Clock:    clock,
		Sync: func(ctx context.Context) (usecase.SyncResult, error) {
			count := atomic.AddInt32(&syncCalls, 1)
			if count == 2 {
				cancel() // exit after 2 ticks
			}
			return usecase.SyncResult{
				DeviceID:       "dev_laptop",
				NetworkID:      "net_uat",
				Generation:     10,
				AlreadyCurrent: count > 1, // Second tick has unchanged generation
			}, nil
		},
	}

	// First tick triggers after loop starts and clock ticks
	go func() {
		clock.Tick() // first tick
		clock.Tick() // second tick
	}()

	err := loop.Run(ctx)
	if err != nil {
		t.Fatalf("expected nil error on ctx cancel, got %v", err)
	}
	if calls := atomic.LoadInt32(&syncCalls); calls != 2 {
		t.Fatalf("expected exactly 2 sync calls, got %d", calls)
	}
}

// 2. 收到 409 (ErrGenerationConflict) 时在同一 tick 内立即重新拉取并应用一次，最多重试 1 次。
func TestSyncLoopRetriesOnceOnConflict(t *testing.T) {
	clock := newFakeLoopClock(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	var attempts int32

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	conflictErr := fault.New(fault.CodeStateConflict, "generation conflict HTTP 409", nil)

	loop := &usecase.SyncLoop{
		Interval: 60 * time.Second,
		Clock:    clock,
		Sync: func(ctx context.Context) (usecase.SyncResult, error) {
			count := atomic.AddInt32(&attempts, 1)
			if count == 1 {
				return usecase.SyncResult{}, conflictErr
			}
			// Second attempt in same tick succeeds
			cancel()
			return usecase.SyncResult{DeviceID: "dev_laptop", NetworkID: "net_uat", Generation: 11}, nil
		},
	}

	go func() {
		clock.Tick()
	}()

	err := loop.Run(ctx)
	if err != nil {
		t.Fatalf("expected nil on cancel after successful retry, got %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts within the same tick on conflict, got %d", got)
	}
}

// 3. 网络错误、5xx、429 按 5s/10s/20s 退避，上限为 interval；不拆隧道（不能调用 Down）。
func TestSyncLoopBacksOffOnTransientErrorsWithoutTearingDownTunnel(t *testing.T) {
	clock := newFakeLoopClock(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	fakeRuntime := &overlayruntime.Fake{}
	var transientCalls int32

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	transientErr := fault.New(fault.CodeControlPlaneUnavailable, "network timeout or 503", nil)

	loop := &usecase.SyncLoop{
		Interval: 60 * time.Second,
		Clock:    clock,
		Runtime:  fakeRuntime,
		Sync: func(ctx context.Context) (usecase.SyncResult, error) {
			count := atomic.AddInt32(&transientCalls, 1)
			if count == 3 {
				cancel()
			}
			return usecase.SyncResult{}, transientErr
		},
	}

	go func() {
		// Deliver ticks after each backoff
		for i := 0; i < 3; i++ {
			clock.Tick()
		}
	}()

	_ = loop.Run(ctx)

	if fakeRuntime.DownCalls != 0 {
		t.Fatalf("expected 0 Down calls during transient failures, got %d", fakeRuntime.DownCalls)
	}

	// Verify backoff sequence: 5s, 10s, 20s
	expectedBackoffs := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
	for i, expected := range expectedBackoffs {
		if i >= len(clock.afterDurs) {
			t.Fatalf("expected at least %d backoff after calls, got %d", len(expectedBackoffs), len(clock.afterDurs))
		}
		if clock.afterDurs[i] != expected {
			t.Errorf("backoff[%d]: expected %v, got %v", i, expected, clock.afterDurs[i])
		}
	}
}

// 4. 401 或吊销时以对应的 fault code 非 0 退出，不主动拆除隧道。
func TestSyncLoopExitsFatalOnAuthenticationOrRevocation(t *testing.T) {
	clock := newFakeLoopClock(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	fakeRuntime := &overlayruntime.Fake{}

	authErr := fault.New(fault.CodeAuthenticationFailed, "device revoked or unauthorized HTTP 401", nil)

	loop := &usecase.SyncLoop{
		Interval: 60 * time.Second,
		Clock:    clock,
		Runtime:  fakeRuntime,
		Sync: func(ctx context.Context) (usecase.SyncResult, error) {
			return usecase.SyncResult{}, authErr
		},
	}

	go func() {
		clock.Tick()
	}()

	err := loop.Run(t.Context())
	if err == nil {
		t.Fatal("expected fatal error, got nil")
	}
	if code := fault.Code(err); code != fault.CodeAuthenticationFailed {
		t.Fatalf("expected fault code %s, got %s", fault.CodeAuthenticationFailed, code)
	}
	if fakeRuntime.DownCalls != 0 {
		t.Fatalf("fatal exit must not teardown tunnel: got %d Down calls", fakeRuntime.DownCalls)
	}
}

// 5. ctx 取消（SIGTERM）后 1 秒内返回 nil，不拆隧道。
func TestSyncLoopReturnsCleanOnContextCancellation(t *testing.T) {
	clock := newFakeLoopClock(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	fakeRuntime := &overlayruntime.Fake{}

	ctx, cancel := context.WithCancel(t.Context())

	loop := &usecase.SyncLoop{
		Interval: 60 * time.Second,
		Clock:    clock,
		Runtime:  fakeRuntime,
		Sync: func(ctx context.Context) (usecase.SyncResult, error) {
			return usecase.SyncResult{DeviceID: "dev_laptop", NetworkID: "net_uat", Generation: 10}, nil
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx)
	}()

	// Cancel context immediately
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected nil on context cancellation, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("SyncLoop.Run did not exit within 1 second after context cancellation")
	}

	if fakeRuntime.DownCalls != 0 {
		t.Fatalf("context cancel must not teardown tunnel: got %d Down calls", fakeRuntime.DownCalls)
	}
}

// 6. --interval 校验：默认 60s，范围 15s 到 100s，越界报 CodeInvalidInput。
func TestValidateSyncInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		wantErr  bool
	}{
		{"default 60s", 60 * time.Second, false},
		{"minimum 15s", 15 * time.Second, false},
		{"maximum 100s", 100 * time.Second, false},
		{"below minimum 14s", 14 * time.Second, true},
		{"above maximum 101s", 101 * time.Second, true},
		{"zero duration", 0, true},
		{"negative duration", -1 * time.Second, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := usecase.ValidateSyncInterval(tt.interval)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSyncInterval(%v) error = %v, wantErr %v", tt.interval, err, tt.wantErr)
			}
			if tt.wantErr && fault.Code(err) != fault.CodeInvalidInput {
				t.Errorf("expected fault code %s, got %s", fault.CodeInvalidInput, fault.Code(err))
			}
		})
	}
}
