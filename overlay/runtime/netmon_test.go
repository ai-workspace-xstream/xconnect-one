package runtime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkMonitorDebouncesBurstChanges(t *testing.T) {
	var emitted atomic.Int32
	m := &NetworkMonitor{
		debounce: 40 * time.Millisecond,
		wakeTick: time.Hour,
		wakeJump: 5 * time.Second,
		startOS: func(ctx context.Context, emit func()) {
			emit()
			time.Sleep(10 * time.Millisecond)
			emit()
			time.Sleep(10 * time.Millisecond)
			emit()
			emitted.Add(3)
			<-ctx.Done()
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	events := m.Start(ctx)

	select {
	case ev, ok := <-events:
		if !ok || ev.Kind != NetworkEventChanged {
			t.Fatalf("expected coalesced NetworkEventChanged, got ev=%+v ok=%v", ev, ok)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for coalesced network event")
	}

	// No extra events should fire from the initial burst.
	select {
	case extra, ok := <-events:
		if ok {
			t.Fatalf("unexpected duplicate event from burst: %+v", extra)
		}
	case <-time.After(90 * time.Millisecond):
	}
}

func TestDetectSleepWakeJump(t *testing.T) {
	now := time.Now()
	prevSame := now.Add(-2 * time.Second)
	if detectSleepWakeJump(prevSame, now, 2*time.Second, 5*time.Second) {
		t.Fatal("normal 2s tick must not trigger wake")
	}

	// Simulate wall clock jumping 30s ahead across suspend/sleep.
	jumped := time.Unix(now.Unix()-35, 0)
	if !detectSleepWakeJump(jumped, now, 2*time.Second, 5*time.Second) {
		t.Fatal("expected 35s wall jump to detect wake")
	}
}

func TestSnapshotNetworkInterfacesRunsCleanly(t *testing.T) {
	snap1 := snapshotNetworkInterfaces(map[string]struct{}{"xconone0": {}})
	snap2 := snapshotNetworkInterfaces(map[string]struct{}{"xconone0": {}})
	if snap1 != snap2 {
		t.Fatalf("snapshot not deterministic: %q != %q", snap1, snap2)
	}
}
