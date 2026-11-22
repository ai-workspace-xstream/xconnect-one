package usecase

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
)

const (
	DefaultSyncInterval       = 60 * time.Second
	MinSyncInterval           = 15 * time.Second
	MaxSyncInterval           = 100 * time.Second
	defaultStaleHandshakeWait = 180 * time.Second
	defaultTxStallWait        = 30 * time.Second
	defaultPolicyRefreshLead  = 2 * time.Minute
	defaultLevel1Cooldown     = 20 * time.Second
	defaultLevel2EscalateWait = 15 * time.Second
	defaultShutdownTimeout    = 8 * time.Second
)

// Clock provides time operations for testing and runtime control.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type transportRestarter interface {
	RestartTransport(context.Context) error
}

type dataPlaneHealthChecker interface {
	DataPlaneHealth(context.Context) (overlayruntime.DataPlaneStatus, error)
}

type runtimeDowner interface {
	Down(context.Context) error
}

// ValidateSyncInterval checks if the specified interval is within [15s, 100s].
func ValidateSyncInterval(interval time.Duration) error {
	if interval < MinSyncInterval || interval > MaxSyncInterval {
		return fault.New(fault.CodeInvalidInput, "validate sync interval", fmt.Errorf("sync interval %v out of range [%v, %v]", interval, MinSyncInterval, MaxSyncInterval))
	}
	return nil
}

// SyncLoop orchestrates periodic device synchronization, fast data-plane health
// supervision, host network-change/sleep-wake self-healing, and graceful shutdown.
type SyncLoop struct {
	Sync                func(context.Context) (SyncResult, error)
	Interval            time.Duration
	Clock               Clock
	Runtime             overlayruntime.Interface
	OnResult            func(SyncResult)
	OnError             func(error)
	Events              <-chan overlayruntime.NetworkEvent
	OnNetworkEvent      func(overlayruntime.NetworkEvent)
	HealthCheckInterval time.Duration
	StaleHandshakeAfter time.Duration
	TxStallAfter        time.Duration
	PolicyExpiry        func() (time.Time, bool)
	ShutdownOnCancel    bool
	OnRecovery          func(level, reason string)
}

func isConflict(err error) bool {
	if err == nil {
		return false
	}
	code := fault.Code(err)
	return code == fault.CodeStateConflict || strings.Contains(err.Error(), "409")
}

func isFatal(err error) bool {
	if err == nil {
		return false
	}
	code := fault.Code(err)
	switch code {
	case fault.CodeAuthenticationFailed,
		fault.CodeAccessDenied,
		fault.CodeCredentialExpired,
		fault.CodeCredentialMissing,
		fault.CodeCredentialInvalid,
		fault.CodeNotJoined:
		return true
	default:
		// An expired short-lived session is cleared by DeviceSessionManager.
		// Retry with the durable device credential instead of exiting the daemon.
		return false
	}
}

func nextBackoff(current time.Duration, max time.Duration) time.Duration {
	if current <= 0 {
		return 5 * time.Second
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}

type loopRecoveryState struct {
	backoff              time.Duration
	lastLevel1At         time.Time
	level1AwaitHandshake bool
	baselineRx           uint64
	baselineHandshake    time.Time
	hasPrevStats         bool
	lastTx               uint64
	lastRx               uint64
	txStallSince         time.Time
}

// Run executes the sync watch loop until ctx is canceled or an unrecoverable error occurs.
func (l *SyncLoop) Run(ctx context.Context) error {
	if l.Interval == 0 {
		l.Interval = DefaultSyncInterval
	}
	if err := ValidateSyncInterval(l.Interval); err != nil {
		return err
	}

	clock := l.Clock
	if clock == nil {
		clock = realClock{}
	}

	staleAfter := l.StaleHandshakeAfter
	if staleAfter <= 0 {
		staleAfter = defaultStaleHandshakeWait
	}
	txStallAfter := l.TxStallAfter
	if txStallAfter <= 0 {
		txStallAfter = defaultTxStallWait
	}

	var healthTicker *time.Ticker
	var healthCh <-chan time.Time
	if l.HealthCheckInterval > 0 {
		healthTicker = time.NewTicker(l.HealthCheckInterval)
		healthCh = healthTicker.C
		defer healthTicker.Stop()
	}

	eventsCh := l.Events
	state := &loopRecoveryState{}
	var waitCh <-chan time.Time

	shutdownCleanup := func() {
		if l.ShutdownOnCancel && l.Runtime != nil {
			if downer, ok := l.Runtime.(runtimeDowner); ok {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
				defer cancel()
				_ = downer.Down(shutdownCtx)
			}
		}
	}

	for {
		if waitCh == nil {
			waitDuration := l.Interval
			if state.backoff > 0 {
				waitDuration = state.backoff
			}
			waitCh = clock.After(waitDuration)
		}

		select {
		case <-ctx.Done():
			shutdownCleanup()
			return nil

		case <-waitCh:
			waitCh = nil
			if ctx.Err() != nil {
				shutdownCleanup()
				return nil
			}
			if fatalErr := l.executeSyncTick(ctx, state); fatalErr != nil {
				return fatalErr
			}

		case ev, ok := <-eventsCh:
			if !ok {
				eventsCh = nil
				continue
			}
			if ctx.Err() != nil {
				shutdownCleanup()
				return nil
			}
			if fatalErr := l.handleNetworkEvent(ctx, clock, state, ev); fatalErr != nil {
				return fatalErr
			}

		case <-healthCh:
			if ctx.Err() != nil {
				shutdownCleanup()
				return nil
			}
			if fatalErr := l.handleHealthTick(ctx, clock, state, staleAfter, txStallAfter); fatalErr != nil {
				return fatalErr
			}
		}
	}
}

func (l *SyncLoop) executeSyncTick(ctx context.Context, state *loopRecoveryState) error {
	result, err := l.Sync(ctx)
	if err != nil {
		if isFatal(err) {
			if l.OnError != nil {
				l.OnError(err)
			}
			return err
		}
		if isConflict(err) {
			// 409 Conflict: retry once immediately in the same tick
			retryResult, retryErr := l.Sync(ctx)
			if retryErr == nil {
				state.backoff = 0
				if l.OnResult != nil {
					l.OnResult(retryResult)
				}
				return nil
			}
			err = retryErr
			if isFatal(err) {
				if l.OnError != nil {
					l.OnError(err)
				}
				return err
			}
		}
		state.backoff = nextBackoff(state.backoff, l.Interval)
		if l.OnError != nil {
			l.OnError(err)
		}
		return nil
	}

	state.backoff = 0
	if l.OnResult != nil {
		l.OnResult(result)
	}
	return nil
}

func (l *SyncLoop) handleNetworkEvent(ctx context.Context, clock Clock, state *loopRecoveryState, ev overlayruntime.NetworkEvent) error {
	if l.OnNetworkEvent != nil {
		l.OnNetworkEvent(ev)
	}
	state.backoff = 0

	if restarter, ok := l.Runtime.(transportRestarter); ok {
		canRestart := true
		if healthChecker, hasHealth := l.Runtime.(dataPlaneHealthChecker); hasHealth {
			if health, err := healthChecker.DataPlaneHealth(ctx); err == nil && health.Interface == "" {
				canRestart = false
			}
		}
		if canRestart {
			if err := restarter.RestartTransport(ctx); err == nil {
				state.lastLevel1At = clock.Now()
				l.reportRecovery("level1", string(ev.Kind))
			} else {
				l.reportRecovery("level2", "transport restart failed after "+string(ev.Kind))
			}
		}
	}
	return l.executeSyncTick(ctx, state)
}

func (l *SyncLoop) handleHealthTick(ctx context.Context, clock Clock, state *loopRecoveryState, staleAfter, txStallAfter time.Duration) error {
	now := clock.Now()

	if l.PolicyExpiry != nil {
		if expiresAt, ok := l.PolicyExpiry(); ok && !expiresAt.IsZero() {
			if now.Add(defaultPolicyRefreshLead).After(expiresAt) {
				l.reportRecovery("level3", "policy approaching expiration")
				if err := l.executeSyncTick(ctx, state); err != nil {
					return err
				}
				now = clock.Now()
			}
		}
	}

	healthChecker, hasHealth := l.Runtime.(dataPlaneHealthChecker)
	if !hasHealth {
		return nil
	}
	health, err := healthChecker.DataPlaneHealth(ctx)
	if err != nil {
		return nil
	}

	if !health.Applied || !health.XrayAlive || !health.LoopbackOwned {
		if health.Interface != "" {
			if restarter, ok := l.Runtime.(transportRestarter); ok && now.Sub(state.lastLevel1At) >= defaultLevel1Cooldown {
				if restartErr := restarter.RestartTransport(ctx); restartErr == nil {
					state.lastLevel1At = now
					l.reportRecovery("level1", "xray or loopback unhealthy")
					return nil
				}
			}
		}
		l.reportRecovery("level2", "data plane unapplied or unhealthy")
		state.level1AwaitHandshake = false
		state.txStallSince = time.Time{}
		return l.executeSyncTick(ctx, state)
	}

	if !health.HasStats {
		return nil
	}

	if state.hasPrevStats {
		if health.RxBytes > state.lastRx {
			state.txStallSince = time.Time{}
			state.level1AwaitHandshake = false
		} else if health.TxBytes > state.lastTx && state.txStallSince.IsZero() {
			state.txStallSince = now
		}
	}
	state.lastTx = health.TxBytes
	state.lastRx = health.RxBytes
	state.hasPrevStats = true

	staleHandshake := !health.LatestHandshake.IsZero() && now.Sub(health.LatestHandshake) > staleAfter
	txStalled := !state.txStallSince.IsZero() && now.Sub(state.txStallSince) >= txStallAfter
	if !staleHandshake && !txStalled {
		return nil
	}

	if state.level1AwaitHandshake && now.Sub(state.lastLevel1At) >= defaultLevel2EscalateWait {
		if health.RxBytes <= state.baselineRx && !health.LatestHandshake.After(state.baselineHandshake) {
			l.reportRecovery("level2", "tunnel handshake still stale after level1 restart")
			if downer, ok := l.Runtime.(runtimeDowner); ok {
				_ = downer.Down(ctx)
			}
			state.level1AwaitHandshake = false
			state.txStallSince = time.Time{}
			return l.executeSyncTick(ctx, state)
		}
		state.level1AwaitHandshake = false
	}

	if !state.level1AwaitHandshake && now.Sub(state.lastLevel1At) >= defaultLevel1Cooldown {
		if restarter, ok := l.Runtime.(transportRestarter); ok {
			state.lastLevel1At = now
			state.baselineRx = health.RxBytes
			state.baselineHandshake = health.LatestHandshake
			if restartErr := restarter.RestartTransport(ctx); restartErr == nil {
				state.level1AwaitHandshake = true
				l.reportRecovery("level1", "wireguard handshake stale or tx stalled")
				return nil
			}
			l.reportRecovery("level2", "level1 restart failed on stalled tunnel")
			return l.executeSyncTick(ctx, state)
		}
	}

	return nil
}

func (l *SyncLoop) reportRecovery(level, reason string) {
	if l.OnRecovery != nil {
		l.OnRecovery(level, reason)
	}
}
