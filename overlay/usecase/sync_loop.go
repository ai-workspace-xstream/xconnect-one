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
	DefaultSyncInterval = 60 * time.Second
	MinSyncInterval     = 15 * time.Second
	MaxSyncInterval     = 100 * time.Second
)

// Clock provides time operations for testing and runtime control.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// ValidateSyncInterval checks if the specified interval is within [15s, 100s].
func ValidateSyncInterval(interval time.Duration) error {
	if interval < MinSyncInterval || interval > MaxSyncInterval {
		return fault.New(fault.CodeInvalidInput, "validate sync interval", fmt.Errorf("sync interval %v out of range [%v, %v]", interval, MinSyncInterval, MaxSyncInterval))
	}
	return nil
}

// SyncLoop orchestrates periodic execution of device synchronization.
type SyncLoop struct {
	Sync     func(context.Context) (SyncResult, error)
	Interval time.Duration
	Clock    Clock
	Runtime  overlayruntime.Interface
	OnResult func(SyncResult)
	OnError  func(error)
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
		fault.CodeEnrollmentExpired,
		fault.CodeNotJoined:
		return true
	default:
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

	var backoff time.Duration

	for {
		waitDuration := l.Interval
		if backoff > 0 {
			waitDuration = backoff
		}

		select {
		case <-ctx.Done():
			return nil
		case <-clock.After(waitDuration):
		}

		if ctx.Err() != nil {
			return nil
		}

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
					backoff = 0
					if l.OnResult != nil {
						l.OnResult(retryResult)
					}
					continue
				}
				err = retryErr
				if isFatal(err) {
					if l.OnError != nil {
						l.OnError(err)
					}
					return err
				}
			}

			// Transient failure: back off according to ladder (5s, 10s, 20s...)
			backoff = nextBackoff(backoff, l.Interval)
			if l.OnError != nil {
				l.OnError(err)
			}
			continue
		}

		// Successful sync
		backoff = 0
		if l.OnResult != nil {
			l.OnResult(result)
		}
	}
}
