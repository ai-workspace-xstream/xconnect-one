package runtime

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

// NetworkEventKind classifies host connectivity transitions relevant to active
// tunnel supervision.
type NetworkEventKind string

const (
	NetworkEventChanged NetworkEventKind = "network_changed"
	NetworkEventWake    NetworkEventKind = "system_wake"

	defaultNetworkDebounce    = 1500 * time.Millisecond
	defaultWakeTickInterval   = 2 * time.Second
	defaultWakeJumpThreshold  = 5 * time.Second
	defaultPollInterval       = 2 * time.Second
	defaultFallbackPollPeriod = 5 * time.Second
)

// NetworkEvent represents a debounced host network transition or system wake.
type NetworkEvent struct {
	Kind NetworkEventKind
	At   time.Time
}

// NetworkMonitor watches host interface, IP address, routing, and sleep/wake
// transitions without CGO and emits coalesced NetworkEvent notifications.
type NetworkMonitor struct {
	ignoreInterface string
	debounce        time.Duration
	wakeTick        time.Duration
	wakeJump        time.Duration
	startOS         func(ctx context.Context, emit func())
	resolveIgnored  func(name string) []string
}

// NewNetworkMonitor constructs a cross-platform monitor ignoring link/address
// events belonging to ignoreInterface (for example, the managed WireGuard device).
func NewNetworkMonitor(ignoreInterface string) *NetworkMonitor {
	m := &NetworkMonitor{
		ignoreInterface: strings.TrimSpace(ignoreInterface),
		debounce:        defaultNetworkDebounce,
		wakeTick:        defaultWakeTickInterval,
		wakeJump:        defaultWakeJumpThreshold,
	}
	m.startOS = m.watchOS
	return m
}

// Start begins watching host network transitions and sleep/wake jumps until ctx
// is canceled, closing the returned channel cleanly on shutdown.
func (m *NetworkMonitor) Start(ctx context.Context) <-chan NetworkEvent {
	out := make(chan NetworkEvent, 8)
	rawChanges := make(chan struct{}, 32)
	emitChange := func() {
		select {
		case rawChanges <- struct{}{}:
		default:
		}
	}

	if m.startOS != nil {
		go m.startOS(ctx, emitChange)
	}

	go func() {
		defer close(out)

		debounce := m.debounce
		if debounce <= 0 {
			debounce = defaultNetworkDebounce
		}
		wakeTick := m.wakeTick
		if wakeTick <= 0 {
			wakeTick = defaultWakeTickInterval
		}
		wakeJump := m.wakeJump
		if wakeJump <= 0 {
			wakeJump = defaultWakeJumpThreshold
		}

		var debounceTimer *time.Timer
		var debounceCh <-chan time.Time
		stopDebounce := func() {
			if debounceTimer != nil {
				if !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
				debounceTimer = nil
				debounceCh = nil
			}
		}
		defer stopDebounce()

		wakeTicker := time.NewTicker(wakeTick)
		defer wakeTicker.Stop()
		prevTick := time.Now()

		sendEvent := func(kind NetworkEventKind) {
			ev := NetworkEvent{Kind: kind, At: time.Now().UTC()}
			select {
			case out <- ev:
			case <-ctx.Done():
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-rawChanges:
				if debounceTimer == nil {
					debounceTimer = time.NewTimer(debounce)
					debounceCh = debounceTimer.C
				} else {
					if !debounceTimer.Stop() {
						select {
						case <-debounceTimer.C:
						default:
						}
					}
					debounceTimer.Reset(debounce)
				}
			case <-debounceCh:
				debounceTimer = nil
				debounceCh = nil
				sendEvent(NetworkEventChanged)
			case now := <-wakeTicker.C:
				if detectSleepWakeJump(prevTick, now, wakeTick, wakeJump) {
					stopDebounce()
					sendEvent(NetworkEventWake)
				}
				prevTick = now
			}
		}
	}()

	return out
}

func detectSleepWakeJump(prev, now time.Time, tickInterval, threshold time.Duration) bool {
	wallElapsed := time.Duration(now.UnixNano() - prev.UnixNano())
	monoElapsed := now.Sub(prev)
	if wallElapsed-monoElapsed >= threshold {
		return true
	}
	return wallElapsed >= tickInterval+threshold
}

func (m *NetworkMonitor) ignoredNames() map[string]struct{} {
	ignored := make(map[string]struct{})
	if m.ignoreInterface != "" {
		ignored[m.ignoreInterface] = struct{}{}
	}
	if m.resolveIgnored != nil && m.ignoreInterface != "" {
		for _, alias := range m.resolveIgnored(m.ignoreInterface) {
			if trimmed := strings.TrimSpace(alias); trimmed != "" {
				ignored[trimmed] = struct{}{}
			}
		}
	}
	return ignored
}

func (m *NetworkMonitor) pollSnapshotLoop(ctx context.Context, period time.Duration, emit func()) {
	if period <= 0 {
		period = defaultPollInterval
	}
	prev := snapshotNetworkInterfaces(m.ignoredNames())
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := snapshotNetworkInterfaces(m.ignoredNames())
			if current != prev {
				prev = current
				emit()
			}
		}
	}
}

func snapshotNetworkInterfaces(ignored map[string]struct{}) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var lines []string
	for _, iface := range ifaces {
		if _, skip := ignored[iface.Name]; skip {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		var addrs []string
		if rawAddrs, addrErr := iface.Addrs(); addrErr == nil {
			for _, a := range rawAddrs {
				addrs = append(addrs, a.String())
			}
		}
		sort.Strings(addrs)
		up := "down"
		if iface.Flags&net.FlagUp != 0 {
			up = "up"
		}
		lines = append(lines, iface.Name+":"+up+":"+strings.Join(addrs, ","))
	}
	sort.Strings(lines)
	return strings.Join(lines, ";")
}
