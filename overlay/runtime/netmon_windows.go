//go:build windows

package runtime

import "context"

func (m *NetworkMonitor) watchOS(ctx context.Context, emit func()) {
	m.pollSnapshotLoop(ctx, defaultPollInterval, emit)
}
