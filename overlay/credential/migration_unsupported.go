//go:build windows || ios || android || (!linux && !darwin && !windows)

package credential

import (
	"context"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func SaveProtectedRecord(context.Context, string, Record) error {
	return fault.New(fault.CodeCredentialStorage, "protected file migration requires desktop Linux or macOS", nil)
}
