//go:build !linux && !darwin && !windows

package accelerate

import (
	"context"
	"errors"
	"io"
)

var errUnsupported = errors.New("TUN acceleration is available on Linux, macOS, and Windows")

func IsSupportedOS() bool { return false }

func IsPrivileged() bool { return false }

func Run(context.Context, uint32, func(context.Context) ([]byte, error), io.Writer) error {
	return errUnsupported
}

func Control(context.Context, bool, io.Writer) error {
	return errUnsupported
}
