//go:build !linux

package accelerate

import (
	"context"
	"errors"
	"io"
)

var errUnsupported = errors.New("TUN acceleration is available on Linux")

func Run(context.Context, uint32, func(context.Context) ([]byte, error), io.Writer) error {
	return errUnsupported
}

func Control(context.Context, bool, io.Writer) error {
	return errUnsupported
}
