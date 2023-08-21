//go:build !linux

package libc

import "errors"

func OpenLibc() error {
	return errors.New("libc is not supported on this platform")
}
