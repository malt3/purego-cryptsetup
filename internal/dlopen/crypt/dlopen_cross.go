//go:build !linux

package crypt

import "errors"

func OpenCryptsetup() error {
	return errors.New("cryptsetup is not supported on this platform")
}
