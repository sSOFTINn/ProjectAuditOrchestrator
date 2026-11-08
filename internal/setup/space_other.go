//go:build !windows && !linux

package setup

import "errors"

func availableBytes(string) (uint64, error) {
	return 0, errors.New("setup supports Windows and Linux amd64 only")
}
