//go:build !windows && !linux

package doctor

import "errors"

func supportedHost() error { return errors.New("unsupported host OS") }
