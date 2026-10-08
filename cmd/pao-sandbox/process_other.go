//go:build !linux

package main

import "errors"

func isContainerSupervisor() bool { return false }
func stopDescendants() error      { return errors.New("the PAO supervisor requires Linux") }
