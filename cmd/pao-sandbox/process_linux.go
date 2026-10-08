//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func isContainerSupervisor() bool { return os.Getpid() == 1 && os.Getuid() != 0 }
func stopDescendants() error {
	if os.Getpid() != 1 {
		return errors.New("process-tree teardown requires container PID 1")
	}
	if err := syscall.Kill(-1, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.ECHILD) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if pid == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return errors.New("process-tree teardown deadline exceeded")
}
