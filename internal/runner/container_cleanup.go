package runner

import (
	"errors"
	"sync"
)

// A transport failure cannot prove the container stopped. Retain sealed input
// copies and live-process leases until separately verified operator recovery.
// Windows handles end with the PAO process; private readonly copies remain.
type UnconfirmedContainerCleanupError struct {
	ContainerName string
	Cause         error
}

func (e *UnconfirmedContainerCleanupError) Error() string {
	return "container teardown could not be confirmed; private inputs retained"
}
func (e *UnconfirmedContainerCleanupError) Unwrap() error { return e.Cause }

var retainedInputLeases struct {
	sync.Mutex
	cleanups []func() error
}

func retainCleanupIfUnconfirmed(err error, cleanup func() error) bool {
	var pending *UnconfirmedContainerCleanupError
	if !errors.As(err, &pending) {
		return false
	}
	retainedInputLeases.Lock()
	defer retainedInputLeases.Unlock()
	// Closures retain the owning file handles, preventing GC finalizers from
	// silently releasing locks while the process is still alive.
	retainedInputLeases.cleanups = append(retainedInputLeases.cleanups, cleanup)
	return true
}

func hasUnconfirmedTeardown() bool {
	retainedInputLeases.Lock()
	defer retainedInputLeases.Unlock()
	return len(retainedInputLeases.cleanups) != 0
}
