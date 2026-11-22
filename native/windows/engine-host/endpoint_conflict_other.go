//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// The portable tests bind real sockets; elsewhere a held address is EADDRINUSE.
func endpointInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
