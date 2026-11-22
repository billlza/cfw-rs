package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// endpointInUse reports a bind that another program's socket refuses, and
// one that Windows refuses because the port lies in an excluded port range,
// such as the ranges Hyper-V and WinNAT reserve.
func endpointInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
