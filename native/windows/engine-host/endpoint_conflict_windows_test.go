package main

import (
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// A port in an excluded range cannot be reserved in a test without changing
// the machine's reservations, so the refusal is written as Windows reports it.
func TestExcludedPortRangeNamesTheEndpoint(t *testing.T) {
	options := parsedOptions(t, startConfiguration(mixedInbound(proxyInboundTag, 7890), "127.0.0.1:9090"))
	for _, test := range []struct {
		port  int
		errno syscall.Errno
		code  string
	}{
		{7890, windows.WSAEACCES, "mixed_endpoint_in_use"},
		{9090, windows.WSAEACCES, "controller_endpoint_in_use"},
		{7890, windows.WSAEADDRINUSE, "mixed_endpoint_in_use"},
		{7890, windows.ERROR_ACCESS_DENIED, "start_failed"},
		{7891, windows.WSAEACCES, "start_failed"},
	} {
		refused := &net.OpError{Op: "listen", Net: "tcp4", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: test.port}, Err: os.NewSyscallError("bind", test.errno)}
		if code := startFailure(refused, options); code != test.code {
			t.Fatalf("port %d errno %d: named %q, want %q", test.port, test.errno, code, test.code)
		}
	}
}
