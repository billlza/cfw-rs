//go:build !windows

package main

import "errors"

// The portable control/probe tests do not create a Windows native capability.
func openPacketRuntime(packetAttachment) (packetRuntime, error) {
	return nil, errors.New("packet_tunnel_requires_windows")
}
