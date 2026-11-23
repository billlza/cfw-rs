package main

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/option"
)

// proxyInboundTag names the projection's own loopback proxy listener. The
// LAN listener has a tag of its own, so a LAN port another program holds
// stays an ordinary start failure.
const proxyInboundTag = "cfw-system-proxy"

// startFailure names a start that could not listen on the loopback proxy
// listener or on the controller because another program holds that address,
// so that the application can move an automatic port or name the port the
// user configured. Only a listen failure at exactly one of those two
// addresses is named; every other failure stays start_failed.
func startFailure(err error, options option.Options) string {
	var listen *net.OpError
	if !errors.As(err, &listen) || listen.Op != "listen" || !endpointInUse(listen.Err) {
		return "start_failed"
	}
	address, ok := listen.Addr.(*net.TCPAddr)
	if !ok {
		return "start_failed"
	}
	failed := unmapped(address.AddrPort())
	if endpoint, ok := proxyEndpoint(options); ok && endpoint == failed {
		return "mixed_endpoint_in_use"
	}
	if endpoint, ok := controllerEndpoint(options); ok && endpoint == failed {
		return "controller_endpoint_in_use"
	}
	return "start_failed"
}

func proxyEndpoint(options option.Options) (netip.AddrPort, bool) {
	for _, inbound := range options.Inbounds {
		mixed, ok := inbound.Options.(*option.HTTPMixedInboundOptions)
		if inbound.Tag == proxyInboundTag && ok && mixed.ListenPort != 0 {
			// The listener's own default when the address is absent.
			listen := mixed.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
			return unmapped(netip.AddrPortFrom(listen, mixed.ListenPort)), true
		}
	}
	return netip.AddrPort{}, false
}

func controllerEndpoint(options option.Options) (netip.AddrPort, bool) {
	if options.Experimental == nil || options.Experimental.ClashAPI == nil {
		return netip.AddrPort{}, false
	}
	endpoint, err := netip.ParseAddrPort(options.Experimental.ClashAPI.ExternalController)
	if err != nil || endpoint.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return unmapped(endpoint), true
}

func unmapped(endpoint netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}
