//go:build with_gvisor

package main

import (
	"bytes"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun"
)

var _ tun.GVisorTun = (*packetDevice)(nil)
var _ stack.LinkEndpoint = (*packetEndpoint)(nil)

func (p *packetDevice) WritePacket(packet *stack.PacketBuffer) (int, error) {
	if packet.Size() <= 0 || packet.Size() > p.mtu {
		return 0, p.fail(errPacketContract)
	}
	view := packet.ToView()
	defer view.Release()
	return p.Write(view.AsSlice())
}

func (p *packetDevice) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	p.linkMu.Lock()
	defer p.linkMu.Unlock()
	if p.link != nil || p.state.Load() == 2 {
		return nil, stack.NICOptions{}, errPacketInactive
	}
	endpoint := &packetEndpoint{
		Endpoint: channel.New(1, uint32(p.mtu), ""),
		device:   p, done: make(chan struct{}),
	}
	p.link = endpoint
	return endpoint, stack.NICOptions{}, nil
}

// Reuse the pinned netstack's IP-only link metadata and dispatcher binding.
// Outbound WritePackets is synchronous and bypasses its channel queue, so
// packet writes retain the pipe's explicit backpressure/failure semantics.
// No checksum-offload or GSO capability is advertised.
type packetEndpoint struct {
	*channel.Endpoint
	device  *packetDevice
	mu      sync.Mutex
	running bool
	ended   bool
	done    chan struct{}
	onClose func()
}

func (e *packetEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	if e.ended {
		e.mu.Unlock()
		if dispatcher != nil {
			e.device.fail(errPacketInactive)
		}
		return
	}
	e.Endpoint.Attach(dispatcher)
	e.mu.Unlock()
	if dispatcher == nil {
		e.Close()
	} else if e.device.state.Load() == 1 {
		if err := e.start(); err != nil {
			e.device.fail(err)
		}
	}
}

func (e *packetEndpoint) start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ended || e.device.state.Load() == 2 {
		return errPacketInactive
	}
	if !e.running && e.IsAttached() {
		e.running = true
		go e.receive()
	}
	return nil
}

func (e *packetEndpoint) receive() {
	defer close(e.done)
	storage := make([]byte, e.device.mtu)
	defer clear(storage)
	for {
		length, err := e.device.Read(storage)
		if err != nil {
			return
		}
		protocol := header.IPv4ProtocolNumber
		if storage[0]>>4 == 6 {
			protocol = header.IPv6ProtocolNumber
		}
		// Netstack may retain the packet after dispatch returns. It owns
		// this bounded copy; the next native read cannot overwrite it.
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(bytes.Clone(storage[:length])),
			IsForwardedPacket: true,
		})
		e.InjectInbound(protocol, packet)
		packet.DecRef()
	}
}

func (e *packetEndpoint) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	count := 0
	for _, packet := range packets.AsSlice() {
		if _, err := e.device.WritePacket(packet); err != nil {
			return count, &tcpip.ErrAborted{}
		}
		count++
	}
	return count, nil
}

func (e *packetEndpoint) SetMTU(mtu uint32) {
	if mtu != uint32(e.device.mtu) {
		e.device.fail(errPacketRoutes)
	}
}

func (e *packetEndpoint) SetLinkAddress(address tcpip.LinkAddress) {
	if address != "" {
		e.device.fail(errPacketContract)
	}
}

func (e *packetEndpoint) SetOnCloseAction(action func()) {
	e.mu.Lock()
	if !e.ended {
		e.onClose = action
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	if action != nil {
		action()
	}
}

func (e *packetEndpoint) Close() {
	e.mu.Lock()
	if e.ended {
		e.mu.Unlock()
		return
	}
	e.ended = true
	if !e.running {
		close(e.done)
	}
	action := e.onClose
	e.onClose = nil
	e.mu.Unlock()
	if err := e.device.shutdown(); err != nil {
		e.device.fail(err)
	}
	e.Endpoint.Attach(nil)
	e.Endpoint.Close()
	if action != nil {
		action()
	}
}

func (e *packetEndpoint) Wait() { <-e.done }
func (e *packetEndpoint) stop() { e.Close(); e.Wait() }
