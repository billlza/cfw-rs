//go:build with_gvisor

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Observe completed responses on the real control runner. The hook performs
// traffic only after Start returned running, before Observe and Stop are read.
type packetResponseObserver struct {
	bytes.Buffer
	observe func(response)
}

func (w *packetResponseObserver) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	if err == nil && len(data) > 4 {
		var value response
		if json.Unmarshal(data, &value) == nil {
			w.observe(value)
		}
	}
	return n, err
}

func packetForwardConfig(mtu int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"tun","tag":"tun-in","mtu":%d,"stack":"gvisor","address":["192.0.2.1/30","2001:db8:1::1/126"],"auto_route":false}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","rules":[{"ip_cidr":["192.0.2.123/32"],"action":"route","outbound":"direct","override_address":"127.0.0.1"},{"ip_cidr":["2001:db8:2::123/128"],"action":"route","outbound":"direct","override_address":"::1"}]}}`, mtu))
}

func packetTestRemote(family int, port uint16) netip.AddrPort {
	address := "192.0.2.123"
	if family == 6 {
		address = "2001:db8:2::123"
	}
	return netip.AddrPortFrom(netip.MustParseAddr(address), port)
}

func packetHello(handle windows.Handle, mtu int) request {
	value := hello()
	value.Tunnel = &packetAttachment{Handle: uint64(handle), Name: packetTestName, MTU: uint32(mtu)}
	return value
}

func TestPacketTunnelControlForwardsRealTCPAndUDPAndStops(t *testing.T) {
	for _, mtu := range []int{1280, 1500, 9000} {
		t.Run(fmt.Sprintf("mtu%d", mtu), func(t *testing.T) {
			peer, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
			var exchanges int
			output := &packetResponseObserver{observe: func(value response) {
				if value.ID != 2 || value.State != "running" || value.Error != "" {
					return
				}
				for _, family := range []int{4, 6} {
					packetUDPExchange(t, peer, mtu, family)
					packetTCPExchange(t, peer, mtu, family)
					exchanges++
				}
			}}
			input := messages(t, packetHello(handle, mtu),
				request{Protocol: protocol, Session: testSession, ID: 2, Op: "start", Digest: testDigest, Config: packetForwardConfig(mtu)},
				request{Protocol: protocol, Session: testSession, ID: 3, Op: "observe", Digest: testDigest},
				request{Protocol: protocol, Session: testSession, ID: 4, Op: "stop", Digest: testDigest})
			if code := run(bytes.NewReader(input), output); code != 0 {
				t.Fatalf("packet engine exit %d: %s", code, output.Bytes())
			}
			replies := responses(t, output.Bytes())
			if exchanges != 2 || len(replies) != 4 {
				t.Fatal("real packet traffic or control response missing", exchanges, replies)
			}
			for index, state := range []string{"idle", "running", "running", "stopped"} {
				if replies[index].State != state || replies[index].Error != "" || replies[index].ID != uint64(index+1) {
					t.Fatal("unexpected packet engine state", replies[index])
				}
			}
			if n, err := peer.Read(make([]byte, mtu)); err == nil || n != 0 {
				t.Fatal("packet endpoint survived stopped receipt", n, err)
			}
		})
	}
}

func TestPacketTunnelRejectsMalformedInputBeforeRunningObservation(t *testing.T) {
	peer, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
	observedFailure := false
	output := &packetResponseObserver{observe: func(value response) {
		if value.ID == 2 && value.State == "running" && value.Error == "" {
			if n, err := peer.Write([]byte{0x45}); err != nil || n != 1 {
				t.Fatal("malformed fixture write failed", n, err)
			}
			if n, err := peer.Read(make([]byte, 1500)); err == nil || n != 0 {
				t.Fatal("invalid packet did not close the native endpoint", n, err)
			}
			observedFailure = true
		}
	}}
	input := messages(t, packetHello(handle, 1500),
		request{Protocol: protocol, Session: testSession, ID: 2, Op: "start", Digest: testDigest, Config: packetForwardConfig(1500)},
		request{Protocol: protocol, Session: testSession, ID: 3, Op: "observe", Digest: testDigest},
		request{Protocol: protocol, Session: testSession, ID: 4, Op: "stop", Digest: testDigest})
	if code := run(bytes.NewReader(input), output); code != 2 || !observedFailure {
		t.Fatalf("malformed packet did not fail its owned engine: exit %d; %s", code, output.Bytes())
	}
	replies := responses(t, output.Bytes())
	if len(replies) != 3 || replies[2].Error != "packet_io_failed" {
		t.Fatal("packet failure became a healthy or stopped receipt", replies)
	}
}

func TestPacketTunnelPreservesUpstreamLoopbackReflection(t *testing.T) {
	peer, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
	reflected := 0
	output := &packetResponseObserver{observe: func(value response) {
		if value.ID != 2 || value.State != "running" || value.Error != "" {
			return
		}
		// The original failed fixture used loopback destinations. Keep the
		// exact counterexample: the pinned filter returns these IP packets
		// unchanged instead of treating them as forwardable unicast traffic.
		for _, endpoints := range [][2]string{{"192.0.2.2", "127.0.0.1"}, {"2001:db8:1::2", "::1"}} {
			packet := packetUDPFrame(netip.AddrPortFrom(netip.MustParseAddr(endpoints[0]), 34567),
				netip.AddrPortFrom(netip.MustParseAddr(endpoints[1]), 54321), []byte("cfw-loopback-counterexample"))
			if n, err := peer.Write(packet); err != nil || n != len(packet) {
				t.Fatal("loopback counterexample write", n, err)
			}
			buffer := make([]byte, 1500)
			if n, err := peer.Read(buffer); err != nil || n != len(packet) || !bytes.Equal(buffer[:n], packet) {
				t.Fatal("upstream loopback packet handling changed", n, err)
			}
			reflected++
		}
	}}
	input := messages(t, packetHello(handle, 1500),
		request{Protocol: protocol, Session: testSession, ID: 2, Op: "start", Digest: testDigest, Config: packetForwardConfig(1500)},
		request{Protocol: protocol, Session: testSession, ID: 3, Op: "stop", Digest: testDigest})
	if code := run(bytes.NewReader(input), output); code != 0 || reflected != 2 {
		t.Fatalf("loopback counterexample did not complete: %d, %d; %s", code, reflected, output.Bytes())
	}
}

func TestPacketTunnelRefusesUnownedNetworkConfiguration(t *testing.T) {
	configurations := []string{
		`{"outbounds":[{"type":"direct"}]}`,
		string(bytes.Replace(packetForwardConfig(1500), []byte(`"gvisor"`), []byte(`"system"`), 1)),
		string(bytes.Replace(packetForwardConfig(1500), []byte(`"auto_route":false`), []byte(`"auto_route":true`), 1)),
		string(packetForwardConfig(9000)),
	}
	for _, config := range configurations {
		_, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
		var output bytes.Buffer
		input := messages(t, packetHello(handle, 1500), request{Protocol: protocol, Session: testSession, ID: 2, Op: "start", Digest: testDigest, Config: json.RawMessage(config)})
		if code := run(bytes.NewReader(input), &output); code != 2 {
			t.Fatal("unowned platform operation accepted", config, code)
		}
		replies := responses(t, output.Bytes())
		if len(replies) != 2 || replies[1].Error != "invalid_packet_config" {
			t.Fatal("unexpected platform rejection", replies)
		}
	}
	var output bytes.Buffer
	input := messages(t, hello(), request{Protocol: protocol, Session: testSession, ID: 2, Op: "start", Digest: testDigest, Config: packetForwardConfig(1500)})
	if run(bytes.NewReader(input), &output) != 2 {
		t.Fatal("TUN started without an inherited capability")
	}
	replies := responses(t, output.Bytes())
	if len(replies) != 2 || replies[1].Error != "packet_capability_required" {
		t.Fatal("unexpected missing-capability rejection", replies)
	}
}

// Independent native UDP endpoint: bytes must leave sing-box through an actual
// Windows socket and its distinct reply must return through the IP packet pipe.
func packetUDPExchange(t *testing.T, peer *os.File, mtu, family int) {
	t.Helper()
	network, host := "udp4", "127.0.0.1"
	source := netip.MustParseAddr("192.0.2.2")
	headerBytes := 20
	if family == 6 {
		network, host = "udp6", "::1"
		source = netip.MustParseAddr("2001:db8:1::2")
		headerBytes = 40
	}
	server, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	remote := packetTestRemote(family, server.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	local := netip.AddrPortFrom(source, 34567)
	payload := bytes.Repeat([]byte(fmt.Sprintf("cfw-packet-forward-ipv%d-mtu%d", family, mtu)), mtu)
	payload = payload[:mtu-headerBytes-8]
	expected := bytes.Clone(payload)
	expected[0] ^= 0xff
	completed := make(chan error, 1)
	go func() {
		buffer := make([]byte, mtu)
		n, address, err := server.ReadFromUDPAddrPort(buffer)
		if err == nil && !bytes.Equal(buffer[:n], payload) {
			err = fmt.Errorf("native UDP payload changed: %d", n)
		}
		if err == nil {
			var sent int
			sent, err = server.WriteToUDPAddrPort(expected, address)
			if err == nil && sent != len(expected) {
				err = fmt.Errorf("native UDP response was partial: %d", sent)
			}
		}
		completed <- err
	}()
	request := packetUDPFrame(local, remote, payload)
	if len(request) != mtu {
		t.Fatal("fixture packet does not fill the negotiated MTU")
	}
	if n, err := peer.Write(request); err != nil || n != len(request) {
		t.Fatal("packet request failed", n, err)
	}
	if err := <-completed; err != nil {
		t.Fatal("actual Windows UDP endpoint did not complete", err)
	}
	response := make([]byte, mtu)
	n, err := peer.Read(response)
	if err != nil || n != mtu {
		t.Fatal("packet response failed", n, err)
	}
	assertPacketUDPFrame(t, response[:n], remote, local, expected)
}

func packetChecksum(bytes []byte) uint16 {
	var sum uint32
	for len(bytes) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(bytes))
		bytes = bytes[2:]
	}
	if len(bytes) == 1 {
		sum += uint32(bytes[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func packetUDPPseudo(source, destination netip.Addr, udp []byte) []byte {
	return packetTransportPseudo(source, destination, 17, udp)
}

func packetTransportPseudo(source, destination netip.Addr, protocol byte, transport []byte) []byte {
	pseudo := append(bytes.Clone(source.AsSlice()), destination.AsSlice()...)
	if source.Is4() {
		pseudo = append(pseudo, 0, protocol, byte(len(transport)>>8), byte(len(transport)))
	} else {
		pseudo = append(pseudo, 0, 0, byte(len(transport)>>8), byte(len(transport)), 0, 0, 0, protocol)
	}
	return append(pseudo, transport...)
}

func packetUDPFrame(source, destination netip.AddrPort, payload []byte) []byte {
	headerBytes := 20
	if source.Addr().Is6() {
		headerBytes = 40
	}
	packet := make([]byte, headerBytes+8+len(payload))
	if headerBytes == 20 {
		packet[0], packet[8], packet[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], source.Addr().AsSlice())
		copy(packet[16:20], destination.Addr().AsSlice())
		binary.BigEndian.PutUint16(packet[10:12], packetChecksum(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		copy(packet[8:24], source.Addr().AsSlice())
		copy(packet[24:40], destination.Addr().AsSlice())
	}
	udp := packet[headerBytes:]
	binary.BigEndian.PutUint16(udp[:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	checksum := packetChecksum(packetUDPPseudo(source.Addr(), destination.Addr(), udp))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet
}

func assertPacketUDPFrame(t *testing.T, packet []byte, source, destination netip.AddrPort, payload []byte) {
	t.Helper()
	if !validIPPacket(packet, 9000) {
		t.Fatal("invalid response IP framing")
	}
	headerBytes := 40
	if source.Addr().Is4() {
		headerBytes = 20
		if packet[0] != 0x45 || packet[9] != 17 || packetChecksum(packet[:20]) != 0 ||
			!bytes.Equal(packet[12:16], source.Addr().AsSlice()) || !bytes.Equal(packet[16:20], destination.Addr().AsSlice()) {
			t.Fatal("invalid IPv4 response tuple or checksum")
		}
	} else if packet[0]>>4 != 6 || packet[6] != 17 || !bytes.Equal(packet[8:24], source.Addr().AsSlice()) || !bytes.Equal(packet[24:40], destination.Addr().AsSlice()) {
		t.Fatal("invalid IPv6 response tuple")
	}
	udp := packet[headerBytes:]
	if len(udp) < 8 || int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) || binary.BigEndian.Uint16(udp[:2]) != source.Port() ||
		binary.BigEndian.Uint16(udp[2:4]) != destination.Port() || binary.BigEndian.Uint16(udp[6:8]) == 0 ||
		packetChecksum(packetUDPPseudo(source.Addr(), destination.Addr(), udp)) != 0 || !bytes.Equal(udp[8:], payload) {
		t.Fatal("invalid UDP response ports, length, checksum or payload")
	}
}
