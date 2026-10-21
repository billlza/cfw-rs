//go:build with_gvisor

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"
)

// A small independent TCP peer drives SYN/ACK, HTTP bytes and acknowledgements
// through the packet pipe. The response must come from a real Windows listener.
func packetTCPExchange(t *testing.T, peer *os.File, mtu, family int) {
	t.Helper()
	network, host := "tcp4", "127.0.0.1"
	source := netip.MustParseAddr("192.0.2.2")
	if family == 6 {
		network, host = "tcp6", "::1"
		source = netip.MustParseAddr("2001:db8:1::2")
	}
	server, err := net.ListenTCP(network, &net.TCPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Error("native TCP listener cleanup", err)
		}
	}()
	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	remote := server.Addr().(*net.TCPAddr).AddrPort()
	local := netip.AddrPortFrom(source, 34568)
	body := fmt.Sprintf("cfw-native-tcp-ipv%d-mtu%d", family, mtu)
	expected := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body))
	completed := make(chan error, 1)
	go func() {
		connection, err := server.AcceptTCP()
		if err != nil {
			completed <- err
			return
		}
		err = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if err == nil {
			var request *http.Request
			request, err = http.ReadRequest(bufio.NewReader(connection))
			if err == nil {
				if request.Method != "GET" || request.URL.Path != "/packet-fixture" || request.ContentLength != 0 {
					err = errors.New("actual TCP request differs")
				}
				err = errors.Join(err, request.Body.Close())
			}
		}
		if err == nil {
			var n int
			n, err = connection.Write(expected)
			if err == nil && n != len(expected) {
				err = errors.New("actual TCP response was partial")
			}
		}
		completed <- errors.Join(err, connection.Close())
	}()
	clientSequence := uint32(0x10203040)
	writePacketTCP(t, peer, local, remote, clientSequence, 0, 0x02, nil)
	sequence, ack, flags, payload := readPacketTCP(t, peer, mtu, remote, local)
	if flags&0x17 != 0x12 || ack != clientSequence+1 || len(payload) != 0 {
		t.Fatal("invalid TCP SYN-ACK", sequence, ack, flags, len(payload))
	}
	clientSequence++
	serverSequence := sequence + 1
	writePacketTCP(t, peer, local, remote, clientSequence, serverSequence, 0x10, nil)
	request := []byte("GET /packet-fixture HTTP/1.1\r\nHost: packet.fixture\r\nConnection: close\r\n\r\n")
	writePacketTCP(t, peer, local, remote, clientSequence, serverSequence, 0x18, request)
	clientSequence += uint32(len(request))
	var received []byte
	for count := 0; count < 16 && len(received) < len(expected); count++ {
		sequence, ack, flags, payload = readPacketTCP(t, peer, mtu, remote, local)
		if flags&0x04 != 0 || flags&0x10 == 0 || sequence != serverSequence || ack != clientSequence {
			t.Fatal("invalid TCP response sequence or acknowledgement", sequence, ack, flags)
		}
		if len(received)+len(payload) > len(expected) {
			t.Fatal("unexpected TCP response bytes")
		}
		received = append(received, payload...)
		serverSequence += uint32(len(payload))
		if flags&0x01 != 0 {
			serverSequence++
		}
		if len(payload) != 0 || flags&0x01 != 0 {
			writePacketTCP(t, peer, local, remote, clientSequence, serverSequence, 0x10, nil)
		}
	}
	if !bytes.Equal(received, expected) {
		t.Fatal("actual native HTTP response did not return through TUN packets")
	}
	// Retire this fixture flow explicitly, so the following family/MTU case
	// cannot consume trailing TCP packets from a previous flow.
	writePacketTCP(t, peer, local, remote, clientSequence, serverSequence, 0x11, nil)
	clientSequence++
	finSeen := flags&0x01 != 0
	ackSeen := false
	for count := 0; count < 16 && !(finSeen && ackSeen); count++ {
		sequence, ack, flags, payload = readPacketTCP(t, peer, mtu, remote, local)
		if flags&0x04 != 0 || len(payload) != 0 || sequence != serverSequence || (ack != clientSequence && ack != clientSequence-1) {
			t.Fatal("invalid TCP retirement", sequence, ack, flags)
		}
		ackSeen = ack == clientSequence
		if flags&0x01 != 0 {
			finSeen = true
			serverSequence++
			writePacketTCP(t, peer, local, remote, clientSequence, serverSequence, 0x10, nil)
		}
	}
	if !finSeen || !ackSeen {
		t.Fatal("TCP FIN/ACK retirement did not complete")
	}
	if err := <-completed; err != nil {
		t.Fatal("actual Windows TCP endpoint did not complete", err)
	}
}

func writePacketTCP(t *testing.T, peer *os.File, source, destination netip.AddrPort, sequence, ack uint32, flags byte, payload []byte) {
	t.Helper()
	headerBytes := 20
	if source.Addr().Is6() {
		headerBytes = 40
	}
	packet := make([]byte, headerBytes+20+len(payload))
	if headerBytes == 20 {
		packet[0], packet[8], packet[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], source.Addr().AsSlice())
		copy(packet[16:20], destination.Addr().AsSlice())
		binary.BigEndian.PutUint16(packet[10:12], packetChecksum(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		copy(packet[8:24], source.Addr().AsSlice())
		copy(packet[24:40], destination.Addr().AsSlice())
	}
	tcp := packet[headerBytes:]
	binary.BigEndian.PutUint16(tcp[:2], source.Port())
	binary.BigEndian.PutUint16(tcp[2:4], destination.Port())
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], packetChecksum(packetTransportPseudo(source.Addr(), destination.Addr(), 6, tcp)))
	if n, err := peer.Write(packet); err != nil || n != len(packet) {
		t.Fatal("TCP packet write failed", n, err)
	}
}

func readPacketTCP(t *testing.T, peer *os.File, mtu int, source, destination netip.AddrPort) (uint32, uint32, byte, []byte) {
	t.Helper()
	packet := make([]byte, mtu)
	n, err := peer.Read(packet)
	if err != nil || !validIPPacket(packet[:n], mtu) {
		t.Fatal("TCP packet read failed", n, err)
	}
	packet = packet[:n]
	headerBytes := 40
	if source.Addr().Is4() {
		headerBytes = 20
		if packet[0] != 0x45 || packet[9] != 6 || packetChecksum(packet[:20]) != 0 ||
			!bytes.Equal(packet[12:16], source.Addr().AsSlice()) || !bytes.Equal(packet[16:20], destination.Addr().AsSlice()) {
			t.Fatal("invalid TCP IPv4 tuple or checksum")
		}
	} else if packet[0]>>4 != 6 || packet[6] != 6 || !bytes.Equal(packet[8:24], source.Addr().AsSlice()) || !bytes.Equal(packet[24:40], destination.Addr().AsSlice()) {
		t.Fatal("invalid TCP IPv6 tuple")
	}
	tcp := packet[headerBytes:]
	if len(tcp) < 20 || binary.BigEndian.Uint16(tcp[:2]) != source.Port() || binary.BigEndian.Uint16(tcp[2:4]) != destination.Port() ||
		packetChecksum(packetTransportPseudo(source.Addr(), destination.Addr(), 6, tcp)) != 0 {
		t.Fatal("invalid TCP ports or checksum")
	}
	header := int(tcp[12]>>4) * 4
	if header < 20 || header > len(tcp) {
		t.Fatal("invalid TCP header length")
	}
	return binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]), tcp[13], tcp[header:]
}
