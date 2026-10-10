package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func loopbackConfig() endpointConfig {
	return endpointConfig{
		transportTCP: []string{"127.0.0.1:0", "[::1]:0"},
		transportUDP: []string{"127.0.0.1:0", "[::1]:0"},
		dnsUDP:       []string{"127.0.0.1:0", "[::1]:0"},
	}
}

func TestProductionConfigIsFixedDualStack(t *testing.T) {
	config := productionConfig()
	if err := validateConfig(config); err != nil {
		t.Fatalf("production config is invalid: %v", err)
	}
	if got := config.transportTCP[0]; got != "0.0.0.0:44333" {
		t.Fatalf("unexpected transport listener %q", got)
	}
	if got := config.dnsUDP[1]; got != "[::]:53" {
		t.Fatalf("unexpected DNS listener %q", got)
	}
}

func TestConfigRejectsMissingFamilyAndArbitraryAddress(t *testing.T) {
	missing := loopbackConfig()
	missing.transportTCP = []string{"127.0.0.1:0"}
	if err := validateConfig(missing); err == nil {
		t.Fatal("accepted a single-stack transport listener")
	}

	arbitrary := loopbackConfig()
	arbitrary.dnsUDP[0] = "192.0.2.10:53"
	if err := validateConfig(arbitrary); err == nil {
		t.Fatal("accepted an arbitrary bind address")
	}
}

func TestReceiveOnlyEndpointAcceptsTCPAndUDPWithoutResponding(t *testing.T) {
	server, err := openEndpoint(loopbackConfig())
	if err != nil {
		t.Fatalf("open endpoint: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx) }()

	tcpAddress := server.tcpListeners[0].Addr().String()
	tcp, err := net.DialTimeout("tcp4", tcpAddress, time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial TCP: %v", err)
	}
	if _, err := tcp.Write([]byte("bounded-test-token")); err != nil {
		cancel()
		t.Fatalf("write TCP: %v", err)
	}
	_ = tcp.Close()

	udpAddress := server.udpListeners[0].connection.LocalAddr().String()
	udp, err := net.DialTimeout("udp4", udpAddress, time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial UDP: %v", err)
	}
	if _, err := udp.Write([]byte("bounded-test-token")); err != nil {
		cancel()
		t.Fatalf("write UDP: %v", err)
	}
	if err := udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		cancel()
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := udp.Read(buffer); err == nil {
		cancel()
		t.Fatal("receive-only endpoint unexpectedly replied")
	}
	_ = udp.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint did not stop after cancellation")
	}
	server.wait()
}

func TestAuthoritativeDNSAnswersOnlyExactEvidenceNames(t *testing.T) {
	query := dnsQuery(0x1234, "release-token-0001", 1)
	response, ok := authoritativeDNSResponse(query)
	if !ok {
		t.Fatal("exact evidence A query was not answered")
	}
	if got, want := response[:2], []byte{0x12, 0x34}; !bytes.Equal(got, want) {
		t.Fatalf("response ID %x, want %x", got, want)
	}
	if got := binary.BigEndian.Uint16(response[2:4]); got != 0x8500 {
		t.Fatalf("response flags %#x, want 0x8500", got)
	}
	if !bytes.Equal(response[len(response)-4:], dnsIPv4Answer[:]) {
		t.Fatalf("response A address %x", response[len(response)-4:])
	}

	aaaa, ok := authoritativeDNSResponse(dnsQuery(0x4321, "release-token-0002", 28))
	if !ok || !bytes.Equal(aaaa[len(aaaa)-16:], dnsIPv6Answer[:]) {
		t.Fatal("exact evidence AAAA query was not answered with the fixed address")
	}

	for _, invalid := range [][]byte{
		dnsQuery(1, "short", 1),
		dnsQueryForName(2, []string{"release-token-0001", "example", "test"}, 1),
		dnsQuery(3, "release_token_0001", 1),
		dnsQuery(4, "release-token-0001", 15),
		append(dnsQuery(5, "release-token-0001", 1), 0),
	} {
		if response, ok := authoritativeDNSResponse(invalid); ok || response != nil {
			t.Fatal("invalid or unrelated DNS query received a response")
		}
	}
}

func TestDNSListenerReturnsOneBoundedAuthoritativeAnswer(t *testing.T) {
	server, err := openEndpoint(loopbackConfig())
	if err != nil {
		t.Fatalf("open endpoint: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx) }()

	dnsAddress := server.udpListeners[2].connection.LocalAddr().String()
	connection, err := net.DialTimeout("udp4", dnsAddress, time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial DNS UDP: %v", err)
	}
	query := dnsQuery(7, "release-token-0003", 1)
	if _, err := connection.Write(query); err != nil {
		cancel()
		t.Fatalf("write DNS query: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		cancel()
		t.Fatalf("set DNS read deadline: %v", err)
	}
	response := make([]byte, maximumDNSQuery)
	count, err := connection.Read(response)
	if err != nil {
		cancel()
		t.Fatalf("read DNS response: %v", err)
	}
	if count <= len(query) || count > len(query)+32 {
		cancel()
		t.Fatalf("DNS response size %d is outside the fixed bound", count)
	}
	_ = connection.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint did not stop after cancellation")
	}
	server.wait()
}

func dnsQuery(identifier uint16, token string, questionType uint16) []byte {
	return dnsQueryForName(identifier, []string{token, "evidence", "test"}, questionType)
}

func dnsQueryForName(identifier uint16, labels []string, questionType uint16) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], identifier)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range labels {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, questionType)
	message = binary.BigEndian.AppendUint16(message, 1)
	return message
}
