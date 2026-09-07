// Command packet-evidence-endpoint is the fixed peer used by the v0.4.0
// physical packet matrix. It deliberately has no flags, configuration file,
// shell execution, or packet-content logging surface. Its only response path
// is the closed authoritative DNS answer implemented below.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	transportPort   = 44333
	dnsPort         = 53
	maximumTCPPeers = 64
	maximumTCPBytes = 8 * 1024
	maximumDatagram = 8 * 1024
	maximumDNSQuery = 512
	tcpReadDeadline = 15 * time.Second
)

var (
	dnsIPv4Answer = [4]byte{192, 0, 2, 1}
	dnsIPv6Answer = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
)

type endpointConfig struct {
	transportTCP []string
	transportUDP []string
	dnsUDP       []string
}

func productionConfig() endpointConfig {
	return endpointConfig{
		transportTCP: []string{
			fmt.Sprintf("0.0.0.0:%d", transportPort),
			fmt.Sprintf("[::]:%d", transportPort),
		},
		transportUDP: []string{
			fmt.Sprintf("0.0.0.0:%d", transportPort),
			fmt.Sprintf("[::]:%d", transportPort),
		},
		dnsUDP: []string{
			fmt.Sprintf("0.0.0.0:%d", dnsPort),
			fmt.Sprintf("[::]:%d", dnsPort),
		},
	}
}

type endpointServer struct {
	tcpListeners []net.Listener
	udpListeners []udpListener
	peerSlots    chan struct{}
	workers      sync.WaitGroup
	closeOnce    sync.Once
}

type udpListener struct {
	connection net.PacketConn
	dns        bool
}

func openEndpoint(config endpointConfig) (*endpointServer, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	server := &endpointServer{peerSlots: make(chan struct{}, maximumTCPPeers)}
	closeOnFailure := func(err error) (*endpointServer, error) {
		server.close()
		return nil, err
	}
	for _, address := range config.transportTCP {
		listener, err := net.Listen(tcpNetwork(address), address)
		if err != nil {
			return closeOnFailure(fmt.Errorf("listen TCP %s: %w", address, err))
		}
		server.tcpListeners = append(server.tcpListeners, listener)
	}
	for _, group := range []struct {
		addresses []string
		dns       bool
	}{
		{config.transportUDP, false},
		{config.dnsUDP, true},
	} {
		for _, address := range group.addresses {
			connection, err := net.ListenPacket(udpNetwork(address), address)
			if err != nil {
				return closeOnFailure(fmt.Errorf("listen UDP %s: %w", address, err))
			}
			server.udpListeners = append(server.udpListeners, udpListener{
				connection: connection,
				dns:        group.dns,
			})
		}
	}
	return server, nil
}

func validateConfig(config endpointConfig) error {
	groups := []struct {
		name      string
		addresses []string
	}{
		{"transport TCP", config.transportTCP},
		{"transport UDP", config.transportUDP},
		{"DNS UDP", config.dnsUDP},
	}
	seen := make(map[string]string, 8)
	for _, group := range groups {
		if len(group.addresses) != 2 {
			return fmt.Errorf("%s must contain exact IPv4 and IPv6 listeners", group.name)
		}
		families := make(map[string]struct{}, 2)
		for _, address := range group.addresses {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%s address is invalid: %w", group.name, err)
			}
			ip := net.ParseIP(host)
			if ip == nil || (!ip.IsUnspecified() && !ip.IsLoopback()) {
				return fmt.Errorf("%s address is not an unspecified or test-loopback IP", group.name)
			}
			family := "ipv6"
			if ip.To4() != nil {
				family = "ipv4"
			}
			if _, duplicate := families[family]; duplicate {
				return fmt.Errorf("%s repeats %s", group.name, family)
			}
			families[family] = struct{}{}
			if port != "0" {
				key := group.name[len(group.name)-3:] + "/" + address
				if previous, duplicate := seen[key]; duplicate {
					return fmt.Errorf("%s address duplicates %s", group.name, previous)
				}
				seen[key] = group.name
			}
			if port == "0" && !ip.IsLoopback() {
				return fmt.Errorf("%s production listener may not use an ephemeral port", group.name)
			}
		}
		if len(families) != 2 {
			return fmt.Errorf("%s is not dual-stack", group.name)
		}
	}
	return nil
}

func tcpNetwork(address string) string {
	host, _, _ := net.SplitHostPort(address)
	if net.ParseIP(host).To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

func udpNetwork(address string) string {
	host, _, _ := net.SplitHostPort(address)
	if net.ParseIP(host).To4() != nil {
		return "udp4"
	}
	return "udp6"
}

func (server *endpointServer) serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, len(server.tcpListeners)+len(server.udpListeners))
	for _, listener := range server.tcpListeners {
		server.workers.Add(1)
		go func(listener net.Listener) {
			defer server.workers.Done()
			errCh <- server.serveTCP(ctx, listener)
		}(listener)
	}
	for _, listener := range server.udpListeners {
		server.workers.Add(1)
		go func(listener udpListener) {
			defer server.workers.Done()
			errCh <- server.serveUDP(ctx, listener)
		}(listener)
	}
	go func() {
		<-ctx.Done()
		server.close()
	}()
	err := <-errCh
	server.close()
	if ctx.Err() != nil && isClosedNetworkError(err) {
		return nil
	}
	return err
}

func (server *endpointServer) serveTCP(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept TCP %s: %w", listener.Addr(), err)
		}
		select {
		case server.peerSlots <- struct{}{}:
			server.workers.Add(1)
			go server.consumeTCP(connection)
		case <-ctx.Done():
			_ = connection.Close()
			return ctx.Err()
		default:
			_ = connection.Close()
		}
	}
}

func (server *endpointServer) consumeTCP(connection net.Conn) {
	defer server.workers.Done()
	defer func() { <-server.peerSlots }()
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(tcpReadDeadline)); err != nil {
		return
	}
	_, _ = io.CopyN(io.Discard, connection, maximumTCPBytes+1)
}

func (server *endpointServer) serveUDP(ctx context.Context, listener udpListener) error {
	buffer := make([]byte, maximumDatagram)
	for {
		if err := listener.connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return fmt.Errorf("set UDP deadline %s: %w", listener.connection.LocalAddr(), err)
		}
		count, peer, err := listener.connection.ReadFrom(buffer)
		if err == nil {
			if listener.dns {
				if response, ok := authoritativeDNSResponse(buffer[:count]); ok {
					if _, err := listener.connection.WriteTo(response, peer); err != nil {
						return fmt.Errorf(
							"send bounded DNS response %s: %w",
							listener.connection.LocalAddr(),
							err,
						)
					}
				}
			}
			continue
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		return fmt.Errorf("receive UDP %s: %w", listener.connection.LocalAddr(), err)
	}
}

func authoritativeDNSResponse(query []byte) ([]byte, bool) {
	const (
		dnsHeaderBytes = 12
		dnsTypeA       = 1
		dnsTypeAAAA    = 28
		dnsClassIN     = 1
	)
	if len(query) < dnsHeaderBytes || len(query) > maximumDNSQuery {
		return nil, false
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&0xfeff != 0 ||
		binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 ||
		binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) != 0 {
		return nil, false
	}
	offset := dnsHeaderBytes
	token, next, ok := dnsLabel(query, offset)
	if !ok || !validEvidenceToken(token) {
		return nil, false
	}
	offset = next
	evidence, next, ok := dnsLabel(query, offset)
	if !ok || !bytes.Equal(evidence, []byte("evidence")) {
		return nil, false
	}
	offset = next
	test, next, ok := dnsLabel(query, offset)
	if !ok || !bytes.Equal(test, []byte("test")) {
		return nil, false
	}
	offset = next
	if offset >= len(query) || query[offset] != 0 {
		return nil, false
	}
	offset++
	if offset+4 != len(query) {
		return nil, false
	}
	questionType := binary.BigEndian.Uint16(query[offset : offset+2])
	questionClass := binary.BigEndian.Uint16(query[offset+2 : offset+4])
	if questionClass != dnsClassIN || (questionType != dnsTypeA && questionType != dnsTypeAAAA) {
		return nil, false
	}

	rdata := dnsIPv4Answer[:]
	if questionType == dnsTypeAAAA {
		rdata = dnsIPv6Answer[:]
	}
	response := make([]byte, 0, len(query)+12+len(rdata))
	response = append(response, query[:2]...)
	responseFlags := uint16(0x8400) | flags&0x0100
	response = binary.BigEndian.AppendUint16(response, responseFlags)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint16(response, 0)
	response = binary.BigEndian.AppendUint16(response, 0)
	response = append(response, query[dnsHeaderBytes:]...)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, questionType)
	response = binary.BigEndian.AppendUint16(response, dnsClassIN)
	response = binary.BigEndian.AppendUint32(response, 0)
	response = binary.BigEndian.AppendUint16(response, uint16(len(rdata)))
	response = append(response, rdata...)
	return response, true
}

func dnsLabel(message []byte, offset int) ([]byte, int, bool) {
	if offset >= len(message) {
		return nil, offset, false
	}
	length := int(message[offset])
	if length < 1 || length > 63 || offset+1+length > len(message) {
		return nil, offset, false
	}
	return message[offset+1 : offset+1+length], offset + 1 + length, true
}

func validEvidenceToken(token []byte) bool {
	if len(token) < 16 || len(token) > 63 {
		return false
	}
	for index, character := range token {
		isLetter := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLetter && !isDigit && (character != '-' || index == 0 || index == len(token)-1) {
			return false
		}
	}
	return true
}

func (server *endpointServer) close() {
	server.closeOnce.Do(func() {
		for _, listener := range server.tcpListeners {
			_ = listener.Close()
		}
		for _, listener := range server.udpListeners {
			_ = listener.connection.Close()
		}
	})
}

func (server *endpointServer) wait() {
	server.workers.Wait()
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)
}

func run(ctx context.Context, config endpointConfig) error {
	server, err := openEndpoint(config)
	if err != nil {
		return err
	}
	defer server.wait()
	defer server.close()
	return server.serve(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, productionConfig()); err != nil {
		fmt.Fprintf(os.Stderr, "packet evidence endpoint failed: %v\n", err)
		os.Exit(1)
	}
}
