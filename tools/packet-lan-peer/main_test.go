package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func testLimits() peerLimits {
	return peerLimits{
		maximumConnections:  2,
		maximumRequestBytes: maximumRequestBytes,
		readDeadline:        100 * time.Millisecond,
	}
}

func TestProductionContractIsFixedAndBounded(t *testing.T) {
	if listenNetwork != "tcp4" {
		t.Fatalf("unexpected listener network %q", listenNetwork)
	}
	if listenAddress != ":44333" {
		t.Fatalf("unexpected listener %q", listenAddress)
	}
	limits := productionLimits()
	if err := limits.validate(); err != nil {
		t.Fatalf("production limits are invalid: %v", err)
	}
	if limits.maximumConnections != 8 || limits.maximumRequestBytes != 64 {
		t.Fatalf("unexpected production limits: %+v", limits)
	}
	if limits.readDeadline != 5*time.Second {
		t.Fatalf("unexpected read deadline %s", limits.readDeadline)
	}
}

func TestLimitsRejectExpansionBeyondProductionContract(t *testing.T) {
	for _, limits := range []peerLimits{
		{maximumConnections: 0, maximumRequestBytes: 64, readDeadline: time.Second},
		{maximumConnections: 9, maximumRequestBytes: 64, readDeadline: time.Second},
		{maximumConnections: 1, maximumRequestBytes: 65, readDeadline: time.Second},
		{maximumConnections: 1, maximumRequestBytes: 64, readDeadline: 6 * time.Second},
	} {
		if err := limits.validate(); err == nil {
			t.Fatalf("accepted limits outside the production contract: %+v", limits)
		}
	}
}

func TestNormalRequestIsDiscardedAndConnectionIsClosed(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	done := make(chan requestResult, 1)
	go func() {
		done <- consumeRequest(&managedConnection{Conn: serverSide}, testLimits())
	}()

	payload := make([]byte, maximumRequestBytes)
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatalf("write bounded request: %v", err)
	}
	if err := clientSide.Close(); err != nil {
		t.Fatalf("close request writer: %v", err)
	}
	result := <-done
	if result.outcome != requestAccepted || result.closeFailed {
		t.Fatalf("bounded request result = %+v", result)
	}
}

func TestOverflowIsRejectedAndConnectionIsClosed(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	done := make(chan requestResult, 1)
	go func() {
		done <- consumeRequest(&managedConnection{Conn: serverSide}, testLimits())
	}()

	payload := make([]byte, maximumRequestBytes+1)
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatalf("write oversized request: %v", err)
	}
	result := <-done
	if result.outcome != requestOverflow || result.closeFailed {
		t.Fatalf("overflow result = %+v", result)
	}
	if _, err := clientSide.Write([]byte{0}); err == nil {
		t.Fatal("oversized connection remained writable")
	}
	_ = clientSide.Close()
}

func TestReadTimeoutClosesSilentConnection(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	limits := testLimits()
	limits.readDeadline = 20 * time.Millisecond
	started := time.Now()
	result := consumeRequest(&managedConnection{Conn: serverSide}, limits)
	if result.outcome != requestTimedOut || result.closeFailed {
		t.Fatalf("timeout result = %+v", result)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("timeout elapsed %s is outside the test bound", elapsed)
	}
	if _, err := clientSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("silent client read error = %v, want EOF", err)
	}
	_ = clientSide.Close()
}

func TestReadAndDeadlineFailuresStillCloseConnection(t *testing.T) {
	sentinel := errors.New("injected I/O failure")
	for _, test := range []struct {
		name     string
		decorate func(net.Conn) net.Conn
		expected requestOutcome
	}{
		{
			name: "deadline",
			decorate: func(connection net.Conn) net.Conn {
				return &faultConnection{Conn: connection, deadlineError: sentinel}
			},
			expected: requestDeadlineFailed,
		},
		{
			name: "read",
			decorate: func(connection net.Conn) net.Conn {
				return &faultConnection{Conn: connection, readError: sentinel}
			},
			expected: requestReadFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverSide, clientSide := net.Pipe()
			fault := test.decorate(serverSide).(*faultConnection)
			result := consumeRequest(&managedConnection{Conn: fault}, testLimits())
			if result.outcome != test.expected || result.closeFailed {
				t.Fatalf("failure result = %+v", result)
			}
			if fault.closeCount() != 1 {
				t.Fatalf("close count = %d, want 1", fault.closeCount())
			}
			_ = clientSide.Close()
		})
	}
}

func TestManagedConnectionConcurrentCloseClosesUnderlyingConnectionOnce(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	fault := &faultConnection{Conn: serverSide}
	connection := &managedConnection{Conn: fault}
	const closers = 64
	var workers sync.WaitGroup
	workers.Add(closers)
	for range closers {
		go func() {
			defer workers.Done()
			if err := connection.close(); err != nil {
				t.Errorf("managed close: %v", err)
			}
		}()
	}
	workers.Wait()
	if fault.closeCount() != 1 {
		t.Fatalf("underlying close count = %d, want 1", fault.closeCount())
	}
	_ = clientSide.Close()
}

func TestServerAcceptsOneBoundedRequestWithoutResponding(t *testing.T) {
	limits := testLimits()
	limits.readDeadline = time.Second
	server, address, cancel, done := startTestServer(t, limits)
	client, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial peer: %v", err)
	}
	tcpClient, ok := client.(*net.TCPConn)
	if !ok {
		_ = client.Close()
		cancel()
		t.Fatalf("dial returned %T, want *net.TCPConn", client)
	}
	if _, err := tcpClient.Write([]byte("fixed-lan-observation-token")); err != nil {
		_ = tcpClient.Close()
		cancel()
		t.Fatalf("write request: %v", err)
	}
	if err := tcpClient.CloseWrite(); err != nil {
		_ = tcpClient.Close()
		cancel()
		t.Fatalf("close request writer: %v", err)
	}
	if err := tcpClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		_ = tcpClient.Close()
		cancel()
		t.Fatalf("set response deadline: %v", err)
	}
	if _, err := tcpClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		_ = tcpClient.Close()
		cancel()
		t.Fatalf("peer response read error = %v, want EOF", err)
	}
	_ = tcpClient.Close()
	waitForStatistic(t, server, func(statistics peerStatistics) bool {
		return statistics.accepted == 1 && statistics.active == 0
	})

	cancel()
	assertServerStopped(t, done)
}

func TestConcurrencyCapRefusesAdditionalConnection(t *testing.T) {
	limits := testLimits()
	limits.readDeadline = requestReadDeadline
	server, address, cancel, done := startTestServer(t, limits)
	defer cancel()

	clients := make([]net.Conn, 0, 3)
	defer func() {
		for _, connection := range clients {
			_ = connection.Close()
		}
	}()
	for range limits.maximumConnections {
		connection, err := net.DialTimeout("tcp4", address, time.Second)
		if err != nil {
			t.Fatalf("dial admitted connection: %v", err)
		}
		clients = append(clients, connection)
	}
	waitForStatistic(t, server, func(statistics peerStatistics) bool {
		return statistics.active == limits.maximumConnections
	})

	refused, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatalf("dial refused connection: %v", err)
	}
	clients = append(clients, refused)
	waitForStatistic(t, server, func(statistics peerStatistics) bool {
		return statistics.concurrencyRefused == 1
	})
	if err := refused.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set refused read deadline: %v", err)
	}
	if _, err := refused.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("refused connection read error = %v, want EOF", err)
	}
	statistics := server.statisticsSnapshot()
	if statistics.peakActive != limits.maximumConnections {
		t.Fatalf("peak active = %d, want %d", statistics.peakActive, limits.maximumConnections)
	}

	cancel()
	assertServerStopped(t, done)
}

func TestCancellationClosesActiveConnectionAndStopsPromptly(t *testing.T) {
	limits := testLimits()
	limits.readDeadline = requestReadDeadline
	server, address, cancel, done := startTestServer(t, limits)
	client, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial active connection: %v", err)
	}
	defer client.Close()
	waitForStatistic(t, server, func(statistics peerStatistics) bool {
		return statistics.active == 1
	})

	started := time.Now()
	cancel()
	assertServerStopped(t, done)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("graceful cancellation took %s", elapsed)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set cancelled read deadline: %v", err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("cancelled connection read error = %v, want EOF", err)
	}
	if statistics := server.statisticsSnapshot(); statistics.active != 0 {
		t.Fatalf("active connections after shutdown = %d", statistics.active)
	}
}

func startTestServer(
	t *testing.T,
	limits peerLimits,
) (*peerServer, string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open test listener: %v", err)
	}
	server, err := newPeerServer(listener, limits)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("create test server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.serve(ctx)
	}()
	return server, listener.Addr().String(), cancel, done
}

func waitForStatistic(
	t *testing.T,
	server *peerServer,
	predicate func(peerStatistics) bool,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate(server.statisticsSnapshot()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("server statistic condition was not reached: %+v", server.statisticsSnapshot())
}

func assertServerStopped(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}

type faultConnection struct {
	net.Conn
	deadlineError error
	readError     error
	mutex         sync.Mutex
	closes        int
}

func (connection *faultConnection) SetReadDeadline(time.Time) error {
	return connection.deadlineError
}

func (connection *faultConnection) Read([]byte) (int, error) {
	if connection.readError != nil {
		return 0, connection.readError
	}
	return connection.Conn.Read(nil)
}

func (connection *faultConnection) Close() error {
	connection.mutex.Lock()
	connection.closes++
	connection.mutex.Unlock()
	return connection.Conn.Close()
}

func (connection *faultConnection) closeCount() int {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return connection.closes
}
