// Command packet-lan-peer is the receive-only Android peer used by the
// v0.4.0 physical LAN-bypass packet observation. It deliberately has no
// flags, environment configuration, configuration files, response path,
// subprocesses, shell execution, UDP socket, DNS role, or payload logging.
package main

import (
	"context"
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
	listenNetwork       = "tcp4"
	listenAddress       = ":44333"
	maximumConnections  = 8
	maximumRequestBytes = 64
	requestReadDeadline = 5 * time.Second
)

type requestOutcome uint8

const (
	requestAccepted requestOutcome = iota
	requestOverflow
	requestTimedOut
	requestReadFailed
	requestDeadlineFailed
)

type requestResult struct {
	outcome     requestOutcome
	closeFailed bool
}

type peerLimits struct {
	maximumConnections  int
	maximumRequestBytes int64
	readDeadline        time.Duration
}

func productionLimits() peerLimits {
	return peerLimits{
		maximumConnections:  maximumConnections,
		maximumRequestBytes: maximumRequestBytes,
		readDeadline:        requestReadDeadline,
	}
}

func (limits peerLimits) validate() error {
	if limits.maximumConnections < 1 || limits.maximumConnections > maximumConnections {
		return errors.New("connection limit is outside the production bound")
	}
	if limits.maximumRequestBytes < 1 || limits.maximumRequestBytes > maximumRequestBytes {
		return errors.New("request limit is outside the production bound")
	}
	if limits.readDeadline <= 0 || limits.readDeadline > requestReadDeadline {
		return errors.New("read deadline is outside the production bound")
	}
	return nil
}

type managedConnection struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (connection *managedConnection) close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
	})
	return connection.closeErr
}

type peerStatistics struct {
	active             int
	peakActive         int
	accepted           uint64
	overflow           uint64
	timedOut           uint64
	readFailed         uint64
	deadlineFailed     uint64
	closeFailed        uint64
	concurrencyRefused uint64
}

type peerServer struct {
	listener net.Listener
	limits   peerLimits
	slots    chan struct{}
	workers  sync.WaitGroup

	mutex       sync.Mutex
	active      map[*managedConnection]struct{}
	statistics  peerStatistics
	closing     bool
	shutdownErr error

	shutdownOnce sync.Once
}

func newPeerServer(listener net.Listener, limits peerLimits) (*peerServer, error) {
	if listener == nil {
		return nil, errors.New("listener is required")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &peerServer{
		listener: listener,
		limits:   limits,
		slots:    make(chan struct{}, limits.maximumConnections),
		active:   make(map[*managedConnection]struct{}, limits.maximumConnections),
	}, nil
}

func (server *peerServer) serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("serve context is required")
	}
	contextWatcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.shutdown()
		case <-contextWatcherDone:
		}
	}()

	acceptError := server.acceptConnections()
	close(contextWatcherDone)
	cancelled := ctx.Err() != nil
	shutdownError := server.shutdown()
	server.workers.Wait()
	if cancelled && errors.Is(acceptError, net.ErrClosed) {
		return shutdownError
	}
	return errors.Join(acceptError, shutdownError)
}

func (server *peerServer) acceptConnections() error {
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return fmt.Errorf("accept fixed LAN peer connection: %w", err)
		}
		server.admit(connection)
	}
}

func (server *peerServer) admit(raw net.Conn) {
	connection := &managedConnection{Conn: raw}
	select {
	case server.slots <- struct{}{}:
	default:
		closeFailed := connection.close() != nil
		server.mutex.Lock()
		server.statistics.concurrencyRefused++
		if closeFailed {
			server.statistics.closeFailed++
		}
		server.mutex.Unlock()
		return
	}

	server.mutex.Lock()
	if server.closing {
		server.mutex.Unlock()
		<-server.slots
		if connection.close() != nil {
			server.mutex.Lock()
			server.statistics.closeFailed++
			server.mutex.Unlock()
		}
		return
	}
	server.active[connection] = struct{}{}
	server.statistics.active++
	if server.statistics.active > server.statistics.peakActive {
		server.statistics.peakActive = server.statistics.active
	}
	server.workers.Add(1)
	server.mutex.Unlock()

	go server.consume(connection)
}

func (server *peerServer) consume(connection *managedConnection) {
	defer server.workers.Done()
	result := consumeRequest(connection, server.limits)

	server.mutex.Lock()
	delete(server.active, connection)
	server.statistics.active--
	server.recordResult(result)
	server.mutex.Unlock()
	<-server.slots
}

func consumeRequest(connection *managedConnection, limits peerLimits) requestResult {
	if err := connection.SetReadDeadline(time.Now().Add(limits.readDeadline)); err != nil {
		return requestResult{
			outcome:     requestDeadlineFailed,
			closeFailed: connection.close() != nil,
		}
	}

	count, readError := io.CopyN(
		io.Discard,
		connection,
		limits.maximumRequestBytes+1,
	)
	result := requestResult{}
	switch {
	case count > limits.maximumRequestBytes:
		result.outcome = requestOverflow
	case readError == nil:
		result.outcome = requestOverflow
	case errors.Is(readError, io.EOF):
		result.outcome = requestAccepted
	case isTimeout(readError):
		result.outcome = requestTimedOut
	default:
		result.outcome = requestReadFailed
	}
	result.closeFailed = connection.close() != nil
	return result
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func (server *peerServer) recordResult(result requestResult) {
	switch result.outcome {
	case requestAccepted:
		server.statistics.accepted++
	case requestOverflow:
		server.statistics.overflow++
	case requestTimedOut:
		server.statistics.timedOut++
	case requestReadFailed:
		server.statistics.readFailed++
	case requestDeadlineFailed:
		server.statistics.deadlineFailed++
	}
	if result.closeFailed {
		server.statistics.closeFailed++
	}
}

func (server *peerServer) shutdown() error {
	server.shutdownOnce.Do(func() {
		server.mutex.Lock()
		server.closing = true
		connections := make([]*managedConnection, 0, len(server.active))
		for connection := range server.active {
			connections = append(connections, connection)
		}
		server.mutex.Unlock()

		var shutdownErrors []error
		if err := server.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("close LAN peer listener: %w", err))
		}
		for _, connection := range connections {
			if err := connection.close(); err != nil {
				shutdownErrors = append(
					shutdownErrors,
					fmt.Errorf("close active LAN peer connection: %w", err),
				)
			}
		}
		server.shutdownErr = errors.Join(shutdownErrors...)
	})
	return server.shutdownErr
}

func (server *peerServer) statisticsSnapshot() peerStatistics {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	return server.statistics
}

func run(ctx context.Context) error {
	listener, err := net.Listen(listenNetwork, listenAddress)
	if err != nil {
		return fmt.Errorf("listen on fixed TCP %s: %w", listenAddress, err)
	}
	server, err := newPeerServer(listener, productionLimits())
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	return server.serve(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error: fixed packet LAN peer failed:", err)
		os.Exit(1)
	}
}
