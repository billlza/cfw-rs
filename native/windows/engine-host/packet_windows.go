// The engine receives packets through an already connected, explicitly
// inherited capability. It never opens a pipe by name or loads Wintun.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/windows"
)

const packetWriteTimeout = 5 * time.Second
const maximumPacketPipeBuffer = 128 * 1024

var errPacketContract = errors.New("invalid tunnel packet or pipe contract")
var errPacketInactive = errors.New("tunnel packet device is not running")
var errPacketRoutes = errors.New("tunnel routing belongs to the Windows authority")

// packetDevice owns one overlapped message-pipe client. A write is exactly one
// IP packet, with no stream framing, batching, background reader or user-space
// queue. Authorization and generation binding belong to the launcher before
// inheritance; the checks below validate the received native capability.
type packetDevice struct {
	file      *os.File
	name      string
	mtu       int
	state     atomic.Uint32 // 0: prepared, 1: started, 2: closed
	read      sync.Mutex
	write     sync.Mutex
	closeOnce sync.Once
	closeErr  error
	failureMu sync.Mutex
	failure   error
	linkMu    sync.Mutex
	link      packetLink

	// Test-only scheduling point after write admission, before the deadline.
	writeAdmitted func()
}

type packetLink interface {
	start() error
	stop()
}

var _ tun.Tun = (*packetDevice)(nil)

// Ownership is consumed on both success and failure. Only an explicit handle
// list from the admitted launcher may supply this handle. Configuration JSON,
// an environment variable and a user-supplied path cannot select an endpoint.
func newPacketDevice(handle windows.Handle, name string, mtu uint32) (_ *packetDevice, result error) {
	if handle == 0 || handle == windows.InvalidHandle {
		return nil, errPacketContract
	}
	var file *os.File
	defer func() {
		if result != nil {
			if file != nil {
				result = errors.Join(result, file.Close())
			} else {
				result = errors.Join(result, windows.CloseHandle(handle))
			}
		}
	}()
	if mtu < 1280 || mtu > 9000 || !packetAdapterName(name) {
		return nil, fmt.Errorf("%w: mtu=%d canonical_adapter=%t", errPacketContract, mtu, packetAdapterName(name))
	}
	var flags, output, input, instances, state, server uint32
	if err := windows.GetNamedPipeInfo(handle, &flags, &output, &input, &instances); err != nil {
		return nil, err
	}
	if err := windows.GetNamedPipeHandleState(handle, &state, nil, nil, nil, nil, 0); err != nil {
		return nil, err
	}
	if err := windows.GetNamedPipeServerProcessId(handle, &server); err != nil {
		return nil, err
	}
	// Windows also reports PIPE_REJECT_REMOTE_CLIENTS here (observed 0x0c
	// for a private message client). That additional restriction is valid;
	// server ends, byte pipes and unknown flag bits still fail admission.
	const allowedFlags = windows.PIPE_TYPE_MESSAGE | windows.PIPE_REJECT_REMOTE_CLIENTS
	if flags&windows.PIPE_TYPE_MESSAGE == 0 || flags & ^uint32(allowedFlags) != 0 || state != windows.PIPE_READMODE_MESSAGE || instances != 1 || server == 0 ||
		input < mtu || output < mtu || input > maximumPacketPipeBuffer || output > maximumPacketPipeBuffer {
		return nil, fmt.Errorf("%w: flags=%#x state=%#x instances=%d server_present=%t input=%d output=%d mtu=%d",
			errPacketContract, flags, state, instances, server != 0, input, output, mtu)
	}
	// The engine must not pass this capability to any subsequent child.
	if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, err
	}
	file = os.NewFile(uintptr(handle), "cfw-tunnel-packets")
	if file == nil {
		return nil, errPacketContract
	}
	// Go's Windows file implementation detects overlapped handles and owns
	// cancellation/completion. Demand working deadlines rather than assuming a
	// synchronous handle can be safely cancelled by Close. No I/O has started.
	if err := file.SetDeadline(time.Now().Add(packetWriteTimeout)); err != nil {
		return nil, err
	}
	if err := file.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &packetDevice{file: file, name: name, mtu: int(mtu)}, nil
}

func packetAdapterName(name string) bool {
	const prefix = "CFW-TUN-"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+36 {
		return false
	}
	guid := name[len(prefix):]
	nonzero := false
	for index, value := range []byte(guid) {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value != '-' {
				return false
			}
		} else if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
			return false
		} else {
			nonzero = nonzero || value != '0'
		}
	}
	return nonzero
}

func validIPPacket(packet []byte, mtu int) bool {
	if mtu < 1280 || mtu > 9000 || len(packet) == 0 || len(packet) > mtu {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return false
		}
		header := int(packet[0]&15) * 4
		return header >= 20 && header <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
	case 6:
		return len(packet) >= 40 && int(binary.BigEndian.Uint16(packet[4:6]))+40 == len(packet)
	default:
		return false
	}
}

func (p *packetDevice) Name() (string, error) { return p.name, nil }

func (p *packetDevice) Start() error {
	if !p.state.CompareAndSwap(0, 1) {
		return errPacketInactive
	}
	p.linkMu.Lock()
	link := p.link
	p.linkMu.Unlock()
	if link != nil {
		if err := link.start(); err != nil {
			return p.fail(err)
		}
	}
	return nil
}

func (p *packetDevice) Read(buffer []byte) (int, error) {
	p.read.Lock()
	defer p.read.Unlock()
	if p.state.Load() != 1 {
		return 0, errPacketInactive
	}
	if len(buffer) < p.mtu {
		return 0, io.ErrShortBuffer
	}
	length, err := p.file.Read(buffer[:p.mtu])
	if err != nil {
		// ERROR_MORE_DATA is also terminal: a truncated message must never
		// become the prefix of a new packet on a later read.
		return 0, p.ioFailure(err)
	}
	if !validIPPacket(buffer[:length], p.mtu) {
		return 0, p.fail(errPacketContract)
	}
	return length, nil
}

func (p *packetDevice) Write(packet []byte) (int, error) {
	p.write.Lock()
	defer p.write.Unlock()
	if p.state.Load() != 1 {
		return 0, errPacketInactive
	}
	if !validIPPacket(packet, p.mtu) {
		return 0, p.fail(errPacketContract)
	}
	if p.writeAdmitted != nil {
		p.writeAdmitted()
	}
	// An intentional Close can land after admission. The closing file is then
	// the expected result of that Close, not a newly observed I/O failure.
	if err := p.file.SetWriteDeadline(time.Now().Add(packetWriteTimeout)); err != nil {
		return 0, p.ioFailure(err)
	}
	length, err := p.file.Write(packet)
	if err != nil {
		return 0, p.ioFailure(err)
	}
	if length != len(packet) {
		return 0, p.fail(io.ErrShortWrite)
	}
	return length, nil
}

func (p *packetDevice) UpdateRouteOptions(tun.Options) error { return errPacketRoutes }

func (p *packetDevice) ioFailure(err error) error {
	if p.state.Load() == 2 {
		// An intentional Close cancels outstanding I/O; it is not a newly
		// observed data-plane failure. The operation itself still fails.
		return err
	}
	return p.fail(err)
}

// A malformed packet, peer loss or uncertain timed-out write poisons this
// generation. No reconnect, partial success or silent packet drop follows.
func (p *packetDevice) fail(err error) error {
	p.failureMu.Lock()
	if p.failure == nil {
		p.failure = err
	}
	p.failureMu.Unlock()
	// A read/dispatch worker can discover failure itself. Close native I/O
	// here; the external owner calls Close to join that worker. Waiting for
	// our own dispatch loop here would deadlock packet-error recovery.
	return errors.Join(err, p.shutdown())
}

func (p *packetDevice) Failure() error {
	p.failureMu.Lock()
	defer p.failureMu.Unlock()
	return p.failure
}

func (p *packetDevice) Close() error {
	err := p.shutdown()
	p.linkMu.Lock()
	link := p.link
	p.linkMu.Unlock()
	if link != nil {
		link.stop()
	}
	return err
}

func (p *packetDevice) shutdown() error {
	p.closeOnce.Do(func() {
		p.state.Store(2)
		p.closeErr = p.file.Close()
	})
	return p.closeErr
}
