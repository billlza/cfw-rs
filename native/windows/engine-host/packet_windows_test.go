package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/windows"
)

const packetTestName = "CFW-TUN-8c4fe63e-b108-4cb8-b422-fd9186cba252"

// Real native message-pipe endpoints, private to this test user's SID. These
// tests do not create a TUN interface or authorize a SYSTEM-owned generation.
func packetTestPair(t *testing.T, clientFlags uint32) (*os.File, windows.Handle) {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	user, userErr := token.GetTokenUser()
	closeErr := token.Close()
	if err := errors.Join(userErr, closeErr); err != nil {
		t.Fatal(err)
	}
	security, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}
	id, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(`\\.\pipe\cfw-packet-test-` + id.String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 64*1024, 64*1024, 0, &attributes)
	if err != nil {
		t.Fatal(err)
	}
	peer := os.NewFile(uintptr(server), "cfw-packet-test-server")
	if peer == nil {
		t.Fatal("server file was not constructed")
	}
	t.Cleanup(func() { requirePacketClose(t, peer.Close()) })
	client, err := windows.CreateFile(name,
		windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		clientFlags|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The client has already connected. No asynchronous connect operation is
	// submitted, so no OVERLAPPED address or connect completion is abandoned.
	if err := windows.ConnectNamedPipe(server, nil); !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		t.Fatalf("already-connected server: %v", err)
	}
	mode := uint32(windows.PIPE_READMODE_MESSAGE)
	if err := windows.SetNamedPipeHandleState(client, &mode, nil, nil); err != nil {
		t.Fatal(errors.Join(err, windows.CloseHandle(client)))
	}
	if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(errors.Join(err, windows.CloseHandle(client)))
	}
	return peer, client
}

func requirePacketClose(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func packetTestDevice(t *testing.T, mtu int) (*os.File, *packetDevice) {
	t.Helper()
	peer, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
	device, err := newPacketDevice(handle, packetTestName, uint32(mtu))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { requirePacketClose(t, device.Close()) })
	if err := device.Start(); err != nil {
		t.Fatal(err)
	}
	return peer, device
}

func packetTestIP(version, length int) []byte {
	packet := bytes.Repeat([]byte{0x69}, length)
	if version == 4 {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(length-40))
	}
	return packet
}

func TestPacketDeviceNativeFullMTUBidirectionalMessages(t *testing.T) {
	for _, mtu := range []int{1280, 1500, 9000} {
		for _, version := range []int{4, 6} {
			t.Run(fmt.Sprintf("ipv%d-mtu%d", version, mtu), func(t *testing.T) {
				peer, device := packetTestDevice(t, mtu)
				request := packetTestIP(version, mtu)
				for _, length := range []int{mtu, 64, mtu} {
					request = packetTestIP(version, length)
					if n, err := peer.Write(request); err != nil || n != len(request) {
						t.Fatalf("peer write: %d, %v", n, err)
					}
					buffer := make([]byte, mtu+10)
					if n, err := device.Read(buffer); err != nil || n != len(request) || !bytes.Equal(buffer[:n], request) {
						t.Fatalf("device packet: %d, %v", n, err)
					}
					response := bytes.Clone(request)
					response[len(response)-1] ^= 0xff
					if n, err := device.Write(response); err != nil || n != len(response) {
						t.Fatalf("device write: %d, %v", n, err)
					}
					if n, err := peer.Read(buffer); err != nil || n != len(response) || !bytes.Equal(buffer[:n], response) {
						t.Fatalf("peer packet: %d, %v", n, err)
					}
				}
				if device.Failure() != nil {
					t.Fatal(device.Failure())
				}
			})
		}
	}
}

func TestPacketDeviceRejectsMalformedAndOversizedNativeMessages(t *testing.T) {
	badLength := packetTestIP(4, 1500)
	badLength[3]--
	for _, packet := range [][]byte{{0x45}, bytes.Repeat([]byte{0x70}, 40), badLength, packetTestIP(4, 1501)} {
		peer, device := packetTestDevice(t, 1500)
		if n, err := peer.Write(packet); err != nil || n != len(packet) {
			t.Fatalf("peer write: %d, %v", n, err)
		}
		if n, err := device.Read(make([]byte, 1500)); n != 0 || err == nil || device.Failure() == nil {
			t.Fatalf("malformed message accepted: %d, %v", n, err)
		}
		if _, err := device.Read(make([]byte, 1500)); !errors.Is(err, errPacketInactive) {
			t.Fatal("failed endpoint was reused", err)
		}
	}
}

func TestPacketDeviceCloseCancelsNativeReadAndPeerLossFails(t *testing.T) {
	for _, peerLoss := range []bool{false, true} {
		peer, device := packetTestDevice(t, 1500)
		result := make(chan error, 1)
		go func() { _, err := device.Read(make([]byte, 1500)); result <- err }()
		select {
		case err := <-result:
			t.Fatal("empty pipe did not wait for a packet", err)
		case <-time.After(100 * time.Millisecond):
		}
		if peerLoss {
			requirePacketClose(t, peer.Close())
		} else {
			requirePacketClose(t, device.Close())
		}
		select {
		case err := <-result:
			if err == nil || (device.Failure() != nil) != peerLoss {
				t.Fatalf("close/peer-loss result: %v, failure: %v", err, device.Failure())
			}
		case <-time.After(3 * time.Second):
			t.Fatal("native read did not retire after endpoint close")
		}
	}
}

func TestPacketDeviceBackpressureExpiresWithoutSuccessfulDrop(t *testing.T) {
	_, device := packetTestDevice(t, 9000)
	packet := packetTestIP(6, 9000)
	started := time.Now()
	writes := 0
	for ; writes < 100; writes++ {
		n, err := device.Write(packet)
		if err != nil {
			if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || device.Failure() == nil {
				t.Fatalf("backpressure failure: %d, %v", n, err)
			}
			break
		}
		if n != len(packet) {
			t.Fatalf("partial successful packet: %d", n)
		}
	}
	if writes == 0 || writes == 100 || time.Since(started) < packetWriteTimeout {
		t.Fatalf("native bounded pipe did not apply backpressure: %d writes", writes)
	}
	if _, err := device.Write(packet); !errors.Is(err, errPacketInactive) {
		t.Fatal("timed-out generation was reused", err)
	}
}

func TestPacketDeviceCloseCancelsBackpressuredWrite(t *testing.T) {
	_, device := packetTestDevice(t, 9000)
	var completed atomic.Int32
	result := make(chan error, 1)
	go func() {
		packet := packetTestIP(4, 9000)
		for completed.Load() < 100 {
			n, err := device.Write(packet)
			if err != nil {
				result <- err
				return
			}
			if n != len(packet) {
				result <- io.ErrShortWrite
				return
			}
			completed.Add(1)
		}
		result <- nil
	}()
	select {
	case err := <-result:
		t.Fatal("native pipe did not hold a backpressured write", err)
	case <-time.After(100 * time.Millisecond):
	}
	if completed.Load() == 0 {
		t.Fatal("no initial packet reached the native pipe")
	}
	requirePacketClose(t, device.Close())
	select {
	case err := <-result:
		if err == nil || device.Failure() != nil {
			t.Fatalf("intentional write cancellation: %v, failure: %v", err, device.Failure())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backpressured native write did not retire after close")
	}
}

func TestPacketDeviceAdmissionRejectsSynchronousPipeAndInvalidContract(t *testing.T) {
	for _, item := range []struct {
		flags uint32
		name  string
		mtu   uint32
	}{
		{0, packetTestName, 1500},
		{windows.FILE_FLAG_OVERLAPPED, packetTestName, 1279},
		{windows.FILE_FLAG_OVERLAPPED, packetTestName, 9001},
		{windows.FILE_FLAG_OVERLAPPED, strings.ToUpper(packetTestName), 1500},
		{windows.FILE_FLAG_OVERLAPPED, "CFW-TUN-00000000-0000-0000-0000-000000000000", 1500},
	} {
		_, handle := packetTestPair(t, item.flags)
		if device, err := newPacketDevice(handle, item.name, item.mtu); err == nil || device != nil {
			t.Fatal("invalid native capability admitted")
		}
		var flags uint32
		if err := windows.GetNamedPipeInfo(handle, &flags, nil, nil, nil); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			t.Fatal("rejected native capability was not closed", err)
		}
	}
}

func TestPacketDeviceLifecycleDoesNotMutateAuthorityRoutes(t *testing.T) {
	_, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
	device, err := newPacketDevice(handle, packetTestName, 1500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { requirePacketClose(t, device.Close()) })
	if _, err := device.Read(make([]byte, 1500)); !errors.Is(err, errPacketInactive) {
		t.Fatal("read before start", err)
	}
	if err := device.Start(); err != nil {
		t.Fatal(err)
	}
	if err := device.Start(); !errors.Is(err, errPacketInactive) {
		t.Fatal("duplicate start", err)
	}
	if _, err := device.Read(make([]byte, 1499)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("short receive buffer", err)
	}
	if err := device.UpdateRouteOptions(tun.Options{}); !errors.Is(err, errPacketRoutes) {
		t.Fatal("route update did not require authority", err)
	}
	requirePacketClose(t, device.Close())
	if err := device.Start(); !errors.Is(err, errPacketInactive) {
		t.Fatal("retired capability restarted", err)
	}
}

func TestPacketDeviceInheritedCapability(t *testing.T) {
	const handleVariable = "CFW_PACKET_TEST_INHERITED_HANDLE"
	if encoded := os.Getenv(handleVariable); encoded != "" {
		handle, err := strconv.ParseUint(encoded, 10, 64)
		if err != nil || uint64(uintptr(handle)) != handle {
			t.Fatal("invalid inherited test handle", err)
		}
		device, err := newPacketDevice(windows.Handle(handle), packetTestName, 9000)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { requirePacketClose(t, device.Close()) })
		if err := device.Start(); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 9000)
		for _, version := range []int{4, 6} {
			request := packetTestIP(version, 9000)
			n, err := device.Read(buffer)
			if err != nil || n != len(request) || !bytes.Equal(buffer[:n], request) {
				t.Fatalf("inherited receive: %d, %v", n, err)
			}
			buffer[n-1] ^= 0xff
			if count, err := device.Write(buffer[:n]); err != nil || count != n {
				t.Fatalf("inherited response: %d, %v", count, err)
			}
		}
		return
	}
	peer, handle := packetTestPair(t, windows.FILE_FLAG_OVERLAPPED)
	if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		t.Fatal(errors.Join(err, windows.CloseHandle(handle)))
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(errors.Join(err, windows.CloseHandle(handle)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestPacketDeviceInheritedCapability$", "-test.timeout=8s")
	command.Env = append(os.Environ(), handleVariable+"="+strconv.FormatUint(uint64(handle), 10))
	command.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(handle)}}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(errors.Join(err, windows.CloseHandle(handle)))
	}
	// This process drops its client copy immediately. Only the explicitly
	// inherited child endpoint can return the transformed packet bytes.
	if err := windows.CloseHandle(handle); err != nil {
		cancel()
		t.Fatal(errors.Join(err, command.Wait()))
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			if err := command.Wait(); err != nil {
				t.Logf("failed packet fixture cleanup: %v; %s", err, output.String())
			}
		}
	}()
	for _, version := range []int{4, 6} {
		request := packetTestIP(version, 9000)
		if n, err := peer.Write(request); err != nil || n != len(request) {
			t.Fatalf("parent send: %d, %v", n, err)
		}
		buffer := make([]byte, 9000)
		request[len(request)-1] ^= 0xff
		if n, err := peer.Read(buffer); err != nil || n != len(request) || !bytes.Equal(buffer[:n], request) {
			t.Fatalf("parent receive: %d, %v", n, err)
		}
	}
	err = command.Wait()
	waited = true
	if err != nil || command.ProcessState.ExitCode() != 0 {
		t.Fatalf("inherited packet worker did not exit successfully: %v; %s", err, output.String())
	}
}
