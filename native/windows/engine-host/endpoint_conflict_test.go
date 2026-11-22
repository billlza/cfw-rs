package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// holdPort listens on a loopback port as another program would, and returns
// that address with the error a second listen there really gets.
func holdPort(t *testing.T) (*net.TCPAddr, *net.OpError) {
	t.Helper()
	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Close() })
	second, err := net.Listen("tcp4", holder.Addr().String())
	if err == nil {
		_ = second.Close()
		t.Fatal("a held loopback port was bound twice")
	}
	var refused *net.OpError
	if !errors.As(err, &refused) || !endpointInUse(refused.Err) {
		t.Fatalf("a held port refused the listen for another reason: %v", err)
	}
	return holder.Addr().(*net.TCPAddr), refused
}

// freePort returns a loopback port that nothing listens on any more.
func freePort(t *testing.T) int {
	t.Helper()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err = reservation.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func mixedInbound(tag string, port int) string {
	return `{"type":"mixed","tag":"` + tag + `","listen":"127.0.0.1","listen_port":` + strconv.Itoa(port) + `}`
}

func startConfiguration(inbound string, controller string) string {
	text := `{"log":{"disabled":true},"inbounds":[` + inbound + `],"outbounds":[{"type":"direct","tag":"direct"}]`
	if controller != "" {
		text += `,"experimental":{"clash_api":{"external_controller":"` + controller + `","secret":"conflict-test-secret"}}`
	}
	return text + `}`
}

func parsedOptions(t *testing.T, text string) option.Options {
	t.Helper()
	options, err := singjson.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func TestStartFailureNamesOnlyAHeldProjectedEndpoint(t *testing.T) {
	held, refused := holdPort(t)
	other := freePort(t)
	otherController := "127.0.0.1:" + strconv.Itoa(other)
	// The engine wraps the listen error in the names of its components.
	wrapped := fmt.Errorf("start inbound/mixed[%s]: %w", proxyInboundTag, refused)
	mapped := &net.OpError{Op: "listen", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: held.Port}, Err: refused.Err}
	dial := &net.OpError{Op: "dial", Net: refused.Net, Addr: refused.Addr, Err: refused.Err}
	otherFailure := &net.OpError{Op: "listen", Net: refused.Net, Addr: refused.Addr, Err: errors.New("listen refused for another reason")}
	for _, test := range []struct {
		name          string
		configuration string
		err           error
		code          string
	}{
		{"proxy listener", startConfiguration(mixedInbound(proxyInboundTag, held.Port), otherController), wrapped, "mixed_endpoint_in_use"},
		{"IPv4-mapped address", startConfiguration(mixedInbound(proxyInboundTag, held.Port), ""), mapped, "mixed_endpoint_in_use"},
		{"controller", startConfiguration(mixedInbound(proxyInboundTag, other), held.String()), wrapped, "controller_endpoint_in_use"},
		{"LAN listener", startConfiguration(mixedInbound("cfw-lan-proxy", held.Port), ""), wrapped, "start_failed"},
		{"another address", startConfiguration(mixedInbound(proxyInboundTag, other), otherController), wrapped, "start_failed"},
		{"another operation", startConfiguration(mixedInbound(proxyInboundTag, held.Port), ""), dial, "start_failed"},
		{"another listen failure", startConfiguration(mixedInbound(proxyInboundTag, held.Port), ""), otherFailure, "start_failed"},
		{"no listen failure", startConfiguration(mixedInbound(proxyInboundTag, held.Port), ""), errors.New("start service"), "start_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if code := startFailure(test.err, parsedOptions(t, test.configuration)); code != test.code {
				t.Fatalf("named %q, want %q", code, test.code)
			}
		})
	}
}

func TestHeldEndpointsAreNamedInTheStartReply(t *testing.T) {
	held, _ := holdPort(t)
	proxy := freePort(t)
	for _, test := range []struct {
		name          string
		configuration string
		code          string
	}{
		{"proxy listener", startConfiguration(mixedInbound(proxyInboundTag, held.Port), ""), "mixed_endpoint_in_use"},
		{"controller", startConfiguration(mixedInbound(proxyInboundTag, proxy), held.String()), "controller_endpoint_in_use"},
		{"LAN listener", startConfiguration(mixedInbound("cfw-lan-proxy", held.Port), ""), "start_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			input := messages(t, hello(), request{protocol, testSession, 2, "start", testDigest, json.RawMessage(test.configuration), nil, nil})
			if code := run(bytes.NewReader(input), &output); code != 2 {
				t.Fatalf("exit %d: %s", code, output.Bytes())
			}
			replies := responses(t, output.Bytes())
			if len(replies) != 2 || replies[1].Error != test.code || replies[1].State != "idle" || replies[1].Digest != "" {
				t.Fatalf("start reply: %+v", replies)
			}
			if strings.Contains(output.String(), "conflict-test-secret") {
				t.Fatal("the start reply echoed configuration")
			}
		})
	}
	// The proxy listener bound before the controller failed is released.
	released, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(proxy))
	if err != nil {
		t.Fatalf("the refused start kept its proxy listener: %v", err)
	}
	_ = released.Close()
}
