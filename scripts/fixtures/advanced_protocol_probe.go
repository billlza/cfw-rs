// Run from the pinned, patched sing-box module with the product's build tags.
// The Rust projector validates every client profile. Servers use ephemeral
// credentials and local listeners; no system proxy, route or DNS setting changes.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	stls "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"
)

type object = map[string]any

const profileID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const sharedID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func require(ok bool, detail string) {
	if !ok {
		panic(detail)
	}
}

func checked[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func closeChecked(closer io.Closer) {
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		panic(err)
	}
}

func project(projector string, profile object) object {
	return projectMode(projector, profile, false)
}

func projectMode(projector string, profile object, tunnel bool) object {
	return projectInput(projector, object{"profile": profile, "profile_id": profileID, "tunnel": tunnel})
}

func projectInput(projector string, envelopeInput object) object {
	input := checked(json.Marshal(envelopeInput))
	command := exec.Command(projector)
	command.Stdin = bytes.NewReader(input)
	command.Stderr = os.Stderr
	output := checked(command.Output())
	var envelope object
	require(json.Unmarshal(output, &envelope) == nil, "invalid projector response")
	return envelope["configuration"].(map[string]any)
}

func start(config object) *box.Box {
	instance, _ := startWithContext(config, nil)
	return instance
}

func startWithContext(config object, roots *x509.CertPool) (*box.Box, context.Context) {
	ctx := include.Context(service.ContextWithDefaultRegistry(context.Background()))
	if roots != nil {
		ctx = service.ContextWith[adapter.CertificateStore](ctx, testCertificateStore{roots})
	}
	options := checked(sjson.UnmarshalExtendedContext[option.Options](ctx, checked(json.Marshal(config))))
	instance := checked(box.New(box.Options{Context: ctx, Options: options}))
	if err := instance.StartWithExternalCleanup(); err != nil {
		panic(errors.Join(err, instance.Close()))
	}
	return instance, ctx
}

func localPort(address, network string) int {
	if network == "udp" {
		listener := checked(net.ListenPacket(network, net.JoinHostPort(address, "0")))
		defer closeChecked(listener)
		return listener.LocalAddr().(*net.UDPAddr).Port
	}
	listener := checked(net.Listen(network, net.JoinHostPort(address, "0")))
	defer closeChecked(listener)
	return listener.Addr().(*net.TCPAddr).Port
}

func prepareListeners(config object, address string) {
	inbounds := config["inbounds"].([]any)
	inbounds[0].(map[string]any)["listen_port"] = localPort("127.0.0.1", "tcp")
	api := config["experimental"].(map[string]any)["clash_api"].(map[string]any)
	api["external_controller"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort("127.0.0.1", "tcp")))
	// Numeric local server addresses use no bootstrap resolver. Leave the
	// application's DNS projection intact; the probes below use numeric targets.
	_ = address
}

func tcpExchange(instance *box.Box, tag, target string) {
	tcpExchangeClosing(instance, tag, target, closeChecked)
}

// closeQUICStream accepts the one error quic-go reports for closing a stream
// that the echo server has already finished; the payload has round-tripped by
// then. Every other close failure still fails the probe.
func closeQUICStream(closer io.Closer) {
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) &&
		!strings.HasPrefix(err.Error(), "close called for canceled stream") {
		panic(err)
	}
}

func tcpExchangeClosing(instance *box.Box, tag, target string, closeConn func(io.Closer)) {
	outbound, exists := instance.Outbound().Outbound(tag)
	require(exists, "projected outbound missing")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := checked(outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(target)))
	defer closeConn(conn)
	require(conn.SetDeadline(time.Now().Add(5*time.Second)) == nil, "TCP deadline")
	require(func() bool { _, err := conn.Write([]byte("cfm-roundtrip")); return err == nil }(), "TCP write")
	body := make([]byte, len("cfm-roundtrip"))
	_, err := io.ReadFull(conn, body)
	require(err == nil && string(body) == "cfm-roundtrip", "TCP did not traverse the configured transport")
}

func udpExchange(instance *box.Box, tag, target string, expected bool) {
	outbound, exists := instance.Outbound().Outbound(tag)
	require(exists, "projected UDP outbound missing")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn := checked(outbound.ListenPacket(ctx, M.ParseSocksaddr(target)))
	defer closeChecked(conn)
	// Only the read can block; Hysteria2 packet connections refuse a combined deadline.
	require(conn.SetReadDeadline(time.Now().Add(2*time.Second)) == nil, "UDP read deadline")
	_, writeErr := conn.WriteTo([]byte("cfm-datagram"), checked(net.ResolveUDPAddr("udp", target)))
	if !expected && writeErr != nil {
		return
	}
	require(writeErr == nil, "UDP write")
	body := make([]byte, 128)
	count, _, err := conn.ReadFrom(body)
	if expected {
		require(err == nil && string(body[:count]) == "cfm-datagram", "UDP roundtrip failed")
	} else {
		require(err != nil, "wrong WireGuard preshared key forwarded a datagram")
	}
}

func echoServers(address string) (string, string, func()) {
	tcp := checked(net.Listen("tcp", net.JoinHostPort(address, "0")))
	udp := checked(net.ListenPacket("udp", net.JoinHostPort(address, "0")))
	tcpDone, udpDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(tcpDone)
		for {
			conn, err := tcp.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				panic(err)
			}
			go func() {
				defer closeChecked(conn)
				require(conn.SetDeadline(time.Now().Add(5*time.Second)) == nil, "echo TCP deadline")
				body := make([]byte, len("cfm-roundtrip"))
				if _, err := io.ReadFull(conn, body); err != nil {
					panic(err)
				}
				if _, err := conn.Write(body); err != nil {
					panic(err)
				}
			}()
		}
	}()
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 512)
		for {
			count, peer, err := udp.ReadFrom(buffer)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				panic(err)
			}
			if _, err := udp.WriteTo(buffer[:count], peer); err != nil {
				panic(err)
			}
		}
	}()
	return tcp.Addr().String(), udp.LocalAddr().String(), func() {
		closeChecked(tcp)
		closeChecked(udp)
		<-tcpDone
		<-udpDone
	}
}

func wireguardProbe(projector, address, tcpTarget, udpTarget string) {
	clientKey := checked(ecdh.X25519().GenerateKey(rand.Reader))
	serverKey := checked(ecdh.X25519().GenerateKey(rand.Reader))
	shared := make([]byte, 32)
	_, err := rand.Read(shared)
	require(err == nil, "random preshared key")
	encode := base64.StdEncoding.EncodeToString
	port := localPort(address, "udp")
	server := start(object{
		"log": object{"level": "error"},
		"endpoints": []any{object{"type": "wireguard", "tag": "server", "system": false, "address": []string{"10.91.0.1/32"}, "private_key": encode(serverKey.Bytes()), "listen_port": port,
			"peers": []any{object{"public_key": encode(clientKey.PublicKey().Bytes()), "pre_shared_key": encode(shared), "allowed_ips": []string{"10.91.0.2/32"}}}}},
		"outbounds": []any{object{"type": "direct", "tag": "direct"}},
	})
	defer closeChecked(server)
	profile := object{"outbounds": []any{object{"type": "wireguard", "tag": "wg", "server": address, "server_port": port,
		"local_addresses": []string{"10.91.0.2/32"}, "peer_public_key": encode(serverKey.PublicKey().Bytes()),
		"private_key_credential_ref":    object{"id": profileID, "kind": "wireguard_private_key"},
		"pre_shared_key_credential_ref": object{"id": sharedID, "kind": "wireguard_pre_shared_key"},
		"mtu":                           1420, "persistent_keepalive_seconds": 0}}}
	for _, validKey := range []bool{true, false} {
		config := project(projector, profile)
		prepareListeners(config, address)
		endpoint := config["endpoints"].([]any)[0].(map[string]any)
		endpoint["private_key"] = encode(clientKey.Bytes())
		key := append([]byte(nil), shared...)
		if !validKey {
			key[0] ^= 1
		}
		endpoint["peers"].([]any)[0].(map[string]any)["pre_shared_key"] = encode(key)
		client := start(config)
		if validKey {
			tcpExchange(client, "wg", tcpTarget)
		}
		udpExchange(client, "wg", udpTarget, validKey)
		closeChecked(client)
	}
	fmt.Println("PASS WireGuard TCP, UDP and wrong-preshared-key rejection")
}

// requireExchangeRefused requires that no payload round-trips. Protocols that
// authenticate lazily (TUIC, VMess, Shadowsocks) return a local stream before
// the server has checked the credential, so a successful dial alone proves
// nothing; the echo must not come back.
func requireExchangeRefused(instance *box.Box, tag, target, detail string) {
	outbound, exists := instance.Outbound().Outbound(tag)
	require(exists, "projected outbound missing")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(target))
	if err != nil {
		return
	}
	// The server has already torn down a refused stream; closing it reports that
	// teardown, not a probe failure.
	defer func() { _ = conn.Close() }()
	require(conn.SetReadDeadline(time.Now().Add(3*time.Second)) == nil, "refused exchange read deadline")
	if _, err := conn.Write([]byte("cfm-roundtrip")); err != nil {
		return
	}
	body := make([]byte, len("cfm-roundtrip"))
	_, err = io.ReadFull(conn, body)
	require(err != nil || string(body) != "cfm-roundtrip", detail)
}

func projectedOutbound(config object, tag string) map[string]any {
	for _, candidate := range config["outbounds"].([]any) {
		if outbound := candidate.(map[string]any); outbound["tag"] == tag {
			return outbound
		}
	}
	panic("projected outbound " + tag + " missing")
}

// serverIdentity is a self-signed server leaf with its PEM encoding and the
// SHA-256 SPKI pin a projected client trusts it by.
type serverIdentity struct {
	certificate, key string
	pin              [32]byte
}

func newServerIdentity(name string, signer crypto.Signer) serverIdentity {
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der := checked(x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer))
	return serverIdentity{
		certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: checked(x509.MarshalPKCS8PrivateKey(signer))})),
		pin:         sha256.Sum256(checked(x509.ParseCertificate(der)).RawSubjectPublicKeyInfo),
	}
}

func ecdsaServerIdentity(name string) serverIdentity {
	key := checked(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	return newServerIdentity(name, key)
}

func (identity serverIdentity) inboundTLS() object {
	return object{"enabled": true, "certificate": []string{identity.certificate}, "key": []string{identity.key}}
}

func (identity serverIdentity) pinnedTLS(name string) object {
	return object{"enabled": true, "server_name": name,
		"certificate_public_key_sha256": []string{base64.StdEncoding.EncodeToString(identity.pin[:])}}
}

// credentialCase holds the secret fields written into the projected outbound
// and whether the server must accept them.
type credentialCase struct {
	secrets  map[string]any
	accepted bool
}

// credentialProbe starts one in-process server per case, projects the CFM
// profile, fills the projected secret fields and requires the exchange to
// succeed only with the server's own credentials.
func credentialProbe(projector, address, tcpTarget, udpTarget, tag string, udp bool, network string,
	server func(port int) object, profile func(port int) object, cases []credentialCase, detail string) {
	closeConn := closeChecked
	if network == "udp" {
		closeConn = closeQUICStream
	}
	for _, current := range cases {
		port := localPort(address, network)
		instance := start(server(port))
		config := project(projector, object{"outbounds": []any{profile(port)}})
		prepareListeners(config, address)
		outbound := projectedOutbound(config, tag)
		for field, value := range current.secrets {
			outbound[field] = value
		}
		client := start(config)
		if current.accepted {
			tcpExchangeClosing(client, tag, tcpTarget, closeConn)
			if udp {
				udpExchange(client, tag, udpTarget, true)
			}
		} else {
			requireExchangeRefused(client, tag, tcpTarget, detail)
		}
		closeChecked(client)
		closeChecked(instance)
	}
}

func tuicProbe(projector, address, tcpTarget, udpTarget string) {
	identity := ecdsaServerIdentity("tuic.example.com")
	const uuid = "33333333-3333-4333-8333-333333333333"
	credentialProbe(projector, address, tcpTarget, udpTarget, "tuic", true, "udp",
		func(port int) object {
			return object{"log": object{"level": "error"},
				"inbounds": []any{object{"type": "tuic", "tag": "tuic-in", "listen": address, "listen_port": port,
					"users": []any{object{"uuid": uuid, "password": "tuic-secret"}}, "congestion_control": "bbr",
					"tls": identity.inboundTLS()}},
				"outbounds": []any{object{"type": "direct", "tag": "direct"}}}
		},
		func(port int) object {
			return object{"type": "tuic", "tag": "tuic", "server": address, "server_port": port,
				"uuid_credential_ref":     object{"id": profileID, "kind": "tuic_uuid"},
				"password_credential_ref": object{"id": sharedID, "kind": "tuic_password"},
				"congestion_control":      "bbr", "udp_relay_mode": "native", "tls": identity.pinnedTLS("tuic.example.com")}
		},
		[]credentialCase{
			{map[string]any{"uuid": uuid, "password": "tuic-secret"}, true},
			{map[string]any{"uuid": uuid, "password": "wrong-secret"}, false},
		}, "TUIC accepted a wrong password")
	fmt.Println("PASS TUIC TCP and UDP over a pinned QUIC leaf, wrong-password rejection")
}

func anytlsProbe(projector, address, tcpTarget, udpTarget string) {
	identity := ecdsaServerIdentity("anytls.example.com")
	credentialProbe(projector, address, tcpTarget, udpTarget, "anytls", false, "tcp",
		func(port int) object {
			return object{"log": object{"level": "error"},
				"inbounds": []any{object{"type": "anytls", "tag": "anytls-in", "listen": address, "listen_port": port,
					"users": []any{object{"password": "anytls-secret"}}, "tls": identity.inboundTLS()}},
				"outbounds": []any{object{"type": "direct", "tag": "direct"}}}
		},
		func(port int) object {
			return object{"type": "anytls", "tag": "anytls", "server": address, "server_port": port,
				"credential_ref": object{"id": profileID, "kind": "anytls_password"},
				"tls":            identity.pinnedTLS("anytls.example.com")}
		},
		[]credentialCase{
			{map[string]any{"password": "anytls-secret"}, true},
			{map[string]any{"password": "wrong-secret"}, false},
		}, "AnyTLS accepted a wrong password")
	fmt.Println("PASS AnyTLS TCP over a pinned TLS leaf, wrong-password rejection")
}

func vmessProbe(projector, address, tcpTarget, udpTarget string) {
	const uuid = "44444444-4444-4444-8444-444444444444"
	credentialProbe(projector, address, tcpTarget, udpTarget, "vmess", true, "tcp",
		func(port int) object {
			return object{"log": object{"level": "error"},
				"inbounds":  []any{object{"type": "vmess", "tag": "vmess-in", "listen": address, "listen_port": port, "users": []any{object{"uuid": uuid}}}},
				"outbounds": []any{object{"type": "direct", "tag": "direct"}}}
		},
		func(port int) object {
			return object{"type": "vmess", "tag": "vmess", "server": address, "server_port": port,
				"credential_ref": object{"id": profileID, "kind": "vmess_uuid"}, "security": "auto"}
		},
		[]credentialCase{
			{map[string]any{"uuid": uuid}, true},
			{map[string]any{"uuid": "55555555-5555-4555-8555-555555555555"}, false},
		}, "VMess accepted a wrong UUID")
	fmt.Println("PASS VMess TCP and UDP, wrong-UUID rejection")
}

func shadowsocksProbe(projector, address, tcpTarget, udpTarget string) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require(err == nil, "Shadowsocks key")
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	encode := base64.StdEncoding.EncodeToString
	credentialProbe(projector, address, tcpTarget, udpTarget, "ss", true, "tcp",
		func(port int) object {
			return object{"log": object{"level": "error"},
				"inbounds": []any{object{"type": "shadowsocks", "tag": "ss-in", "listen": address, "listen_port": port,
					"method": "2022-blake3-aes-128-gcm", "password": encode(key)}},
				"outbounds": []any{object{"type": "direct", "tag": "direct"}}}
		},
		func(port int) object {
			return object{"type": "shadowsocks", "tag": "ss", "server": address, "server_port": port,
				"method": "2022-blake3-aes-128-gcm", "credential_ref": object{"id": profileID, "kind": "shadowsocks_password"}}
		},
		[]credentialCase{
			{map[string]any{"password": encode(key)}, true},
			{map[string]any{"password": encode(wrong)}, false},
		}, "Shadowsocks 2022 accepted a wrong key")
	fmt.Println("PASS Shadowsocks 2022 TCP and UDP, wrong-key rejection")
}

// realityTarget is the TLS 1.3 site a Reality server borrows its handshake
// from. Like a conventional HTTPS front end it sends its session ticket in
// the first flight and prefers X25519MLKEM768. Go selects that group only
// when the client sent its key share; otherwise it asks for a retry, which a
// Reality server does not authenticate. An authenticated Reality handshake
// uses the group this target selects, so each connection reports the group
// the client actually used.
func realityTarget(address string) (int, <-chan tls.CurveID, func()) {
	identity := ecdsaServerIdentity("www.example.com")
	certificate := checked(tls.X509KeyPair([]byte(identity.certificate), []byte(identity.key)))
	listener := checked(tls.Listen("tcp", net.JoinHostPort(address, "0"), &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		NextProtos:       []string{"h2", "http/1.1"},
	}))
	observed := make(chan tls.CurveID, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				panic(err)
			}
			go func() {
				defer closeChecked(conn)
				target := conn.(*tls.Conn)
				// An authenticated Reality client never finishes this handshake.
				_ = target.Handshake()
				observed <- target.ConnectionState().CurveID
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, observed, func() {
		closeChecked(listener)
		<-done
	}
}

// vlessRealityProbe runs the projected VLESS Reality client against an
// in-process Reality server with and without the X25519MLKEM768 key share,
// then proves that a client holding another server key is refused. The probe
// leaves out the xtls-rprx-vision flow: sing-vmess builds Vision's TLS buffer
// pointers from a stored uintptr, which the race detector's checkptr rejects,
// and the flow does not take part in the Reality handshake under test.
func vlessRealityProbe(projector, address, tcpTarget string) {
	targetPort, observed, stopTarget := realityTarget(address)
	defer stopTarget()
	serverKey := checked(ecdh.X25519().GenerateKey(rand.Reader))
	otherKey := checked(ecdh.X25519().GenerateKey(rand.Reader))
	encode := base64.RawURLEncoding.EncodeToString
	const uuid = "66666666-6666-4666-8666-666666666666"
	for _, scenario := range []struct {
		hybrid    bool
		publicKey []byte
		accepted  bool
	}{
		{false, serverKey.PublicKey().Bytes(), true},
		{true, serverKey.PublicKey().Bytes(), true},
		{false, otherKey.PublicKey().Bytes(), false},
	} {
		port := localPort(address, "tcp")
		server := start(object{"log": object{"level": "error"},
			"inbounds": []any{object{"type": "vless", "tag": "vless-in", "listen": address, "listen_port": port,
				"users": []any{object{"uuid": uuid}},
				"tls": object{"enabled": true, "server_name": "www.example.com",
					"reality": object{"enabled": true, "private_key": encode(serverKey.Bytes()), "short_id": []string{"a1b2c3d4"},
						"handshake": object{"server": address, "server_port": targetPort}}}}},
			"outbounds": []any{object{"type": "direct", "tag": "direct"}}})
		reality := object{"enabled": true, "public_key": encode(scenario.publicKey), "short_id": "a1b2c3d4"}
		if scenario.hybrid {
			reality["support_x25519mlkem768"] = true
		}
		config := project(projector, object{"outbounds": []any{object{"type": "vless", "tag": "reality",
			"server": address, "server_port": port,
			"credential_ref": object{"id": profileID, "kind": "vless_uuid"},
			"tls": object{"enabled": true, "server_name": "www.example.com",
				"utls": object{"enabled": true, "fingerprint": "chrome"}, "reality": reality}}}})
		prepareListeners(config, address)
		projectedOutbound(config, "reality")["uuid"] = uuid
		client := start(config)
		if scenario.accepted {
			tcpExchange(client, "reality", tcpTarget)
		} else {
			requireExchangeRefused(client, "reality", tcpTarget, "Reality authenticated a server with another key")
		}
		closeChecked(client)
		closeChecked(server)
		select {
		case group := <-observed:
			expected := tls.X25519
			if scenario.hybrid {
				expected = tls.X25519MLKEM768
			}
			require(!scenario.accepted || group == expected,
				fmt.Sprintf("Reality target negotiated %v, expected %v", group, expected))
		case <-time.After(10 * time.Second):
			panic("Reality target never reported its connection")
		}
	}
	select {
	case group := <-observed:
		panic(fmt.Sprintf("unexpected extra Reality target connection negotiated %v", group))
	default:
	}
	fmt.Println("PASS VLESS Reality TCP with target-observed X25519 and X25519MLKEM768 key exchange, wrong-key rejection")
}

// hysteria2Probe runs the projected Hysteria2 client against an in-process
// Hysteria2 server for salamander and gecko obfuscation, then proves that a
// wrong obfuscation password and a wrong pinned key are both refused.
func hysteria2Probe(projector, address, tcpTarget, udpTarget string) {
	ecdsaServer := ecdsaServerIdentity("hy2.example.com")
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require(err == nil, "Ed25519 server key")
	ed25519Server := newServerIdentity("hy2.example.com", edPrivate)
	otherPin := sha256.Sum256([]byte("a different server key"))
	encode := base64.StdEncoding.EncodeToString
	gecko := object{"min_packet_size": 400, "max_packet_size": 1400}
	for _, scenario := range []struct {
		server       serverIdentity
		obfs         string
		sizes        object
		obfsPassword string
		pin          [32]byte
		accepted     bool
		detail       string
	}{
		{ecdsaServer, "salamander", nil, "mask-secret", ecdsaServer.pin, true, ""},
		{ecdsaServer, "gecko", gecko, "mask-secret", ecdsaServer.pin, true, ""},
		{ecdsaServer, "gecko", gecko, "wrong-mask", ecdsaServer.pin, false, "Hysteria2 accepted a wrong obfuscation password"},
		{ecdsaServer, "gecko", gecko, "mask-secret", otherPin, false, "Hysteria2 accepted a certificate outside its pin"},
		// The Chrome QUIC parrot offers no Ed25519 signature algorithm.
		{ed25519Server, "salamander", nil, "mask-secret", ed25519Server.pin, false, "Hysteria2 completed a Chrome QUIC handshake with an Ed25519 certificate"},
	} {
		port := localPort(address, "udp")
		serverObfs := object{"type": scenario.obfs, "password": "mask-secret"}
		profileObfs := object{"type": scenario.obfs, "credential_ref": object{"id": sharedID, "kind": "hysteria2_obfs_password"}}
		for name, value := range scenario.sizes {
			serverObfs[name] = value
			profileObfs[name] = value
		}
		server := start(object{"log": object{"level": "error"},
			"inbounds": []any{object{"type": "hysteria2", "tag": "hy2-in", "listen": address, "listen_port": port,
				"users": []any{object{"password": "hy-secret"}}, "obfs": serverObfs,
				"tls": object{"enabled": true, "certificate": []string{scenario.server.certificate}, "key": []string{scenario.server.key}}}},
			"outbounds": []any{object{"type": "direct", "tag": "direct"}}})
		config := project(projector, object{"outbounds": []any{object{"type": "hysteria2", "tag": "hy2",
			"server": address, "server_port": port, "bbr_profile": "conservative",
			"credential_ref": object{"id": profileID, "kind": "hysteria2_password"},
			"tls":            object{"enabled": true, "server_name": "hy2.example.com", "certificate_public_key_sha256": []string{encode(scenario.pin[:])}},
			"obfs":           profileObfs}}})
		prepareListeners(config, address)
		outbound := projectedOutbound(config, "hy2")
		outbound["password"] = "hy-secret"
		outbound["obfs"].(map[string]any)["password"] = scenario.obfsPassword
		client := start(config)
		if scenario.accepted {
			tcpExchangeClosing(client, "hy2", tcpTarget, closeQUICStream)
			udpExchange(client, "hy2", udpTarget, true)
		} else {
			requireExchangeRefused(client, "hy2", tcpTarget, scenario.detail)
		}
		closeChecked(client)
		closeChecked(server)
	}
	fmt.Println("PASS Hysteria2 salamander and gecko TCP and UDP; wrong obfuscation password, wrong pin and Ed25519 certificate rejection")
}

func socksServer(address, tag string, port int, username, password string) *box.Box {
	return start(object{"log": object{"level": "error"},
		"inbounds":  []any{object{"type": "mixed", "tag": tag, "listen": address, "listen_port": port, "users": []any{object{"username": username, "password": password}}}},
		"outbounds": []any{object{"type": "direct", "tag": "direct"}}})
}

func groupProbe(projector, address, tcpTarget string) {
	entryPort, exitPort := localPort(address, "tcp"), localPort(address, "tcp")
	username := "local-probe"
	passwordBytes := make([]byte, 32)
	_, err := rand.Read(passwordBytes)
	require(err == nil, "random SOCKS password")
	password := base64.StdEncoding.EncodeToString(passwordBytes)
	entry := socksServer(address, "entry", entryPort, username, password)
	exit := socksServer(address, "exit", exitPort, username, password)
	defer closeChecked(exit)
	node := func(tag string, port int) object {
		return object{"type": "socks5", "tag": tag, "server": address, "server_port": port,
			"authentication": object{"username_credential_ref": object{"id": profileID, "kind": "socks5_username"}, "password_credential_ref": object{"id": sharedID, "kind": "socks5_password"}}}
	}
	profile := object{"outbounds": []any{node("Entry", entryPort), node("Exit", exitPort)}, "detours": object{"Exit": "Entry"}, "route": object{"final": "Exit"}}
	fill := func(config object) {
		prepareListeners(config, address)
		for _, value := range config["outbounds"].([]any) {
			outbound := value.(map[string]any)
			if outbound["type"] == "socks" {
				outbound["username"] = username
				outbound["password"] = password
			}
		}
	}
	config := project(projector, profile)
	fill(config)
	client := start(config)
	tcpExchange(client, "Exit", tcpTarget)
	closeChecked(entry)
	outbound, exists := client.Outbound().Outbound("Exit")
	require(exists, "exit")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(tcpTarget))
	cancel()
	if conn != nil {
		closeChecked(conn)
	}
	require(err != nil, "multihop bypassed the stopped entry")
	closeChecked(client)
	fmt.Println("PASS authenticated multihop forwarding and entry-failure rejection")

	probeListener := checked(net.Listen("tcp", "127.0.0.1:0"))
	httpServer := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(probeListener) }()
	defer func() { closeChecked(httpServer); require(errors.Is(<-done, http.ErrServerClosed), "HTTP server stop") }()
	probeURL := "http://" + probeListener.Addr().String() + "/generate_204"
	profile = object{"outbounds": []any{node("Down", entryPort), node("Healthy", exitPort),
		object{"type": "urltest", "tag": "Auto", "outbounds": []string{"Down", "Healthy"}, "url": probeURL, "interval_seconds": 30, "tolerance_ms": 0, "idle_timeout_seconds": 60}},
		"route": object{"final": "Auto"}}
	config = project(projector, profile)
	fill(config)
	client = start(config)
	defer closeChecked(client)
	automatic, exists := client.Outbound().Outbound("Auto")
	require(exists, "automatic group")
	tester, ok := automatic.(*group.URLTest)
	require(ok, "group algorithm changed")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	_, err = tester.URLTest(ctx)
	require(err == nil, "URL test failed")
	// PostStart begins the first probe asynchronously. Wait for its observable
	// selection, not for an assumed delay or a successful empty probe response.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for tester.Now() != "Healthy" {
		select {
		case <-ctx.Done():
			panic("automatic group did not select the healthy node before its deadline")
		case <-ticker.C:
		}
	}
	cancel()
	require(tester.Now() == "Healthy", "automatic group did not select the healthy node")
	tcpExchange(client, "Auto", tcpTarget)
	fmt.Println("PASS automatic URL test selects and forwards through the healthy node")
}

func fallbackProbe(projector, address, tcpTarget, udpTarget string) {
	primaryPort, backupPort := localPort(address, "tcp"), localPort(address, "tcp")
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require(err == nil, "fallback fixture password")
	password := base64.StdEncoding.EncodeToString(secret)
	primary := socksServer(address, "primary", primaryPort, "fixture", password)
	backup := socksServer(address, "backup", backupPort, "fixture", password)
	defer func() {
		if primary != nil {
			closeChecked(primary)
		}
		if backup != nil {
			closeChecked(backup)
		}
	}()
	listener := checked(net.Listen("tcp", "127.0.0.1:0"))
	httpServer := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	defer func() {
		closeChecked(httpServer)
		require(errors.Is(<-done, http.ErrServerClosed), "fallback HTTP stop")
	}()
	node := func(tag string, port int) object {
		return object{"type": "socks5", "tag": tag, "server": address, "server_port": port,
			"authentication": object{"username_credential_ref": object{"id": profileID, "kind": "socks5_username"}, "password_credential_ref": object{"id": sharedID, "kind": "socks5_password"}}}
	}
	config := project(projector, object{"outbounds": []any{node("Primary", primaryPort), node("Backup", backupPort),
		object{"type": "fallback", "tag": "Failover", "outbounds": []string{"Primary", "Backup"}, "url": "http://" + listener.Addr().String() + "/probe", "interval_seconds": 30, "idle_timeout_seconds": 60}}, "route": object{"final": "Failover"}})
	prepareListeners(config, address)
	for _, value := range config["outbounds"].([]any) {
		outbound := value.(map[string]any)
		if outbound["type"] == "socks" {
			outbound["username"] = "fixture"
			outbound["password"] = password
		}
	}
	client, serviceContext := startWithContext(config, nil)
	defer closeChecked(client)
	outbound, found := client.Outbound().Outbound("Failover")
	require(found && outbound.Type() == "fallback", "ordered group is a first-class runtime type")
	policy, ok := outbound.(*group.URLTest)
	require(ok, "fallback shares the bounded health-check lifecycle")
	history := service.PtrFromContext[urltest.HistoryStorage](serviceContext)
	require(history != nil, "fallback live URL-test history")
	api := config["experimental"].(map[string]any)["clash_api"].(map[string]any)
	apiRequest := checked(http.NewRequest("GET", "http://"+api["external_controller"].(string)+"/version", nil))
	apiRequest.Header.Set("Authorization", "Bearer "+api["secret"].(string))
	apiClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	apiResponse := checked(apiClient.Do(apiRequest))
	closeChecked(apiResponse.Body)
	require(apiResponse.StatusCode == http.StatusOK, "fallback live controller rejected the authenticated request")
	deadline := time.Now().Add(5 * time.Second)
	for history.LoadURLTestHistory("Primary") == nil || history.LoadURLTestHistory("Backup") == nil {
		require(time.Now().Before(deadline), "both fallback services did not become healthy")
		time.Sleep(10 * time.Millisecond)
	}
	require(policy.Now() == "Primary", "priority did not choose primary")
	tcpExchange(client, "Failover", tcpTarget)
	udpExchange(client, "Failover", udpTarget, true)
	closeChecked(primary)
	primary = nil
	// This attempt still starts with Primary's last successful observation. The
	// real failed SOCKS handshake must move it to Backup before any payload.
	tcpExchange(client, "Failover", tcpTarget)
	require(policy.Now() == "Backup", "failed primary remained selected")
	ctx, cancel := context.WithTimeout(interrupt.ContextWithIsExternalConnection(context.Background()), 5*time.Second)
	defer cancel()
	association := checked(policy.ListenPacket(ctx, M.ParseSocksaddr(udpTarget)))
	defer closeChecked(association)
	primary = socksServer(address, "primary", primaryPort, "fixture", password)
	deadline = time.Now().Add(5 * time.Second)
	for policy.Now() != "Primary" {
		policy.CheckOutbounds()
		require(time.Now().Before(deadline), "recovered primary was not restored")
	}
	require(association.SetDeadline(time.Now().Add(2*time.Second)) == nil, "persistent UDP deadline")
	_, err = association.WriteTo([]byte("still-backup"), checked(net.ResolveUDPAddr("udp", udpTarget)))
	require(err == nil, "existing UDP association closed on primary recovery")
	body := make([]byte, 64)
	n, _, err := association.ReadFrom(body)
	require(err == nil && string(body[:n]) == "still-backup", "UDP association did not survive recovery")
	tcpExchange(client, "Failover", tcpTarget)
	closeChecked(primary)
	primary = nil
	closeChecked(backup)
	backup = nil
	conn, err := policy.DialContext(ctx, "tcp", M.ParseSocksaddr(tcpTarget))
	if conn != nil {
		closeChecked(conn)
	}
	require(err != nil && policy.Now() == "", "all-failed fallback escaped to direct or retained healthy status")
	fmt.Println("PASS ordered fallback TCP/UDP, real primary failure, recovery, preserved association and all-failed rejection")
}

type testCertificateStore struct{ pool *x509.CertPool }

func (s testCertificateStore) Name() string                   { return "temporary test CA" }
func (s testCertificateStore) Pool() *x509.CertPool           { return s.pool }
func (s testCertificateStore) ExclusiveAnchors() bool         { return true }
func (s testCertificateStore) Start(adapter.StartStage) error { return nil }
func (s testCertificateStore) Close() error                   { return nil }

type tlsCase uint8

const (
	hybridAccepted tlsCase = iota
	classicalRejected
	echAccepted
	echRejected
)

func tlsProbe(projector string, scenario tlsCase) {
	ech := scenario == echAccepted || scenario == echRejected
	classicalOnly := scenario == classicalRejected
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require(err == nil, "certificate key")
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inner.example.com"},
		DNSNames: []string{"inner.example.com", "public.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der := checked(x509.CreateCertificate(rand.Reader, certificate, certificate, publicKey, privateKey))
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	roots := x509.NewCertPool()
	roots.AddCert(checked(x509.ParseCertificate(der)))
	serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	if classicalOnly {
		serverConfig.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	tlsOptions := object{"enabled": true, "server_name": "inner.example.com", "min_version": "1.3", "curve_preferences": []string{"X25519MLKEM768"}}
	if ech {
		configPEM, keyPEM, err := btls.ECHKeygenDefault("public.example.com")
		require(err == nil, "ECH generation")
		keyBlock, _ := pem.Decode([]byte(keyPEM))
		require(keyBlock != nil, "ECH key")
		serverConfig.EncryptedClientHelloKeys = checked(btls.UnmarshalECHKeys(keyBlock.Bytes))
		if scenario == echRejected {
			serverConfig.EncryptedClientHelloKeys = nil
		}
		tlsOptions["ech"] = object{"enabled": true, "config": []string{configPEM}}
	}
	config := project(projector, object{"outbounds": []any{object{"type": "trojan", "tag": "secure", "server": "inner.example.com", "server_port": 443, "credential_ref": object{"id": profileID, "kind": "trojan_password"}, "tls": tlsOptions}}})
	encoded := checked(json.Marshal(config["outbounds"].([]any)[0].(map[string]any)["tls"]))
	var options option.OutboundTLSOptions
	require(json.Unmarshal(encoded, &options) == nil, "TLS options")
	ctx := service.ContextWith[adapter.CertificateStore](context.Background(), testCertificateStore{roots})
	clientConfig := checked(btls.NewClient(ctx, logger.NOP(), "inner.example.com", options))
	listener := checked(net.Listen("tcp", "127.0.0.1:0"))
	defer closeChecked(listener)
	result := make(chan error, 1)
	observed := make(chan tls.ConnectionState, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer closeChecked(raw)
		require(raw.SetDeadline(time.Now().Add(5*time.Second)) == nil, "TLS server deadline")
		conn := tls.Server(raw, serverConfig)
		err = conn.Handshake()
		observed <- conn.ConnectionState()
		if err == nil {
			body := make([]byte, 1)
			_, err = io.ReadFull(conn, body)
			if err == nil {
				_, err = conn.Write(body)
			}
		}
		result <- err
	}()
	raw := checked(net.DialTimeout("tcp", listener.Addr().String(), time.Second))
	defer closeChecked(raw)
	require(raw.SetDeadline(time.Now().Add(5*time.Second)) == nil, "TLS client deadline")
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, clientErr := stls.ClientHandshake(ctx, raw, clientConfig)
	if scenario == echRejected {
		var rejection *tls.ECHRejectionError
		require(errors.As(clientErr, &rejection), "ECH did not fail explicitly when the server rejected it")
		require(<-result != nil && !(<-observed).ECHAccepted, "ECH rejection carried application data")
		fmt.Println("PASS ECH rejection does not fall back to a plaintext ClientHello")
		return
	}
	if classicalOnly {
		require(clientErr != nil, "required post-quantum mode accepted classical exchange")
		require(<-result != nil && !(<-observed).HandshakeComplete, "classical server did not reject handshake")
		fmt.Println("PASS required post-quantum TLS rejects classical-only server")
		return
	}
	require(clientErr == nil, "TLS handshake failed")
	_, err = conn.Write([]byte{42})
	require(err == nil, "TLS write")
	body := make([]byte, 1)
	_, err = io.ReadFull(conn, body)
	require(err == nil && body[0] == 42, "TLS echo")
	state := <-observed
	require(<-result == nil, "TLS server failed")
	require(state.Version == tls.VersionTLS13 && state.CurveID == tls.X25519MLKEM768 && state.ECHAccepted == ech, "server-observed TLS protection mismatch")
	fmt.Printf("PASS server-observed TLS 1.3 X25519MLKEM768 ECH=%t and encrypted data\n", ech)
}

func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		panic("usage: advanced_protocol_probe PROJECTOR LOCAL_IPV4 [dns-bootstrap|lan]")
	}
	projector, address := os.Args[1], os.Args[2]
	require(net.ParseIP(address) != nil, "local numeric fixture address required")
	if len(os.Args) == 4 {
		switch os.Args[3] {
		case "dns-bootstrap":
			dnsBootstrapProbe(projector, address)
		case "lan":
			lanProbe(projector, address)
		case "http":
			httpProxyProbe(projector, address)
		default:
			panic("unknown protocol fixture case")
		}
		return
	}
	tcpTarget, udpTarget, stop := echoServers(address)
	defer stop()
	tlsProbe(projector, hybridAccepted)
	tlsProbe(projector, classicalRejected)
	tlsProbe(projector, echAccepted)
	tlsProbe(projector, echRejected)
	dnsProbe(projector, address)
	dnsPolicyProbe(projector, address)
	dnsFallbackProbe(projector, address)
	dnsBootstrapProbe(projector, address)
	lanProbe(projector, address)
	httpProxyProbe(projector, address)
	groupProbe(projector, address, tcpTarget)
	fallbackProbe(projector, address, tcpTarget, udpTarget)
	loadBalanceProbe(projector, address, tcpTarget, udpTarget)
	wireguardProbe(projector, address, tcpTarget, udpTarget)
	hysteria2Probe(projector, address, tcpTarget, udpTarget)
	tuicProbe(projector, address, tcpTarget, udpTarget)
	anytlsProbe(projector, address, tcpTarget, udpTarget)
	vmessProbe(projector, address, tcpTarget, udpTarget)
	shadowsocksProbe(projector, address, tcpTarget, udpTarget)
	vlessRealityProbe(projector, address, tcpTarget)
}
