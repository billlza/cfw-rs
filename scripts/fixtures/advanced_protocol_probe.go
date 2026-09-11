// Run from the pinned, patched sing-box module with the product's build tags.
// The Rust projector validates every client profile. Servers use ephemeral
// credentials and local listeners; no system proxy, route or DNS setting changes.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
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
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	btls "github.com/sagernet/sing-box/common/tls"
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
	input := checked(json.Marshal(object{"profile": profile, "profile_id": profileID, "tunnel": tunnel}))
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
	outbound, exists := instance.Outbound().Outbound(tag)
	require(exists, "projected outbound missing")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := checked(outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(target)))
	defer closeChecked(conn)
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
	require(conn.SetDeadline(time.Now().Add(2*time.Second)) == nil, "UDP deadline")
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

type testCertificateStore struct{ pool *x509.CertPool }

func (s testCertificateStore) Name() string                   { return "temporary test CA" }
func (s testCertificateStore) Pool() *x509.CertPool           { return s.pool }
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
	if len(os.Args) != 3 {
		panic("usage: advanced_protocol_probe PROJECTOR LOCAL_IPV4")
	}
	projector, address := os.Args[1], os.Args[2]
	require(net.ParseIP(address) != nil, "local numeric fixture address required")
	tcpTarget, udpTarget, stop := echoServers(address)
	defer stop()
	tlsProbe(projector, hybridAccepted)
	tlsProbe(projector, classicalRejected)
	tlsProbe(projector, echAccepted)
	tlsProbe(projector, echRejected)
	dnsProbe(projector, address)
	dnsPolicyProbe(projector, address)
	dnsFallbackProbe(projector, address)
	groupProbe(projector, address, tcpTarget)
	wireguardProbe(projector, address, tcpTarget, udpTarget)
}
