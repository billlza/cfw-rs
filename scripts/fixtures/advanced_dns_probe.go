package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func dnsAnswer(query []byte) []byte {
	var request dns.Msg
	require(request.Unpack(query) == nil, "DNS request decode")
	require(len(request.Question) == 1 && (request.Question[0].Name == "probe.invalid." || request.Question[0].Name == "singlelabel.") && request.Question[0].Qtype == dns.TypeA, "unexpected DNS question")
	var response dns.Msg
	response.SetReply(&request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("203.0.113.7")}}
	return checked(response.Pack())
}

func dnsCertificate() (tls.Certificate, *x509.CertPool) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require(err == nil, "DNS certificate key")
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"resolver.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der := checked(x509.CreateCertificate(rand.Reader, template, template, public, private))
	roots := x509.NewCertPool()
	roots.AddCert(checked(x509.ParseCertificate(der)))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, roots
}

func dnsFixture(kind, address string, certificate tls.Certificate, handlers ...func([]byte) []byte) (int, func()) {
	require(len(handlers) <= 1, "one DNS response handler")
	answerQuery := dnsAnswer
	if len(handlers) == 1 {
		answerQuery = handlers[0]
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		var answer dns.Msg
		require(answer.Unpack(answerQuery(checked(request.Pack()))) == nil, "DNS answer decode")
		require(w.WriteMsg(&answer) == nil, "DNS answer write")
	})
	if kind == "udp" || kind == "tcp" || kind == "tls" {
		server := &dns.Server{Handler: handler, ReadTimeout: time.Second, WriteTimeout: time.Second}
		port := 0
		if kind == "udp" {
			pc := checked(net.ListenPacket("udp", net.JoinHostPort(address, "0")))
			server.PacketConn = pc
			port = pc.LocalAddr().(*net.UDPAddr).Port
		} else {
			ln := checked(net.Listen("tcp", net.JoinHostPort(address, "0")))
			port = ln.Addr().(*net.TCPAddr).Port
			if kind == "tls" {
				ln = tls.NewListener(ln, tlsConfig)
			}
			server.Listener = ln
		}
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		done := make(chan error, 1)
		go func() { done <- server.ActivateAndServe() }()
		select {
		case <-ready:
		case err := <-done:
			panic(fmt.Errorf("DNS fixture startup: %w", err))
		case <-time.After(5 * time.Second):
			panic("DNS fixture startup timed out")
		}
		return port, func() {
			require(server.Shutdown() == nil, "DNS server shutdown")
			require(<-done == nil, "DNS server completion")
		}
	}
	if kind == "quic" {
		tlsConfig.NextProtos = []string{"doq"}
		pc := checked(net.ListenPacket("udp", net.JoinHostPort(address, "0")))
		ln := checked(quic.Listen(pc, tlsConfig, &quic.Config{}))
		ctx, cancel := context.WithCancel(context.Background())
		var workers sync.WaitGroup
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				conn, err := ln.Accept(ctx)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					panic(err)
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { require(conn.CloseWithError(0, "") == nil, "DoQ connection close") }()
					for {
						stream, err := conn.AcceptStream(ctx)
						if ctx.Err() != nil || conn.Context().Err() != nil {
							return
						}
						if err != nil {
							panic(err)
						}
						require(stream.SetDeadline(time.Now().Add(5*time.Second)) == nil, "DoQ deadline")
						var size uint16
						require(binary.Read(stream, binary.BigEndian, &size) == nil && size <= 4096, "DoQ length")
						body := make([]byte, size)
						_, err = io.ReadFull(stream, body)
						require(err == nil, "DoQ body")
						answer := answerQuery(body)
						require(binary.Write(stream, binary.BigEndian, uint16(len(answer))) == nil, "DoQ response length")
						_, err = stream.Write(answer)
						require(err == nil, "DoQ response")
						require(stream.Close() == nil, "DoQ stream close")
					}
				}()
			}
		}()
		return pc.LocalAddr().(*net.UDPAddr).Port, func() { cancel(); closeChecked(ln); workers.Wait(); closeChecked(pc) }
	}
	doh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		if r.Method == "GET" {
			payload = checked(base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns")))
		} else {
			payload = checked(io.ReadAll(io.LimitReader(r.Body, 4097)))
			closeChecked(r.Body)
		}
		require(len(payload) <= 4096, "DoH body bound")
		w.Header().Set("Content-Type", "application/dns-message")
		_, err := w.Write(answerQuery(payload))
		require(err == nil, "DoH response")
	})
	if kind == "https" {
		ln := checked(net.Listen("tcp", net.JoinHostPort(address, "0")))
		server := &http.Server{Handler: doh, TLSConfig: tlsConfig, ReadHeaderTimeout: time.Second}
		done := make(chan error, 1)
		go func() { done <- server.ServeTLS(ln, "", "") }()
		return ln.Addr().(*net.TCPAddr).Port, func() { closeChecked(server); require(errors.Is(<-done, http.ErrServerClosed), "DoH server close") }
	}
	require(kind == "http3", "unknown DNS transport")
	pc := checked(net.ListenPacket("udp", net.JoinHostPort(address, "0")))
	server := &http3.Server{Handler: doh, TLSConfig: tlsConfig}
	done := make(chan error, 1)
	go func() { done <- server.Serve(pc) }()
	return pc.LocalAddr().(*net.UDPAddr).Port, func() {
		closeChecked(server)
		err := <-done
		require(errors.Is(err, http.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed), "HTTP3 server close")
		closeChecked(pc)
	}
}

func dnsProbe(projector, address string) {
	dnsProbeRoute(projector, address, false)
	dnsProbeRoute(projector, address, true)
}

func dnsProbeRoute(projector, address string, viaSOCKS bool) {
	certificate, roots := dnsCertificate()
	outbounds := []any{object{"type": "direct", "tag": "direct"}}
	username, password := "dns-probe", ""
	if viaSOCKS {
		passwordBytes := make([]byte, 32)
		_, err := rand.Read(passwordBytes)
		require(err == nil, "random DNS relay credential")
		password = base64.StdEncoding.EncodeToString(passwordBytes)
		port := localPort(address, "tcp")
		relay := socksServer(address, "dns-relay", port, username, password)
		defer closeChecked(relay)
		outbounds = []any{object{"type": "socks5", "tag": "dns-relay", "server": address, "server_port": port,
			"authentication": object{"username_credential_ref": object{"id": profileID, "kind": "socks5_username"}, "password_credential_ref": object{"id": sharedID, "kind": "socks5_password"}}}}
	}
	for _, kind := range []string{"udp", "tcp", "tls", "https", "quic", "http3"} {
		port, stop := dnsFixture(kind, address, certificate)
		resolver := object{"type": kind, "server": address, "server_port": port}
		if kind == "http3" {
			resolver["type"] = "h3"
		}
		if kind != "udp" && kind != "tcp" {
			resolver["tls"] = object{"enabled": true, "server_name": "resolver.example.com", "min_version": "1.3"}
		}
		if kind == "https" || kind == "http3" {
			resolver["path"] = "/dns-query"
		}
		config := project(projector, object{"outbounds": outbounds, "dns": object{"servers": []any{resolver}}})
		prepareListeners(config, address)
		if viaSOCKS {
			for _, value := range config["outbounds"].([]any) {
				node := value.(map[string]any)
				if node["type"] == "socks" {
					node["username"], node["password"] = username, password
				}
			}
		}
		instance, ctx := startWithContext(config, roots)
		router := service.FromContext[adapter.DNSRouter](ctx)
		require(router != nil, "DNS router")
		query := new(dns.Msg)
		query.SetQuestion("probe.invalid.", dns.TypeA)
		// Fresh queries must reuse a healthy transport after the preceding
		// request context has been cancelled; cached answers cannot prove it.
		for attempt := 0; attempt < 3; attempt++ {
			requestCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			answer, err := router.Exchange(requestCtx, query, adapter.DNSQueryOptions{DisableCache: true})
			cancel()
			if err != nil {
				closeChecked(instance)
				stop()
				panic(fmt.Errorf("DNS %s through SOCKS=%t attempt=%d: %w", kind, viaSOCKS, attempt, err))
			}
			require(len(answer.Answer) == 1, "DNS answer count")
			addressAnswer, ok := answer.Answer[0].(*dns.A)
			require(ok && addressAnswer.A.Equal(net.ParseIP("203.0.113.7")), "DNS answer")
		}
		closeChecked(instance)
		stop()
		fmt.Printf("PASS DNS %s through SOCKS=%t: three uncached exchanges after request cancellation\n", kind, viaSOCKS)
	}
}

// Run the real TUN DNS projection without opening an OS tunnel. This exercises
// DNS policy and persistence; packet-flow acceptance remains a separate test.
func dnsPolicyProbe(projector, address string) {
	certificate, _ := dnsCertificate()
	port, stop := dnsFixture("udp", address, certificate)
	defer stop()
	cacheDirectory := checked(os.MkdirTemp("", "cfm-dns-policy-"))
	defer func() { require(os.RemoveAll(cacheDirectory) == nil, "DNS fixture cleanup") }()
	profile := object{"outbounds": []any{object{"type": "direct", "tag": "direct"}},
		"hosts": object{"node.example.com": []string{"9.9.9.9"}},
		"dns": object{"servers": []any{object{"type": "udp", "server": address, "server_port": port}},
			"ipv6": false, "fake_ip": object{"exclude": []string{"+.invalid"}}}}
	config := projectMode(projector, profile, true)
	config["inbounds"] = []any{object{"type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1", "listen_port": localPort("127.0.0.1", "tcp")}}
	prepareListeners(config, address)
	config["experimental"].(map[string]any)["cache_file"].(map[string]any)["path"] = filepath.Join(cacheDirectory, "routing-cache.db")
	query := func(ctx context.Context, name string, kind uint16) *dns.Msg {
		router := service.FromContext[adapter.DNSRouter](ctx)
		require(router != nil, "policy DNS router")
		request := new(dns.Msg)
		request.SetQuestion(name, kind)
		requestCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return checked(router.Exchange(requestCtx, request, adapter.DNSQueryOptions{}))
	}
	instance, ctx := startWithContext(config, nil)
	host := query(ctx, "node.example.com.", dns.TypeA)
	require(len(host.Answer) == 1 && host.Answer[0].(*dns.A).A.Equal(net.ParseIP("9.9.9.9")), "hosts lost to fake-IP")
	excluded := query(ctx, "probe.invalid.", dns.TypeA)
	require(len(excluded.Answer) == 1 && excluded.Answer[0].(*dns.A).A.Equal(net.ParseIP("203.0.113.7")), "fake-IP exclusion lost")
	fake := query(ctx, "fake.example.com.", dns.TypeA)
	require(len(fake.Answer) == 1, "fake-IP answer count")
	fakeAddress := fake.Answer[0].(*dns.A).A
	_, pool, err := net.ParseCIDR("198.19.0.0/16")
	require(err == nil && pool.Contains(fakeAddress), "fake-IP outside app pool")
	v6 := query(ctx, "fake.example.com.", dns.TypeAAAA)
	require(v6.Rcode == dns.RcodeSuccess && len(v6.Answer) == 0, "disabled IPv6 returned an address")
	closeChecked(instance)
	instance, ctx = startWithContext(config, nil)
	restored := query(ctx, "fake.example.com.", dns.TypeA)
	require(len(restored.Answer) == 1 && restored.Answer[0].(*dns.A).A.Equal(fakeAddress), "fake-IP identity lost on restart")
	closeChecked(instance)
	fmt.Println("PASS DNS hosts, fake-IP exclusion, AAAA disabled, distinct pool and restart persistence")
	profile["dns"].(map[string]any)["ipv6"] = true
	profile["dns"].(map[string]any)["fake_ip"] = object{"exclude": []string{"*.invalid", "*"}}
	next := projectMode(projector, profile, true)
	next["inbounds"] = config["inbounds"]
	next["experimental"] = config["experimental"]
	instance, ctx = startWithContext(next, nil)
	for _, name := range []string{"probe.invalid.", "singlelabel."} {
		answer := query(ctx, name, dns.TypeA)
		require(len(answer.Answer) == 1 && answer.Answer[0].(*dns.A).A.Equal(net.ParseIP("203.0.113.7")), "single-label wildcard exclusion")
	}
	deep := query(ctx, "deep.probe.invalid.", dns.TypeA)
	require(len(deep.Answer) == 1 && pool.Contains(deep.Answer[0].(*dns.A).A), "wildcard incorrectly matched multiple labels")
	v6 = query(ctx, "v6.example.com.", dns.TypeAAAA)
	_, pool6, err := net.ParseCIDR("2001:2:ffff::/48")
	require(err == nil && len(v6.Answer) == 1 && pool6.Contains(v6.Answer[0].(*dns.AAAA).AAAA), "fake IPv6 outside app pool")
	closeChecked(instance)
	fmt.Println("PASS DNS single-label wildcard semantics and enabled IPv6 fake-IP")
}

// Exercise fallback with real TLS handshakes and DNS messages. A certificate
// identity failure may select only the explicitly configured second resolver;
// it must never turn off certificate validation or invent an empty answer.
func dnsFallbackProbe(projector, address string) {
	certificate, roots := dnsCertificate()
	primaryPort, stopPrimary := dnsFixture("https", address, certificate)
	defer stopPrimary()
	secondaryPort, stopSecondary := dnsFixture("https", address, certificate)
	defer stopSecondary()
	for _, bothRejected := range []bool{false, true, false} {
		server := func(port int, name string) object {
			return object{"type": "https", "server": address, "server_port": port,
				"path": "/dns-query", "tls": object{"enabled": true, "server_name": name, "min_version": "1.3"}}
		}
		secondaryName := "resolver.example.com"
		if bothRejected {
			secondaryName = "wrong-resolver.example.com"
		}
		config := project(projector, object{
			"outbounds": []any{object{"type": "direct", "tag": "direct"}},
			"dns": object{"servers": []any{
				server(primaryPort, "wrong-resolver.example.com"),
				server(secondaryPort, secondaryName),
			}},
		})
		prepareListeners(config, address)
		instance, ctx := startWithContext(config, roots)
		router := service.FromContext[adapter.DNSRouter](ctx)
		require(router != nil, "fallback DNS router")
		query := new(dns.Msg)
		query.SetQuestion("probe.invalid.", dns.TypeA)
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		response, err := router.Exchange(requestCtx, query, adapter.DNSQueryOptions{})
		cancel()
		closeChecked(instance)
		if bothRejected {
			require(err != nil && response == nil, "untrusted resolvers returned a successful DNS response")
			fmt.Println("PASS DNS rejects both invalid TLS identities without returning a successful answer")
			continue
		}
		require(err == nil && response != nil && len(response.Answer) == 1, "authenticated DNS fallback response")
		answer, ok := response.Answer[0].(*dns.A)
		require(ok && answer.A.Equal(net.ParseIP("203.0.113.7")), "authenticated DNS fallback answer")
		fmt.Println("PASS failed primary TLS identity uses the authenticated TLS 1.3 fallback, including after restart")
	}
}
