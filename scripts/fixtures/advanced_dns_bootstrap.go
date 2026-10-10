package main

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	"net"
	"sync/atomic"
	"time"
)

func dnsBootstrapProbe(projector, address string) {
	certificate, roots := dnsCertificate()
	var ordinaryCalls, bootstrapCalls atomic.Int32
	ordinaryPort, stopOrdinary := dnsFixture("tcp", address, certificate, func(query []byte) []byte { ordinaryCalls.Add(1); return dnsAnswer(query) })
	defer stopOrdinary()
	bootstrapPort, stopBootstrap := dnsFixture("https", address, certificate, func(query []byte) []byte {
		bootstrapCalls.Add(1)
		var request dns.Msg
		require(request.Unpack(query) == nil && len(request.Question) == 1, "bootstrap DNS request")
		require(request.Question[0].Name == "bootstrap.resolver.test.", "unexpected bootstrap name")
		var response dns.Msg
		response.SetReply(&request)
		if request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP(address)}}
		}
		return checked(response.Pack())
	})
	defer stopBootstrap()
	for _, trusted := range []bool{true, false} {
		serverName := "resolver.example.com"
		if !trusted {
			serverName = "wrong.example.com"
		}
		profile := object{"outbounds": []any{object{"type": "direct", "tag": "direct"}}, "dns": object{
			"servers":           []any{object{"type": "tcp", "server": "bootstrap.resolver.test", "server_port": ordinaryPort, "route": "direct"}},
			"bootstrap_servers": []any{object{"type": "https", "server": address, "server_port": bootstrapPort, "path": "/dns-query", "tls": object{"enabled": true, "server_name": serverName}}},
		}}
		config := project(projector, profile)
		prepareListeners(config, address)
		instance, ctx := startWithContext(config, roots)
		router := service.FromContext[adapter.DNSRouter](ctx)
		require(router != nil, "bootstrap DNS router")
		before := ordinaryCalls.Load()
		query := new(dns.Msg)
		query.SetQuestion("probe.invalid.", dns.TypeA)
		requestCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		response, err := router.Exchange(requestCtx, query, adapter.DNSQueryOptions{DisableCache: true})
		cancel()
		if trusted {
			require(err == nil && len(response.Answer) == 1 && bootstrapCalls.Load() > 0 && ordinaryCalls.Load() > before, "encrypted bootstrap did not resolve the DNS endpoint")
		} else {
			require(err != nil && ordinaryCalls.Load() == before, "invalid bootstrap certificate bypassed authentication")
		}
		closeChecked(instance)
	}
	fmt.Println("PASS encrypted bootstrap resolves a domain DNS endpoint; invalid TLS identity has no plaintext fallback")
}
