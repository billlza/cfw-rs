// Real transport checks: the observer records calls and delegates unchanged to
// the pinned SOCKS implementation. It does not replace authentication or data.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/socks"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type observedSocks struct {
	adapter.Outbound
	tcpTarget, udpTarget string
	tcp, udp             atomic.Int32
}

func (s *observedSocks) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == "tcp" && destination.String() == s.tcpTarget {
		s.tcp.Add(1)
	}
	return s.Outbound.DialContext(ctx, network, destination)
}
func (s *observedSocks) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.String() == s.udpTarget {
		s.udp.Add(1)
	}
	return s.Outbound.ListenPacket(ctx, destination)
}

func loadBalanceProbe(projector, address, tcpTarget, udpTarget string) {
	for _, strategy := range []string{"consistent-hashing", "sticky-sessions", "round-robin"} {
		func() {
			ports := []int{localPort(address, "tcp"), localPort(address, "tcp")}
			servers := []*box.Box{socksServer(address, "a", ports[0], "fixture", "local-probe-secret"), socksServer(address, "b", ports[1], "fixture", "local-probe-secret")}
			defer func() {
				for _, server := range servers {
					if server != nil {
						closeChecked(server)
					}
				}
			}()
			listener := checked(net.Listen("tcp", "127.0.0.1:0"))
			httpServer := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })}
			done := make(chan error, 1)
			go func() { done <- httpServer.Serve(listener) }()
			defer func() {
				closeChecked(httpServer)
				require(errors.Is(<-done, http.ErrServerClosed), "balance health server cleanup")
			}()
			node := func(tag string, port int) object {
				return object{"type": "socks5", "tag": tag, "server": address, "server_port": port,
					"authentication": object{"username_credential_ref": object{"id": profileID, "kind": "socks5_username"}, "password_credential_ref": object{"id": sharedID, "kind": "socks5_password"}}}
			}
			healthURL := "http://" + listener.Addr().String() + "/health"
			config := project(projector, object{"outbounds": []any{node("A", ports[0]), node("B", ports[1]),
				object{"type": "loadbalance", "tag": "Balanced", "outbounds": []string{"A", "B"}, "url": healthURL, "interval_seconds": 30, "idle_timeout_seconds": 60, "strategy": strategy, "lazy": false}},
				"providers": object{"proxies": []any{object{"name": "Pool", "source": object{"interval_seconds": 0}, "members": []any{object{"tag": "A", "name": "First"}, object{"tag": "B", "name": "Second"}}, "health_check": object{"url": healthURL, "interval_seconds": 60, "timeout_ms": 1000, "expected_status": "204", "lazy": false}}}, "groups": []any{object{"group": "Balanced", "local_members": []string{}, "providers": []string{"Pool"}}}},
				"route":     object{"final": "Balanced"}})
			prepareListeners(config, address)
			for _, value := range config["outbounds"].([]any) {
				entry := value.(map[string]any)
				if entry["type"] == "socks" {
					entry["username"] = "fixture"
					entry["password"] = "local-probe-secret"
				}
			}
			observations := make(map[string]*observedSocks)
			registry := include.OutboundRegistry()
			outbound.Register[option.SOCKSOutboundOptions](registry, "socks", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
				original, err := socks.NewOutbound(ctx, router, logger, tag, options)
				if err != nil {
					return nil, err
				}
				observer := &observedSocks{Outbound: original, tcpTarget: tcpTarget, udpTarget: udpTarget}
				observations[tag] = observer
				return observer, nil
			})
			ctx := box.Context(service.ContextWithDefaultRegistry(context.Background()), include.InboundRegistry(), registry, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
			options := checked(sjson.UnmarshalExtendedContext[option.Options](ctx, checked(json.Marshal(config))))
			client := checked(box.New(box.Options{Context: ctx, Options: options}))
			require(client.StartWithExternalCleanup() == nil, "balance core startup")
			defer closeChecked(client)
			selected, ok := client.Outbound().Outbound("Balanced")
			require(ok && selected.Type() == "loadbalance", "native balance type")
			policy, ok := selected.(*group.URLTest)
			require(ok, "native balance implementation")
			probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results := checked(policy.URLTest(probeCtx))
			require(len(results) == 2, "both real SOCKS services healthy")
			require(policy.Now() == "", "a balance group must not invent one selected node")
			for i := 0; i < 6; i++ {
				tcpExchange(client, "Balanced", tcpTarget)
			}
			for i := 0; i < 6; i++ {
				udpExchange(client, "Balanced", udpTarget, true)
			}
			a, b := observations["A"], observations["B"]
			if strategy == "round-robin" {
				require(a.tcp.Load() == 3 && b.tcp.Load() == 3 && a.udp.Load() == 3 && b.udp.Load() == 3, "round-robin did not use both real transports evenly")
			} else {
				require((a.tcp.Load() == 6 && a.udp.Load() == 6 && b.tcp.Load() == 0 && b.udp.Load() == 0) || (b.tcp.Load() == 6 && b.udp.Load() == 6 && a.tcp.Load() == 0 && a.udp.Load() == 0), "stable destination split across TCP/UDP nodes")
			}
			// The endpoint is app-owned and authenticated. Hidden health groups are
			// present in the API with explicit metadata, allowing the UI to omit them.
			api := config["experimental"].(map[string]any)["clash_api"].(map[string]any)
			request := checked(http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+api["external_controller"].(string)+"/proxies", nil))
			request.Header.Set("Authorization", "Bearer "+api["secret"].(string))
			response := checked((&http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}).Do(request))
			var snapshot struct {
				Proxies map[string]struct {
					Hidden bool `json:"hidden"`
				} `json:"proxies"`
			}
			require(response.StatusCode == 200 && json.NewDecoder(response.Body).Decode(&snapshot) == nil, "authenticated proxy snapshot")
			closeChecked(response.Body)
			require(snapshot.Proxies["cfw-provider-health-0"].Hidden, "provider health group lost hidden metadata")
			// Only connection establishment is retried after a real remote shutdown.
			closeChecked(servers[0])
			servers[0] = nil
			for i := 0; i < 3; i++ {
				tcpExchange(client, "Balanced", tcpTarget)
				udpExchange(client, "Balanced", udpTarget, true)
			}
			closeChecked(servers[1])
			servers[1] = nil
			conn, err := policy.DialContext(probeCtx, "tcp", M.ParseSocksaddr(tcpTarget))
			if conn != nil {
				closeChecked(conn)
			}
			require(err != nil, "all-failed balance group bypassed its configured remotes")
			fmt.Println("PASS real TCP/UDP balance", strategy, "remote failure recovery and provider health metadata")
		}()
	}
}
