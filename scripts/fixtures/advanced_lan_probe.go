// The product configuration comes from Rust. The external SOCKS client binds
// an explicit source address to exercise both sides of the LAN source policy.
package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func lanProbe(projector, address string) {
	require(net.ParseIP(address).IsPrivate(), "LAN fixture requires a private IPv4 address")
	lanPort := localPort("0.0.0.0", "tcp")
	mixedPort := localPort("127.0.0.1", "tcp")
	require(lanPort != mixedPort, "fixture port collision")
	config := projectInput(projector, object{
		"profile_id": profileID,
		"profile":    object{"outbounds": []any{object{"type": "direct", "tag": "DIRECT"}}},
		"runtime_preferences": object{
			"preferred_mixed_port": mixedPort, "log_level": "error", "tunnel_mtu": 1400,
			"allow_lan": true, "lan_proxy": object{
				"listen": "0.0.0.0", "port": lanPort,
				"allowed_source_cidrs": []string{address + "/32"},
			},
		},
	})
	api := config["experimental"].(map[string]any)["clash_api"].(map[string]any)
	api["external_controller"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort("127.0.0.1", "tcp")))
	engine := start(config)
	defer closeChecked(engine)
	tcpTarget, udpTarget, stop := echoServers("127.0.0.1")
	defer stop()
	for _, source := range []string{address, "127.0.0.1"} {
		client := start(object{
			"log": object{"level": "error"},
			"outbounds": []any{object{
				"type": "socks", "tag": "external-client", "server": source,
				"server_port": lanPort, "inet4_bind_address": source,
			}},
		})
		if source == address {
			tcpExchange(client, "external-client", tcpTarget)
			udpExchange(client, "external-client", udpTarget, true)
		} else {
			outbound, exists := client.Outbound().Outbound("external-client")
			require(exists, "external client missing")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(tcpTarget))
			if conn != nil {
				closeChecked(conn)
			}
			require(err != nil, "LAN source restriction forwarded a forbidden TCP connection")
			packet, err := outbound.ListenPacket(ctx, M.ParseSocksaddr(udpTarget))
			if err == nil {
				require(packet.SetDeadline(time.Now().Add(time.Second)) == nil, "LAN UDP deadline")
				_, writeErr := packet.WriteTo([]byte("cfm-forbidden"), checked(net.ResolveUDPAddr("udp", udpTarget)))
				if writeErr == nil {
					body := make([]byte, 64)
					_, _, readErr := packet.ReadFrom(body)
					require(readErr != nil, "LAN source restriction forwarded a forbidden datagram")
				}
				closeChecked(packet)
			}
			cancel()
		}
		closeChecked(client)
	}
	fmt.Println("LAN sharing: allowed TCP/UDP round trips and denied source rejection passed")
}
