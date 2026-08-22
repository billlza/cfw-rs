import CFWLibboxRuntime
import Foundation
import Testing

#if canImport(Libbox)
  @Test func pinnedLibboxAcceptsProjectedLegacyVMessSelectorShape() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [
          {
            "type": "vmess",
            "tag": "legacy-vmess-primary",
            "server": "1.1.1.1",
            "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "security": "auto",
            "alter_id": 1
          },
          {
            "type": "vmess",
            "tag": "legacy-vmess-secondary",
            "server": "8.8.8.8",
            "server_port": 443,
            "uuid": "22222222-2222-4222-8222-222222222222",
            "security": "auto"
          },
          {
            "type": "selector",
            "tag": "cfw-proxy-selector",
            "outbounds": ["legacy-vmess-primary", "legacy-vmess-secondary"],
            "default": "legacy-vmess-primary",
            "interrupt_exist_connections": false
          }
        ],
        "route": { "final": "cfw-proxy-selector" }
      }
      """#.utf8
    )

    try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
  }

  @Test func pinnedLibboxAcceptsProjectedAnyTLSAndTUICShape() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [
          {
            "type": "anytls",
            "tag": "anytls",
            "server": "1.1.1.1",
            "server_port": 443,
            "password": "anytls-secret",
            "tls": {
              "enabled": true,
              "server_name": "anytls.example.com",
              "min_version": "1.3"
            }
          },
          {
            "type": "tuic",
            "tag": "tuic",
            "server": "8.8.8.8",
            "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "password": "tuic-secret",
            "congestion_control": "bbr",
            "udp_relay_mode": "quic",
            "zero_rtt_handshake": false,
            "tls": {
              "enabled": true,
              "server_name": "tuic.example.com",
              "min_version": "1.3",
              "alpn": ["h3"]
            }
          },
          {
            "type": "selector",
            "tag": "cfw-proxy-selector",
            "outbounds": ["anytls", "tuic"],
            "default": "anytls",
            "interrupt_exist_connections": false
          }
        ],
        "route": { "final": "cfw-proxy-selector" }
      }
      """#.utf8
    )

    try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
  }

  @Test func pinnedLibboxAcceptsProjectedHysteria2PortHoppingShape() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [
          {
            "type": "hysteria2",
            "tag": "hysteria2",
            "server": "1.1.1.1",
            "server_port": 443,
            "server_ports": ["443:443", "5000:5002"],
            "hop_interval": "30s",
            "password": "hysteria2-secret",
            "tls": {
              "enabled": true,
              "server_name": "hysteria2.example.com",
              "min_version": "1.3"
            }
          }
        ],
        "route": { "final": "hysteria2" }
      }
      """#.utf8
    )

    try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
  }

  @Test func pinnedLibboxAcceptsStandardTLSV2RayQUICAndHTTPMethodShape() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [
          {
            "type": "vmess",
            "tag": "vmess-quic",
            "server": "1.1.1.1",
            "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "security": "auto",
            "tls": {
              "enabled": true,
              "server_name": "quic.example.com",
              "min_version": "1.2"
            },
            "transport": { "type": "quic" }
          },
          {
            "type": "vmess",
            "tag": "vmess-http",
            "server": "8.8.8.8",
            "server_port": 80,
            "uuid": "22222222-2222-4222-8222-222222222222",
            "security": "auto",
            "transport": {
              "type": "http",
              "method": "GET",
              "path": "/tunnel",
              "host": ["edge.example.com"]
            }
          }
        ],
        "route": { "final": "vmess-quic" }
      }
      """#.utf8
    )

    try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
  }

  @Test func pinnedLibboxRejectsV2RayQUICWithoutTLS() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [
          {
            "type": "vmess",
            "tag": "vmess-quic",
            "server": "1.1.1.1",
            "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "security": "auto",
            "transport": { "type": "quic" }
          }
        ],
        "route": { "final": "vmess-quic" }
      }
      """#.utf8
    )

    #expect(throws: LibboxRuntimeError.self) {
      try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
    }
  }
#endif
