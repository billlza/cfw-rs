import CFWLibboxRuntime
import Foundation
import Testing

#if canImport(Libbox)
  /// Checks `configuration` and expects libbox to read and refuse it, rather
  /// than to fail to check it or to close what the check built.
  private func expectRejection(
    _ configuration: Data, sourceLocation: SourceLocation = #_sourceLocation
  ) {
    do {
      try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
      Issue.record("libbox accepted the configuration", sourceLocation: sourceLocation)
    } catch LibboxRuntimeError.configurationCheckFailed {
      // libbox read the configuration and refused it.
    } catch {
      Issue.record(
        "the check failed instead of rejecting: \(error)", sourceLocation: sourceLocation)
    }
  }

  @Test func linkedRuntimeImplementationIsAvailable() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer {
      do { try FileManager.default.removeItem(at: root) } catch { Issue.record(error) }
    }
    let directories = try LibboxRuntimeDirectories.prepare(container: root, role: .systemProxy)
    let runtime = try SourceBuiltLibboxServiceRuntime(role: .systemProxy, directories: directories)
    try runtime.stop()
  }

  @Test func pinnedLibboxAcceptsProjectedSOCKS5AnonymousAndAuthenticatedShapes() throws {
    for network: String? in [nil, "tcp", "udp"] {
      var anonymous: [String: Any] = [
        "type": "socks", "version": "5", "tag": "anonymous",
        "server": "9.9.9.9", "server_port": 1080,
      ]
      var authenticated: [String: Any] = [
        "type": "socks", "version": "5", "tag": "authenticated",
        "server": "2606:4700:4700::1111", "server_port": 29177,
        "username": " synthetic-user ", "password": " synthetic:secret ",
      ]
      if let network {
        anonymous["network"] = network
        authenticated["network"] = network
      }
      let configuration = try JSONSerialization.data(withJSONObject: [
        "log": ["level": "error"],
        "outbounds": [anonymous, authenticated],
        "route": ["final": "authenticated"],
      ])
      try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
    }
  }

  @Test func pinnedLibboxRejectsUnsupportedSOCKS5TLSExtension() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [{
          "type": "socks", "version": "5", "tag": "proxy",
          "server": "9.9.9.9", "server_port": 1080,
          "tls": { "enabled": true, "server_name": "proxy.example.com" }
        }]
      }
      """#.utf8
    )
    expectRejection(configuration)
  }

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

  @Test func pinnedLibboxAcceptsTheRealityHybridKeyShareOnlyWithChrome() throws {
    func configuration(fingerprint: String) throws -> Data {
      try JSONSerialization.data(withJSONObject: [
        "log": ["level": "error"],
        "outbounds": [
          [
            "type": "vless", "tag": "reality", "server": "1.1.1.1", "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "tls": [
              "enabled": true, "server_name": "www.example.com",
              "utls": ["enabled": true, "fingerprint": fingerprint],
              "reality": [
                "enabled": true,
                "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                "short_id": "0123456789abcdef",
                "support_x25519mlkem768": true,
              ],
            ],
          ]
        ],
        "route": ["final": "reality"],
      ])
    }
    let checker = SourceBuiltLibboxConfigurationChecker()
    try checker.check(configuration: configuration(fingerprint: "chrome"))
    try expectRejection(configuration(fingerprint: "firefox"))
  }

  @Test func pinnedLibboxAcceptsProjectedHysteria2SingBox114Options() throws {
    func configuration(obfs: [String: Any], extra: [String: Any]) throws -> Data {
      var outbound: [String: Any] = [
        "type": "hysteria2", "tag": "hy2", "server": "1.1.1.1", "server_port": 443,
        "server_ports": ["5000:5100"], "hop_interval": "10s", "password": "hy-secret",
        "obfs": obfs,
        "tls": ["enabled": true, "server_name": "hy2.example.com"],
      ]
      outbound.merge(extra) { _, new in new }
      return try JSONSerialization.data(withJSONObject: [
        "log": ["level": "error"], "outbounds": [outbound], "route": ["final": "hy2"],
      ])
    }
    let checker = SourceBuiltLibboxConfigurationChecker()
    try checker.check(
      configuration: configuration(
        obfs: [
          "type": "gecko", "password": "mask-secret", "min_packet_size": 400,
          "max_packet_size": 1400,
        ],
        extra: ["hop_interval_max": "60s", "bbr_profile": "conservative"]))
    try expectRejection(
      configuration(
        obfs: ["type": "gecko", "password": "mask-secret"],
        extra: ["bbr_profile": "fast"]))
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

    expectRejection(configuration)
  }

  /// A check whose instance does not close fails, so a shape whose close fails
  /// without a start could never be checked. Every outbound, group and inbound
  /// shape CFM projects closes, in a runtime configuration with DNS, a remote
  /// rule set, the cache file and the controller.
  @Test func pinnedLibboxClosesEveryProjectedShapeAfterItsCheck() throws {
    let tls = #""tls":{"enabled":true,"server_name":"node.example.com"}"#
    let uuid = "bf000d23-0752-40b4-affe-68f7707a9661"
    let outbounds = [
      "socks":
        #"{"type":"socks","tag":"p","server":"1.2.3.4","server_port":1080,"username":"u","password":"p"}"#,
      "http":
        #"{"type":"http","tag":"p","server":"1.2.3.4","server_port":8080,"username":"u","password":"p","#
        + tls + "}",
      "shadowsocks":
        #"{"type":"shadowsocks","tag":"p","server":"1.2.3.4","server_port":443,"method":"aes-256-gcm","password":"secret"}"#,
      "trojan":
        #"{"type":"trojan","tag":"p","server":"1.2.3.4","server_port":443,"password":"secret","#
        + tls + "}",
      "vless": #"{"type":"vless","tag":"p","server":"1.2.3.4","server_port":443,"uuid":""#
        + uuid + #"","# + tls + "}",
      "vmess": #"{"type":"vmess","tag":"p","server":"1.2.3.4","server_port":443,"uuid":""#
        + uuid + #"","security":"auto"}"#,
      "hysteria2":
        #"{"type":"hysteria2","tag":"p","server":"1.2.3.4","server_port":443,"password":"secret","#
        + tls + "}",
      "tuic": #"{"type":"tuic","tag":"p","server":"1.2.3.4","server_port":443,"uuid":""#
        + uuid + #"","password":"secret","# + tls + "}",
      "anytls":
        #"{"type":"anytls","tag":"p","server":"1.2.3.4","server_port":443,"password":"secret","#
        + tls + "}",
    ]
    let groups =
      #",{"type":"selector","tag":"sel","outbounds":["p","direct"],"default":"p","interrupt_exist_connections":false}"#
      + #",{"type":"urltest","tag":"auto","outbounds":["p"],"url":"https://www.gstatic.com/generate_204","interval":"5m"}"#
      + #",{"type":"fallback","tag":"fb","outbounds":["p","direct"],"url":"https://www.gstatic.com/generate_204","interval":"5m"}"#
      + #",{"type":"loadbalance","tag":"lb","outbounds":["p","direct"],"url":"https://www.gstatic.com/generate_204","interval":"5m"}"#
    let wireguard =
      #"{"type":"wireguard","tag":"wg","system":false,"address":["10.0.0.2/32"],"mtu":1408,"private_key":"yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=","peers":[{"address":"1.2.3.4","port":51820,"public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","allowed_ips":["0.0.0.0/0"],"persistent_keepalive_interval":25}]}"#
    let mixed =
      #"{"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":7890}"#
    let tun =
      #"{"type":"tun","tag":"cfw-tun","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":9000,"auto_route":true,"strict_route":true,"stack":"system"}"#
    func runtime(
      _ outbound: String, groups: String = "", endpoints: String = "", inbounds: String = mixed
    ) -> Data {
      Data(
        (#"{"log":{"level":"error"},"dns":{"servers":[{"type":"udp","tag":"dns-direct","server":"1.1.1.1"},{"type":"https","tag":"dns-remote","server":"dns.google","detour":"p"}],"final":"dns-direct"},"inbounds":["#
          + inbounds + #"],"endpoints":["# + endpoints + #"],"outbounds":["# + outbound
          + #",{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}"# + groups
          + #"],"route":{"rule_set":[{"type":"remote","tag":"geoip-cn","format":"binary","url":"https://example.com/geoip-cn.srs","download_detour":"direct"}],"rules":[{"rule_set":["geoip-cn"],"action":"route","outbound":"direct"}],"final":"p"},"experimental":{"cache_file":{"enabled":true,"path":"/nonexistent-cfm-check/cache.db"},"clash_api":{"external_controller":"127.0.0.1:9090","secret":"s"}}}"#)
          .utf8)
    }
    var cases = outbounds.mapValues { runtime($0, groups: groups) }
    cases["wireguard endpoint"] = runtime(try #require(outbounds["socks"]), endpoints: wireguard)
    cases["tun inbound"] = runtime(
      try #require(outbounds["shadowsocks"]), groups: groups, inbounds: tun)
    cases["tun and mixed inbounds"] = runtime(
      try #require(outbounds["vless"]), groups: groups, endpoints: wireguard,
      inbounds: tun + "," + mixed)
    let checker = SourceBuiltLibboxConfigurationChecker()
    for (name, configuration) in cases.sorted(by: { $0.key < $1.key }) {
      #expect(throws: Never.self, "\(name)") { try checker.check(configuration: configuration) }
    }
  }
#endif
