import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWLibboxRuntime

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

  /// A configuration near the 4 MiB limit, made of 46,000 domain rules, checks
  /// well within the ProxyAgent's reply to a check, so only a check libbox
  /// cannot finish answers with a timeout.
  @Test func aCheckOfTheLargestConfigurationFitsItsReply() throws {
    let padding = String(repeating: "a", count: 60)
    let domains = (0..<46_000).map { "\"rule-\($0)-\(padding).example.com\"" }
    let configuration = Data(
      (#"{"log":{"level":"error"},"outbounds":[{"type":"direct","tag":"direct"}],"#
        + #""route":{"rules":[{"domain_suffix":["# + domains.joined(separator: ",")
        + #"],"outbound":"direct"}],"final":"direct"}}"#).utf8)
    #expect(configuration.count > 3_500_000)
    #expect(configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes))
    let checker = SourceBuiltLibboxConfigurationChecker()
    let runs = try fastestOfThree { try checker.check(configuration: configuration) }
    print("check of \(configuration.count) bytes of one rule took \(runs.all)")
    #expect(
      runs.fastest < ProxyAgentCallBudget.configurationCheckReply,
      "the check took \(runs.all)")
  }

  /// The fastest of up to three runs of `body`, which a run under another
  /// process's load would otherwise decide, and every run's duration.
  private func fastestOfThree(_ body: () throws -> Void) rethrows -> (
    fastest: Duration, all: [Duration]
  ) {
    var all: [Duration] = []
    for _ in 0..<3 {
      let began = ContinuousClock.now
      try body()
      all.append(began.duration(to: .now))
    }
    return (all.min() ?? .zero, all)
  }

  /// The outbounds of a profile at its limits as CFM projects them: 1,024
  /// nodes of every protocol CFM projects in turn, each with its TLS,
  /// transport and credentials, a selector over all of them and 127 more over
  /// 32 each, and the direct outbound. Every server is a documentation address
  /// (RFC 5737), where nothing answers.
  private func largestProfileOutbounds() -> (outbounds: [[String: Any]], nodes: [String]) {
    let uuid = "bf000d23-0752-40b4-affe-68f7707a9661"
    let nodes = (0..<1_024).map { "node-\($0)" }
    func tls(_ name: String, _ extra: [String: Any] = [:]) -> [String: Any] {
      ["enabled": true, "server_name": name, "min_version": "1.2"].merging(extra) { $1 }
    }
    var outbounds: [[String: Any]] = nodes.indices.map { index in
      let name = "node\(index).example.com"
      let base: [String: Any] = [
        "tag": nodes[index], "server": "192.0.2.\(1 + index % 254)",
        "server_port": 10_000 + index,
      ]
      let shape: [String: Any] =
        switch index % 9 {
        case 0:
          [
            "type": "vless", "uuid": uuid, "flow": "xtls-rprx-vision",
            "tls": tls(
              name,
              [
                "utls": ["enabled": true, "fingerprint": "chrome"],
                "reality": [
                  "enabled": true, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                  "short_id": "0123456789abcdef",
                ],
              ]),
          ]
        case 1:
          [
            "type": "hysteria2", "password": "hysteria2-secret",
            "obfs": ["type": "salamander", "password": "obfs-secret"],
            "tls": tls(
              name, ["certificate_sha256": ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]]),
          ]
        case 2:
          [
            "type": "trojan", "password": "trojan-secret", "tls": tls(name),
            "transport": ["type": "ws", "path": "/ws", "headers": ["Host": name]],
          ]
        case 3:
          [
            "type": "tuic", "uuid": uuid, "password": "tuic-secret", "congestion_control": "bbr",
            "udp_relay_mode": "quic", "zero_rtt_handshake": false,
            "tls": tls(name, ["min_version": "1.3", "alpn": ["h3"]]),
          ]
        case 4:
          ["type": "anytls", "password": "anytls-secret", "tls": tls(name)]
        case 5:
          [
            "type": "shadowsocks", "method": "2022-blake3-aes-128-gcm",
            "password": "AAECAwQFBgcICQoLDA0ODw==",
          ]
        case 6:
          [
            "type": "vmess", "uuid": uuid, "security": "auto", "tls": tls(name),
            "transport": ["type": "grpc", "service_name": "tunnel"],
          ]
        case 7:
          ["type": "socks", "username": "user", "password": "socks-secret"]
        default:
          [
            "type": "vless", "uuid": uuid,
            "tls": tls(name, ["utls": ["enabled": true, "fingerprint": "safari"]]),
            "transport": ["type": "httpupgrade", "path": "/upgrade", "host": name],
          ]
        }
      return base.merging(shape) { $1 }
    }
    outbounds.append([
      "type": "selector", "tag": "cfw-proxy-selector", "outbounds": nodes, "default": nodes[0],
      "interrupt_exist_connections": false,
    ])
    for group in 0..<127 {
      let members = (0..<32).map { nodes[(group * 32 + $0) % nodes.count] }
      outbounds.append([
        "type": "selector", "tag": "group-\(group)", "outbounds": members,
        "default": members[0], "interrupt_exist_connections": false,
      ])
    }
    outbounds.append(["type": "direct", "tag": "cfw-direct"])
    return (outbounds, nodes)
  }

  /// The resolvers CFM projects: a numeric bootstrap pair and an
  /// authenticated DoH pair through the selected outbound.
  private var projectedDNS: [String: Any] {
    [
      "servers": [
        ["type": "udp", "tag": "cfw-bootstrap-dns-0", "server": "223.6.6.6", "server_port": 53],
        ["type": "udp", "tag": "cfw-bootstrap-dns-1", "server": "119.29.29.29", "server_port": 53],
        [
          "type": "https", "tag": "cfw-authenticated-dns-0", "server": "223.5.5.5",
          "server_port": 443, "path": "/dns-query", "connect_timeout": "5s",
          "detour": "cfw-proxy-selector",
          "tls": ["enabled": true, "server_name": "dns.alidns.com", "min_version": "1.2"],
        ],
        [
          "type": "https", "tag": "cfw-authenticated-dns-1", "server": "1.1.1.1",
          "server_port": 443, "path": "/dns-query", "connect_timeout": "5s",
          "detour": "cfw-proxy-selector",
          "tls": ["enabled": true, "server_name": "cloudflare-dns.com", "min_version": "1.2"],
        ],
      ],
      "rules": [["action": "evaluate", "domain_regex": ".*", "server": "cfw-authenticated-dns-0"]],
      "final": "cfw-authenticated-dns-1", "strategy": "prefer_ipv4",
    ]
  }

  private var projectedResolver: [String: Any] {
    ["server": "cfw-authenticated-dns-0", "fallback_server": "cfw-authenticated-dns-1"]
  }

  /// A runtime configuration at a profile's limits: the largest profile's
  /// outbounds and resolvers, remote rule sets, and as many rules as the
  /// 4 MiB limit leaves room for, as rule providers expand into, a tenth of
  /// them regular expressions, over every matcher CFM projects.
  @Test func aCheckOfTheLargestProjectedProfileFitsItsReply() throws {
    let rules: [[String: Any]] = (0..<45_000).map { index in
      var rule: [String: Any] = [
        "action": "route", "outbound": index % 3 == 0 ? "cfw-direct" : "group-\(index % 127)",
      ]
      switch index % 10 {
      case 0: rule["domain"] = "host\(index).example.com"
      case 1: rule["domain_suffix"] = "zone\(index).example.net"
      case 2: rule["domain_keyword"] = "keyword\(index)"
      case 3: rule["domain_regex"] = "^api[0-9]+\\.region\(index)\\.example\\.org$"
      case 4: rule["ip_cidr"] = "10.\(index / 256 % 256).\(index % 256).0/24"
      case 5: rule["source_ip_cidr"] = "172.16.\(index % 256).0/24"
      case 6: rule["port"] = 1_000 + index
      case 7: rule["network"] = index % 2 == 0 ? "tcp" : "udp"
      case 8: rule["process_name"] = "Helper \(index)"
      default: rule["process_path"] = "/Applications/App\(index).app/Contents/MacOS/App\(index)"
      }
      return rule
    }
    let configuration = try JSONSerialization.data(withJSONObject: [
      "log": ["level": "error"],
      "dns": projectedDNS,
      "inbounds": [
        ["type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1", "listen_port": 7890]
      ],
      "outbounds": largestProfileOutbounds().outbounds,
      "route": [
        "default_domain_resolver": projectedResolver,
        "rule_set": ["cn", "jp"].map { country in
          [
            "type": "remote", "tag": "cfw-geoip-\(country)", "format": "binary",
            "url":
              "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-\(country).srs",
            "download_detour": "cfw-proxy-selector", "update_interval": "1d",
          ]
        },
        "rules": [
          ["action": "route", "clash_mode": "Direct", "outbound": "cfw-direct"],
          ["action": "route", "clash_mode": "Global", "outbound": "cfw-proxy-selector"],
          ["action": "resolve"],
          ["action": "route", "rule_set": "cfw-geoip-cn", "outbound": "cfw-direct"],
        ] + rules,
        "final": "cfw-proxy-selector",
      ],
      "experimental": [
        "clash_api": ["external_controller": "127.0.0.1:9090", "secret": "controller-secret"]
      ],
    ])
    #expect(configuration.count > 3_500_000)
    #expect(configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes))
    let checker = SourceBuiltLibboxConfigurationChecker()
    let runs = try fastestOfThree { try checker.check(configuration: configuration) }
    print("check of \(configuration.count) bytes took \(runs.all)")
    #expect(
      runs.fastest < ProxyAgentCallBudget.configurationCheckReply,
      "the check took \(runs.all)")
  }

  /// A latency test at the smallest timeout of 32 nodes of the largest profile,
  /// none of which answers, returns within that timeout plus the ProxyAgent's
  /// allowance, building, starting and closing every outbound and resolver the
  /// Host sends included.
  @Test func aProbeOfTheLargestProjectedProfileFitsItsReply() throws {
    let profile = largestProfileOutbounds()
    let configuration = try JSONSerialization.data(withJSONObject: [
      "dns": projectedDNS, "outbounds": profile.outbounds,
      "route": ["default_domain_resolver": projectedResolver],
    ])
    let targets = Array(profile.nodes.prefix(32))
    let probe = SourceBuiltLibboxProfileProbe()
    var delays: [ProfileProxyDelay] = []
    let runs = try fastestOfThree {
      do {
        delays = try probe.test(
          configuration: configuration, proxies: targets, timeoutMS: 100, targetURL: "",
          expectedStatus: "")
      } catch LibboxRuntimeError.serviceStartFailed(let diagnostic) {
        // Only this generated test profile contains these fake credentials and
        // TEST-NET endpoints. Preserve its actual startup error for CI diagnosis;
        // production diagnostics remain private and the original test still fails.
        print("synthetic largest-profile startup failed: \(diagnostic.text)")
        throw LibboxRuntimeError.serviceStartFailed(diagnostic)
      }
    }
    print("probe of \(targets.count) of \(profile.nodes.count) nodes took \(runs.all)")
    #expect(delays.map(\.name) == targets)
    #expect(delays.allSatisfy { $0.delay == nil })
    #expect(
      runs.fastest < .milliseconds(100) + ProxyAgentCallBudget.profileProbeReplyAllowance,
      "the probe took \(runs.all)")
  }

  /// A latency test of a node that never answers returns within its own
  /// timeout plus the ProxyAgent's allowance, building, starting and closing
  /// its instance included, so only a probe libbox cannot finish answers with
  /// a timeout.
  @Test func aProbeOfAnUnansweringNodeFitsItsReply() throws {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): nothing answers there. A probe
    // takes only the outbounds, endpoints and resolvers the Host sends it.
    let configuration = Data(
      #"{"outbounds":[{"type":"socks","tag":"p","server":"192.0.2.1","server_port":1080}]}"#
        .utf8)
    let began = ContinuousClock.now
    let delays = try SourceBuiltLibboxProfileProbe().test(
      configuration: configuration, proxies: ["p"], timeoutMS: 500, targetURL: "",
      expectedStatus: "")
    let elapsed = began.duration(to: .now)
    #expect(delays.map(\.name) == ["p"])
    #expect(delays.first?.delay == nil)
    #expect(
      elapsed < .milliseconds(500) + ProxyAgentCallBudget.profileProbeReplyAllowance,
      "the probe took \(elapsed)")
  }
#endif
