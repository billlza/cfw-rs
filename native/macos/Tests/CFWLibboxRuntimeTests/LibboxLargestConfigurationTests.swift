import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWLibboxRuntime

// Checks and probes of the largest configurations and profiles, built only
// where Libbox links: each answers within the ProxyAgent's reply.
#if canImport(Libbox)
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
