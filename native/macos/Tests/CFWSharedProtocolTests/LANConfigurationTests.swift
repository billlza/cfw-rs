import Foundation
import Testing

@testable import CFWSharedProtocol

private func lanConfiguration() -> [String: Any] {
  [
    "inbounds": [
      ["type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1", "listen_port": 8890],
      ["type": "mixed", "tag": "cfw-lan-proxy", "listen": "0.0.0.0", "listen_port": 8891],
    ],
    "route": [
      "rules": [
        [
          "type": "logical", "mode": "and", "action": "reject",
          "rules": [
            ["inbound": ["cfw-lan-proxy"]], ["source_ip_cidr": ["192.168.0.0/16"], "invert": true],
          ],
        ]
      ]
    ],
    "experimental": ["clash_api": ["external_controller": "127.0.0.1:9090"]],
  ]
}

@Test func localProxyAcceptsOnlyTheSeparateGuardedLANIngress() throws {
  try ConfigurationDescriptor.validateLocalProxyConfiguration(lanConfiguration())
  for (field, value) in [
    ("listen", "8.8.8.8" as Any), ("listen_port", 80), ("listen_port", 9090), ("listen_port", true),
    ("set_system_proxy", true),
  ] {
    var root = lanConfiguration()
    var inbounds = try #require(root["inbounds"] as? [[String: Any]])
    inbounds[1][field] = value
    root["inbounds"] = inbounds
    #expect(throws: NativeBridgeProtocolError.self) {
      try ConfigurationDescriptor.validateLocalProxyConfiguration(root)
    }
  }
}

@Test func lanACLPrecedesEveryRouteAndRequiresCanonicalPrivateSources() throws {
  for ranges in [
    [], ["0.0.0.0/0"], ["127.0.0.1/32"], ["192.168.1.2/24"], ["10.0.0.0/8", "10.0.0.0/8"],
  ] {
    var root = lanConfiguration()
    var route = try #require(root["route"] as? [String: Any])
    var rules = try #require(route["rules"] as? [[String: Any]])
    var conditions = try #require(rules[0]["rules"] as? [[String: Any]])
    conditions[1]["source_ip_cidr"] = ranges
    rules[0]["rules"] = conditions
    route["rules"] = rules
    root["route"] = route
    #expect(throws: NativeBridgeProtocolError.self) {
      try ConfigurationDescriptor.validateLocalProxyConfiguration(root)
    }
  }
  var root = lanConfiguration()
  var route = try #require(root["route"] as? [String: Any])
  var rules = try #require(route["rules"] as? [[String: Any]])
  rules.insert(["action": "route", "outbound": "direct"], at: 0)
  route["rules"] = rules
  root["route"] = route
  #expect(throws: NativeBridgeProtocolError.self) {
    try ConfigurationDescriptor.validateLocalProxyConfiguration(root)
  }
}
