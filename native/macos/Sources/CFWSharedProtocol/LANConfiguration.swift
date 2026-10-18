import CoreFoundation
import Foundation

extension ConfigurationDescriptor {
  static func validateLANConfiguration(_ root: [String: Any]) throws {
    let inbounds = root["inbounds"] as? [[String: Any]] ?? []
    let listeners = inbounds.filter { $0["tag"] as? String == "cfw-lan-proxy" }
    guard !listeners.isEmpty else { return }
    guard listeners.count == 1, let listener = listeners.first,
      listener["type"] as? String == "mixed",
      let addressText = listener["listen"] as? String,
      let address = canonicalIPv4(addressText), address == 0 || privateIPv4(address),
      let port = integerPort(listener["listen_port"]),
      let route = root["route"] as? [String: Any],
      let rules = route["rules"] as? [[String: Any]], let accessRule = rules.first,
      let conditions = accessRule["rules"] as? [[String: Any]], conditions.count == 2,
      let ranges = conditions[1]["source_ip_cidr"] as? [String],
      (1...32).contains(ranges.count), Set(ranges).count == ranges.count,
      ranges.allSatisfy(canonicalPrivateCIDR)
    else { throw NativeBridgeProtocolError.invalidConfiguration }
    if let systemProxy = listener["set_system_proxy"] {
      guard let value = systemProxy as? NSNumber,
        CFGetTypeID(value) == CFBooleanGetTypeID(), !value.boolValue
      else { throw NativeBridgeProtocolError.invalidConfiguration }
    }
    let expected: [String: Any] = [
      "type": "logical", "mode": "and", "action": "reject",
      "rules": [["inbound": ["cfw-lan-proxy"]], ["source_ip_cidr": ranges, "invert": true]],
    ]
    guard
      try JSONSerialization.data(withJSONObject: accessRule, options: .sortedKeys)
        == JSONSerialization.data(withJSONObject: expected, options: .sortedKeys)
    else { throw NativeBridgeProtocolError.invalidConfiguration }
    for inbound in inbounds where inbound["tag"] as? String != "cfw-lan-proxy" {
      if let other = integerPort(inbound["listen_port"]), other == port {
        throw NativeBridgeProtocolError.invalidConfiguration
      }
    }
    guard let experimental = root["experimental"] as? [String: Any],
      let controller = experimental["clash_api"] as? [String: Any],
      let endpoint = controller["external_controller"] as? String,
      let controllerPort = endpoint.split(separator: ":").last.flatMap({ UInt16($0) }),
      controllerPort != port
    else { throw NativeBridgeProtocolError.invalidConfiguration }
  }

  private static func integerPort(_ value: Any?) -> UInt16? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.doubleValue.rounded() == number.doubleValue,
      (1024...65535).contains(number.doubleValue)
    else { return nil }
    return UInt16(number.doubleValue)
  }

  private static func canonicalIPv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var value: UInt32 = 0
    for part in parts {
      guard let octet = UInt8(part), String(octet) == part else { return nil }
      value = (value << 8) | UInt32(octet)
    }
    return value
  }

  private static func privateIPv4(_ value: UInt32) -> Bool {
    value >> 24 == 10 || value >> 20 == 0xAC1 || value >> 16 == 0xC0A8
  }

  private static func canonicalPrivateCIDR(_ text: String) -> Bool {
    let parts = text.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2, let address = canonicalIPv4(String(parts[0])),
      let prefix = UInt32(parts[1]), prefix <= 32, String(prefix) == parts[1]
    else { return false }
    let mask = prefix == 0 ? UInt32(0) : UInt32.max << (32 - prefix)
    return address & mask == address && privateIPv4(address) && privateIPv4(address | ~mask)
  }
}
