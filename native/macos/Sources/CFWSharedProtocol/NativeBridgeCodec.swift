import CryptoKit
import Foundation

public enum NativeBridgeProtocolCodec {
  public static func decodeRequest(_ data: Data) throws -> NativeRequestEnvelope {
    guard !data.isEmpty, data.count <= NativeBridgeProtocolConstants.maximumRequestBytes else {
      throw NativeBridgeProtocolError.messageTooLarge(
        actual: data.count,
        maximum: NativeBridgeProtocolConstants.maximumRequestBytes
      )
    }
    try NativeBridgeRequestShape.validate(data)
    return try JSONDecoder().decode(NativeRequestEnvelope.self, from: data)
  }

  public static func encodeResponse(_ response: NativeResponseEnvelope) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(response)
    guard data.count <= NativeBridgeProtocolConstants.maximumResponseBytes else {
      throw NativeBridgeProtocolError.messageTooLarge(
        actual: data.count,
        maximum: NativeBridgeProtocolConstants.maximumResponseBytes
      )
    }
    return data
  }
}

private enum NativeBridgeRequestShape {
  static func validate(_ data: Data) throws {
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw NativeBridgeProtocolError.malformedEnvelope
    }
    let envelope = try object(value)
    try exactKeys(envelope, ["schema_version", "request_id", "command"])
    try validateCommand(envelope["command"])
  }

  private static func validateCommand(_ value: Any?) throws {
    let command = try object(value)
    guard let opcodeText = command["opcode"] as? String,
      let opcode = NativeBridgeCommand.Opcode(rawValue: opcodeText)
    else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    switch opcode {
    case .queryStatus, .authorizeSystemProxy, .authorizeSystemProxyRestoration:
      try exactKeys(command, ["opcode"])
    case .maintainCurrentServices:
      try exactKeys(command, ["opcode", "payload"])
      let payload = try object(command["payload"])
      try exactKeys(payload, ["action"])
    case .startSystemProxy, .startTunnel:
      try exactKeys(command, ["opcode", "payload"])
      try validateEngineStartRequest(requestPayload(command))
    case .stopSystemProxy, .installTunnel, .cancelTunnelInstall, .stopTunnel:
      try exactKeys(command, ["opcode", "payload"])
      let payload = try object(command["payload"])
      try exactKeys(payload, ["context"])
      try validateContext(payload["context"])
    case .provisionCredentials:
      try exactKeys(command, ["opcode", "payload"])
      let request = try requestPayload(command)
      try exactKeys(request, ["audience", "required_references", "entries"])
      try validateAudience(request["audience"])
      try validateReferences(request["required_references"])
      guard let entries = request["entries"] as? [Any] else {
        throw NativeBridgeProtocolError.invalidCommand
      }
      for value in entries {
        let entry = try object(value)
        try exactKeys(entry, ["reference", "secret"])
        try validateReference(entry["reference"])
      }
    case .queryCredentialPresence:
      try exactKeys(command, ["opcode", "payload"])
      let request = try requestPayload(command)
      try exactKeys(request, ["audience", "references"])
      try validateAudience(request["audience"])
      try validateReferences(request["references"])
    case .testProfileDelays:
      try exactKeys(command, ["opcode", "payload"])
      let request = try requestPayload(command)
      try exactKeys(
        request, ["audience", "config_json", "credential_slots", "proxies", "timeout_ms"])
      try validateAudience(request["audience"])
      try validateCredentialSlots(request["credential_slots"])
    case .preflightCutover:
      try exactKeys(command, ["opcode", "payload"])
      let request = try requestPayload(command)
      try exactKeys(request, ["target", "system_proxy_request", "tunnel_request"])
      try validateEngineStartRequest(object(request["system_proxy_request"]))
      try validateEngineStartRequest(object(request["tunnel_request"]))
    case .previewCredentialGarbageCollection:
      try exactKeys(command, ["opcode", "payload"])
      let request = try requestPayload(command)
      try exactKeys(request, ["snapshot_digest", "catalog"])
      try validateCatalog(request["catalog"])
    case .commitCredentialGarbageCollection:
      try exactKeys(command, ["opcode", "payload"])
      let request = try requestPayload(command)
      try exactKeys(
        request,
        [
          "snapshot_digest", "catalog", "expected_vault_revision",
          "expected_orphan_bindings",
        ]
      )
      try validateCatalog(request["catalog"])
      guard let bindings = request["expected_orphan_bindings"] as? [Any] else {
        throw NativeBridgeProtocolError.invalidCommand
      }
      for value in bindings {
        let binding = try object(value)
        try exactKeys(binding, ["audience", "reference"])
        try validateAudience(binding["audience"])
        try validateReference(binding["reference"])
      }
    }
  }

  private static func requestPayload(_ command: [String: Any]) throws -> [String: Any] {
    let payload = try object(command["payload"])
    try exactKeys(payload, ["request"])
    return try object(payload["request"])
  }

  private static func validateContext(_ value: Any?) throws {
    try exactKeys(object: value, ["installation_id", "config_epoch", "generation"])
  }

  private static func validateEngineStartRequest(_ request: [String: Any]) throws {
    try exactKeys(
      request,
      [
        "context", "credential_audience", "config_json", "config_content_digest",
        "config_digest", "credential_slots", "tunnel_options",
      ]
    )
    try validateContext(request["context"])
    try validateAudience(request["credential_audience"])
    try validateCredentialSlots(request["credential_slots"])
    if let options = request["tunnel_options"], !(options is NSNull) {
      let fields = try object(options)
      var keys: Set<String> = [
        "ipv6_enabled", "bypass_private_networks", "direct_ipv4_hosts", "mtu",
      ]
      if fields["system_proxy_port"] != nil { keys.insert("system_proxy_port") }
      try exactKeys(fields, keys)
    }
  }

  private static func validateCredentialSlots(_ value: Any?) throws {
    guard let slots = value as? [Any] else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    for value in slots {
      let slot = try object(value)
      try exactKeys(
        slot,
        ["reference", "target", "outbound_index", "json_pointer"]
      )
      try validateReference(slot["reference"])
    }
  }

  private static func validateReferences(_ value: Any?) throws {
    guard let references = value as? [Any] else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    for reference in references {
      try validateReference(reference)
    }
  }

  private static func validateAudience(_ value: Any?) throws {
    try exactKeys(object: value, ["profile_id", "profile_digest"])
  }

  private static func validateCatalog(_ value: Any?) throws {
    guard let entries = value as? [Any] else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    for value in entries {
      let entry = try object(value)
      try exactKeys(entry, ["audience", "references"])
      try validateAudience(entry["audience"])
      try validateReferences(entry["references"])
    }
  }

  private static func validateReference(_ value: Any?) throws {
    try exactKeys(object: value, ["id", "kind"])
  }

  private static func object(_ value: Any?) throws -> [String: Any] {
    guard let value = value as? [String: Any] else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    return value
  }

  private static func exactKeys(object value: Any?, _ expected: Set<String>) throws {
    try exactKeys(try object(value), expected)
  }

  private static func exactKeys(_ value: [String: Any], _ expected: Set<String>) throws {
    guard Set(value.keys) == expected else {
      throw NativeBridgeProtocolError.invalidCommand
    }
  }
}

extension Digest where Self == SHA256.Digest {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
