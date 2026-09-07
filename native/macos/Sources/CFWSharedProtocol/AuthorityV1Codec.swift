import CoreFoundation
import CryptoKit
import Foundation

/// Canonical Authority v1 JSON codec. The accepted representation is UTF-8,
/// whitespace-free JSON with lexicographically sorted object keys, integer-only
/// numbers, exact schemas, and no more than 32 nested containers.
public enum AuthorityV1Codec {
  public static let maximumNestingDepth = 32

  public static func encode(_ envelope: AuthorityRequestEnvelope) throws -> Data {
    let command = try encodeCommand(envelope.command)
    return try canonicalData([
      "command": command,
      "major": envelope.major,
      "minor": envelope.minor,
      "request_id": envelope.requestID.rawValue.uuidString.lowercased(),
      "required_feature_bits": envelope.requiredFeatureBits,
    ])
  }

  public static func decodeRequest(_ data: Data) throws -> AuthorityRequestEnvelope {
    try checkEnvelopeSize(data)
    let object = try parseCanonicalObject(data)
    try exactKeys(object, ["command", "major", "minor", "request_id", "required_feature_bits"])
    let major = try unsigned(object["major"], as: UInt16.self)
    guard major == AuthorityV1Limits.major else {
      throw AuthorityV1ValidationError.unsupportedMajor(major)
    }
    let minor = try unsigned(object["minor"], as: UInt16.self)
    guard minor == AuthorityV1Limits.minor else {
      throw AuthorityV1ValidationError.unsupportedMinor(minor)
    }
    let required = try unsigned(object["required_feature_bits"], as: UInt64.self)
    let unsupported = required & ~AuthorityV1Limits.supportedFeatureBits
    guard unsupported == 0 else {
      throw AuthorityV1ValidationError.unsupportedRequiredFeatures(unsupported)
    }
    let envelope = try AuthorityRequestEnvelope(
      requestID: try identifier(object["request_id"]),
      requiredFeatureBits: required,
      command: try decodeCommand(try dictionary(object["command"]))
    )
    guard try encode(envelope) == data else {
      throw AuthorityV1ValidationError.noncanonicalRepresentation
    }
    return envelope
  }
  public static func encodeCanonical<T: AuthorityV1WireModel>(_ value: T) throws -> Data {
    try value.validateAuthorityV1()
    return try canonicalData(encodedObject(value))
  }

  public static func decodeCanonical<T: AuthorityV1WireModel>(
    _ type: T.Type, from data: Data
  ) throws -> T {
    try checkEnvelopeSize(data)
    _ = try parseCanonicalObject(data)
    let decoded: T
    do { decoded = try JSONDecoder().decode(type, from: data) } catch let error
      as AuthorityV1ValidationError
    { throw error } catch { throw AuthorityV1ValidationError.invalidType }
    try decoded.validateAuthorityV1()
    guard try encodeCanonical(decoded) == data else {
      throw AuthorityV1ValidationError.noncanonicalRepresentation
    }
    return decoded
  }

  public static func encodeResponse<Payload: AuthorityV1WireModel>(
    _ envelope: AuthorityResponseEnvelope<Payload>
  ) throws -> Data {
    try encodeCanonical(envelope)
  }

  public static func decodeResponse<Payload: AuthorityV1WireModel>(
    _ payload: Payload.Type, from data: Data
  ) throws -> AuthorityResponseEnvelope<Payload> {
    try decodeCanonical(AuthorityResponseEnvelope<Payload>.self, from: data)
  }

  public static func encodeEvent(_ event: AuthorityEvent) throws -> Data {
    try encodeCanonical(event)
  }

  public static func decodeEvent(_ data: Data) throws -> AuthorityEvent {
    try decodeCanonical(AuthorityEvent.self, from: data)
  }

  /// Validates the separate secret-free configuration XPC argument before a
  /// caller may dispatch a prepare mutation.
  public static func validateConfiguration(
    _ data: Data, descriptor: AuthorityConfigurationDescriptor
  ) throws {
    try descriptor.validateAuthorityV1()
    guard !data.isEmpty,
      data.count <= AuthorityV1Limits.maximumConfigurationBytes,
      data.count == Int(descriptor.byteCount),
      SHA256.hash(data: data).hexString == descriptor.configSHA256.hex
    else { throw AuthorityV1ValidationError.invalidConfiguration }
  }

  /// Encodes credential bytes only for the bounded XPC transport. The returned
  /// value is canonical v1 JSON and must be erased by both transport endpoints.
  public static func encodeSecretPayload(_ material: AuthoritySecretMaterial) throws -> Data {
    guard material.slots.count <= AuthorityV1Limits.maximumCredentialSlots,
      material.totalByteCount <= AuthorityV1Limits.maximumTotalSecretBytes
    else { throw AuthorityV1ValidationError.boundViolation }
    let slots: [[String: Any]] = try material.slots.map { slot in
      let bytes = try slot.transportCopy()
      guard !bytes.isEmpty,
        bytes.count <= AuthorityV1Limits.maximumIndividualSecretBytes
      else { throw AuthorityV1ValidationError.boundViolation }
      return [
        "id": slot.reference.id.uuidString.lowercased(),
        "kind": slot.reference.kind.rawValue,
        "secret": byteArray(bytes),
      ]
    }
    return try canonicalData(["slots": slots])
  }

  public static func decodeSecretPayload(_ data: Data) throws -> AuthoritySecretMaterial {
    try checkEnvelopeSize(data)
    let object = try parseCanonicalObject(data)
    try exactKeys(object, ["slots"])
    guard let values = object["slots"] as? [Any],
      values.count <= AuthorityV1Limits.maximumCredentialSlots
    else { throw AuthorityV1ValidationError.boundViolation }
    var slots: [AuthoritySecretSlot] = []
    var total = 0
    do {
      for value in values {
        let slot = try dictionary(value)
        try exactKeys(slot, ["id", "kind", "secret"])
        guard let idText = slot["id"] as? String,
          idText == idText.lowercased(),
          let id = UUID(uuidString: idText),
          id.uuidString.lowercased() == idText,
          let kindText = slot["kind"] as? String,
          let kind = CredentialKind(rawValue: kindText),
          let secretValues = slot["secret"] as? [Any],
          !secretValues.isEmpty,
          secretValues.count <= AuthorityV1Limits.maximumIndividualSecretBytes
        else { throw AuthorityV1ValidationError.boundViolation }
        let secret = Data(try secretValues.map { try unsigned($0, as: UInt8.self) })
        let (next, overflow) = total.addingReportingOverflow(secret.count)
        guard !overflow, next <= AuthorityV1Limits.maximumTotalSecretBytes else {
          throw AuthorityV1ValidationError.boundViolation
        }
        total = next
        slots.append(
          try AuthoritySecretSlot(
            reference: CredentialReference(id: id, kind: kind), copying: secret))
      }
      let material = try AuthoritySecretMaterial(slots: slots)
      guard try encodeSecretPayload(material) == data else {
        material.erase()
        throw AuthorityV1ValidationError.noncanonicalRepresentation
      }
      return material
    } catch {
      for slot in slots { slot.erase() }
      throw error
    }
  }

  /// Prepared-start replies contain exactly one transient capability. The
  /// capability models themselves remain deliberately non-Codable.
  public static func encodePreparedResponse(
    requestID: AuthorityIdentifier, prepared: PreparedStart
  ) throws -> Data {
    var result: [String: Any] = [
      "expires_monotonic_ms": prepared.expiresMonotonic,
      "lease_id": prepared.leaseID.rawValue.uuidString.lowercased(),
      "operation": try encodedObject(prepared.operation),
      "preference_descriptor_sha256": prepared.preferenceDescriptorSHA256.hex,
    ]
    if let ticket = prepared.ticket {
      result["ticket"] = byteArray(try ticket.transportCopy())
      result["owner_capability"] = NSNull()
    } else if let capability = prepared.ownerCapability {
      result["ticket"] = NSNull()
      result["owner_capability"] = byteArray(try capability.transportCopy())
    } else {
      throw AuthorityV1ValidationError.invalidState
    }
    return try canonicalData([
      "major": AuthorityV1Limits.major,
      "minor": AuthorityV1Limits.minor,
      "operation_id": prepared.operation.operationID.rawValue.uuidString.lowercased(),
      "request_id": requestID.rawValue.uuidString.lowercased(),
      "result": result,
    ])
  }

  public static func decodePreparedResponse(
    _ data: Data, expectedRequestID: AuthorityIdentifier,
    expectedOperationID: AuthorityIdentifier
  ) throws -> PreparedStart {
    try checkEnvelopeSize(data)
    let envelope = try parseCanonicalObject(data)
    try exactKeys(envelope, ["major", "minor", "operation_id", "request_id", "result"])
    guard try unsigned(envelope["major"], as: UInt16.self) == AuthorityV1Limits.major,
      try unsigned(envelope["minor"], as: UInt16.self) == AuthorityV1Limits.minor,
      try identifier(envelope["request_id"]) == expectedRequestID,
      try identifier(envelope["operation_id"]) == expectedOperationID
    else { throw AuthorityV1ValidationError.invalidContext }
    let result = try dictionary(envelope["result"])
    try exactKeys(
      result,
      [
        "expires_monotonic_ms", "lease_id", "operation", "owner_capability",
        "preference_descriptor_sha256", "ticket",
      ])
    let operation = try decodeObject(OperationContext.self, result["operation"] as Any)
    guard operation.operationID == expectedOperationID,
      let digestText = result["preference_descriptor_sha256"] as? String
    else { throw AuthorityV1ValidationError.invalidContext }
    let digest = try SHA256Digest(hex: digestText)
    let ticket: StartTicket?
    let capability: OwnerCapability?
    if result["ticket"] is NSNull {
      ticket = nil
      capability = try OwnerCapability(
        copying: bytes(
          result["owner_capability"], exactCount: AuthorityV1Limits.capabilityBytes))
    } else {
      ticket = try StartTicket(
        copying: bytes(
          result["ticket"], exactCount: AuthorityV1Limits.ticketBytes))
      capability = nil
      guard result["owner_capability"] is NSNull else {
        ticket?.erase()
        throw AuthorityV1ValidationError.invalidState
      }
    }
    do {
      let prepared = try PreparedStart(
        operation: operation, leaseID: identifier(result["lease_id"]),
        ticket: ticket, ownerCapability: capability,
        expiresMonotonic: unsigned(result["expires_monotonic_ms"], as: UInt64.self),
        preferenceDescriptorSHA256: digest)
      guard try encodePreparedResponse(requestID: expectedRequestID, prepared: prepared) == data
      else {
        prepared.erase()
        throw AuthorityV1ValidationError.noncanonicalRepresentation
      }
      return prepared
    } catch {
      ticket?.erase()
      capability?.erase()
      throw error
    }
  }
}

extension AuthorityV1Codec {
  fileprivate static func encodeCommand(_ command: AuthorityCommand) throws -> [String: Any] {
    switch command {
    case .handshake(let value): return try tagged("handshake", value)
    case .prepareStart(let value): return try tagged("prepare_start", value)
    case .bindProxyOwner(let value):
      try value.operation.validateAuthorityV1()
      guard value.operation.mode == .systemProxy else {
        throw AuthorityV1ValidationError.invalidCapability
      }
      return ["kind": "bind_proxy_owner", "payload": try capabilityPayload(value)]
    case .redeemTunnelTicket(let value):
      return ["kind": "redeem_tunnel_ticket", "payload": try ticketPayload(value)]
    case .attestReady(let value): return try tagged("attest_ready", value)
    case .beginStop(let value): return try tagged("begin_stop", value)
    case .completeStop(let value): return try tagged("complete_stop", value)
    case .reconcileOff(let value): return try tagged("reconcile_off", value)
    case .attestStopped(let value): return try tagged("attest_stopped", value)
    case .cancelPrepared(let value): return try tagged("cancel_prepared", value)
    case .snapshot(let value): return try tagged("snapshot", value)
    }
  }

  fileprivate static func decodeCommand(_ object: [String: Any]) throws -> AuthorityCommand {
    try exactKeys(object, ["kind", "payload"])
    guard let kind = object["kind"] as? String else {
      throw AuthorityV1ValidationError.invalidType
    }
    let payload = try dictionary(object["payload"])
    switch kind {
    case "handshake": return .handshake(try decodeObject(HandshakeRequest.self, payload))
    case "prepare_start": return .prepareStart(try decodeObject(PrepareStartRequest.self, payload))
    case "bind_proxy_owner": return .bindProxyOwner(try decodeCapabilityPayload(payload))
    case "redeem_tunnel_ticket": return .redeemTunnelTicket(try decodeTicketPayload(payload))
    case "attest_ready": return .attestReady(try decodeObject(ReadyAttestation.self, payload))
    case "begin_stop": return .beginStop(try decodeObject(BeginStopRequest.self, payload))
    case "complete_stop":
      return .completeStop(try decodeObject(CompleteStopRequest.self, payload))
    case "reconcile_off":
      return .reconcileOff(try decodeObject(ReconcileOffRequest.self, payload))
    case "attest_stopped": return .attestStopped(try decodeObject(StoppedAttestation.self, payload))
    case "cancel_prepared":
      return .cancelPrepared(try decodeObject(CancelPreparedRequest.self, payload))
    case "snapshot": return .snapshot(try decodeObject(SnapshotRequest.self, payload))
    default: throw AuthorityV1ValidationError.unknownCommand
    }
  }

  fileprivate static func tagged<T: AuthorityV1WireModel>(_ kind: String, _ payload: T) throws
    -> [String: Any]
  {
    ["kind": kind, "payload": try encodedObject(payload)]
  }

  fileprivate static func capabilityPayload(_ value: BindProxyOwnerRequest) throws -> [String: Any]
  {
    [
      "capability": byteArray(try value.capability.transportCopy()),
      "lease_id": value.leaseID.rawValue.uuidString.lowercased(),
      "operation": try encodedObject(value.operation),
    ]
  }

  fileprivate static func ticketPayload(_ value: RedeemTunnelTicketRequest) throws -> [String: Any]
  {
    [
      "ticket": byteArray(try value.ticket.transportCopy())
    ]
  }

  fileprivate static func decodeCapabilityPayload(_ payload: [String: Any]) throws
    -> BindProxyOwnerRequest
  {
    try exactKeys(payload, ["capability", "lease_id", "operation"])
    let operation = try decodeObject(OperationContext.self, payload["operation"] as Any)
    guard operation.mode == .systemProxy else {
      throw AuthorityV1ValidationError.invalidCapability
    }
    return BindProxyOwnerRequest(
      operation: operation,
      leaseID: try identifier(payload["lease_id"]),
      capability: try OwnerCapability(
        copying: bytes(payload["capability"], exactCount: AuthorityV1Limits.capabilityBytes))
    )
  }

  fileprivate static func decodeTicketPayload(_ payload: [String: Any]) throws
    -> RedeemTunnelTicketRequest
  {
    try exactKeys(payload, ["ticket"])
    return RedeemTunnelTicketRequest(
      ticket: try StartTicket(
        copying: bytes(payload["ticket"], exactCount: AuthorityV1Limits.ticketBytes))
    )
  }
}

extension AuthorityV1Codec {
  fileprivate static func checkEnvelopeSize(_ data: Data) throws {
    guard !data.isEmpty else { throw AuthorityV1ValidationError.malformedEnvelope }
    guard data.count <= AuthorityV1Limits.maximumEnvelopeBytes else {
      throw AuthorityV1ValidationError.messageTooLarge(
        actual: data.count, maximum: AuthorityV1Limits.maximumEnvelopeBytes)
    }
  }

  fileprivate static func parseCanonicalObject(_ data: Data) throws -> [String: Any] {
    let value: Any
    do { value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) } catch
    { throw AuthorityV1ValidationError.malformedEnvelope }
    try validateShape(value, depth: 1)
    let object = try dictionary(value)
    guard try canonicalData(object) == data else {
      throw AuthorityV1ValidationError.noncanonicalRepresentation
    }
    return object
  }

  fileprivate static func canonicalData(_ object: Any) throws -> Data {
    try validateShape(object, depth: 1)
    guard JSONSerialization.isValidJSONObject(object) else {
      throw AuthorityV1ValidationError.invalidType
    }
    let data: Data
    do {
      data = try JSONSerialization.data(
        withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    } catch { throw AuthorityV1ValidationError.invalidType }
    guard data.count <= AuthorityV1Limits.maximumEnvelopeBytes else {
      throw AuthorityV1ValidationError.messageTooLarge(
        actual: data.count, maximum: AuthorityV1Limits.maximumEnvelopeBytes)
    }
    return data
  }

  fileprivate static func encodedObject<T: AuthorityV1WireModel>(_ value: T) throws -> Any {
    try value.validateAuthorityV1()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(value)
    do { return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) } catch {
      throw AuthorityV1ValidationError.invalidType
    }
  }

  fileprivate static func decodeObject<T: AuthorityV1WireModel>(_ type: T.Type, _ object: Any)
    throws -> T
  {
    let decoded: T
    do { decoded = try JSONDecoder().decode(type, from: canonicalData(object)) } catch let error
      as AuthorityV1ValidationError
    { throw error } catch { throw AuthorityV1ValidationError.invalidType }
    try decoded.validateAuthorityV1()
    return decoded
  }

  fileprivate static func validateShape(_ value: Any, depth: Int) throws {
    guard depth <= maximumNestingDepth else { throw AuthorityV1ValidationError.boundViolation }
    switch value {
    case let object as [String: Any]:
      for child in object.values { try validateShape(child, depth: depth + 1) }
    case let values as [Any]:
      for child in values { try validateShape(child, depth: depth + 1) }
    case is String, is NSNull:
      return
    case let number as NSNumber:
      if CFGetTypeID(number) == CFBooleanGetTypeID() { return }
      let text = number.stringValue
      guard !text.contains("."), !text.contains("e"), !text.contains("E") else {
        throw AuthorityV1ValidationError.invalidType
      }
    default:
      throw AuthorityV1ValidationError.invalidType
    }
  }

  fileprivate static func dictionary(_ value: Any?) throws -> [String: Any] {
    guard let object = value as? [String: Any] else {
      throw AuthorityV1ValidationError.invalidType
    }
    return object
  }

  fileprivate static func exactKeys(_ object: [String: Any], _ expected: Set<String>) throws {
    guard Set(object.keys) == expected else { throw AuthorityV1ValidationError.malformedEnvelope }
  }

  fileprivate static func identifier(_ value: Any?) throws -> AuthorityIdentifier {
    guard let text = value as? String, text == text.lowercased(),
      let uuid = UUID(uuidString: text), uuid.uuidString.lowercased() == text
    else { throw AuthorityV1ValidationError.invalidIdentifier }
    return AuthorityIdentifier(uuid)
  }

  fileprivate static func unsigned<T: FixedWidthInteger & UnsignedInteger>(
    _ value: Any?, as: T.Type
  ) throws -> T {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { throw AuthorityV1ValidationError.invalidType }
    let text = number.stringValue
    guard !text.contains("."), !text.contains("e"), !text.contains("E"), let parsed = T(text)
    else { throw AuthorityV1ValidationError.invalidType }
    return parsed
  }

  fileprivate static func bytes(_ value: Any?, exactCount: Int) throws -> Data {
    guard let values = value as? [Any], values.count == exactCount else {
      throw AuthorityV1ValidationError.boundViolation
    }
    return Data(try values.map { try unsigned($0, as: UInt8.self) })
  }

  fileprivate static func byteArray(_ data: Data) -> [Int] { data.map(Int.init) }
}

/// The only wire compatibility retained for the installed 0.4.0 build 40019
/// Global Authority. It cannot encode a mutating command and it never changes
/// the current Authority v1.1 codec's accepted protocol version.
package enum Installed40019AuthorityOffValidationError: Error, Equatable, Sendable {
  case notOff
}

package enum Installed40019AuthorityOffCodec {
  public static let protocolMajor: UInt16 = 1
  public static let protocolMinor: UInt16 = 0

  package static func handshakeRequest(requestID: AuthorityIdentifier) throws -> Data {
    try request(
      requestID: requestID,
      kind: "handshake",
      payload: ["version": version()]
    )
  }

  package static func snapshotRequest(requestID: AuthorityIdentifier) throws -> Data {
    try request(requestID: requestID, kind: "snapshot", payload: [:])
  }

  package static func validateHandshakeResponse(
    _ data: Data,
    requestID: AuthorityIdentifier
  ) throws {
    let result = try responseResult(data, requestID: requestID)
    try AuthorityV1Codec.exactKeys(
      result,
      [
        "command_timeout_ms", "maximum_configuration_bytes",
        "maximum_credential_slots", "maximum_individual_secret_bytes",
        "maximum_mutating_transactions", "maximum_queued_events_per_peer",
        "maximum_read_only_requests", "maximum_total_secret_bytes",
        "preparation_lifetime_ms", "stop_attestation_timeout_ms", "version",
      ])
    guard
      try AuthorityV1Codec.unsigned(result["command_timeout_ms"], as: UInt64.self) == 5_000,
      try AuthorityV1Codec.unsigned(
        result["maximum_configuration_bytes"], as: UInt32.self) == 786_432,
      try AuthorityV1Codec.unsigned(result["maximum_credential_slots"], as: UInt16.self)
        == 256,
      try AuthorityV1Codec.unsigned(
        result["maximum_individual_secret_bytes"], as: UInt32.self) == 16_384,
      try AuthorityV1Codec.unsigned(
        result["maximum_mutating_transactions"], as: UInt8.self) == 1,
      try AuthorityV1Codec.unsigned(
        result["maximum_queued_events_per_peer"], as: UInt16.self) == 32,
      try AuthorityV1Codec.unsigned(
        result["maximum_read_only_requests"], as: UInt16.self) == 64,
      try AuthorityV1Codec.unsigned(
        result["maximum_total_secret_bytes"], as: UInt32.self) == 262_144,
      try AuthorityV1Codec.unsigned(
        result["preparation_lifetime_ms"], as: UInt64.self) == 10_000,
      try AuthorityV1Codec.unsigned(
        result["stop_attestation_timeout_ms"], as: UInt64.self) == 5_000
    else { throw AuthorityV1ValidationError.invalidType }
    try validateVersion(try AuthorityV1Codec.dictionary(result["version"]))
  }

  package static func validateOffSnapshotResponse(
    _ data: Data,
    requestID: AuthorityIdentifier
  ) throws {
    let result = try responseResult(data, requestID: requestID)
    try exactKeys(
      result,
      required: [
        "protocol_version", "revision", "state",
      ],
      optional: [
        "console_uid", "last_failure", "lease_view", "replay_cursor",
      ])
    guard let state = result["state"] as? String, AuthorityState(rawValue: state) != nil else {
      throw AuthorityV1ValidationError.invalidState
    }
    guard state == AuthorityState.off.rawValue, result["lease_view"] == nil else {
      throw Installed40019AuthorityOffValidationError.notOff
    }
    try validateVersion(try AuthorityV1Codec.dictionary(result["protocol_version"]))
    let revision = try AuthorityV1Codec.unsigned(result["revision"], as: UInt64.self)
    guard revision > 0 else { throw AuthorityV1ValidationError.invalidState }
    try validateOptionalConsoleUID(result["console_uid"])
    try validateOptionalFailure(result["last_failure"])
    try validateOptionalReplayCursor(result["replay_cursor"], maximumRevision: revision)
  }

  private static func exactKeys(
    _ object: [String: Any],
    required: Set<String>,
    optional: Set<String>
  ) throws {
    // Build 40019 used synthesized Codable encoding: nil optional fields are
    // omitted, while every present field remains part of the closed schema.
    let observed = Set(object.keys)
    guard required.isSubset(of: observed), observed.isSubset(of: required.union(optional)) else {
      throw AuthorityV1ValidationError.malformedEnvelope
    }
  }

  private static func request(
    requestID: AuthorityIdentifier,
    kind: String,
    payload: [String: Any]
  ) throws -> Data {
    try AuthorityV1Codec.canonicalData([
      "command": ["kind": kind, "payload": payload],
      "major": protocolMajor,
      "minor": protocolMinor,
      "request_id": requestID.rawValue.uuidString.lowercased(),
      "required_feature_bits": UInt64(0),
    ])
  }

  private static func responseResult(
    _ data: Data,
    requestID: AuthorityIdentifier
  ) throws -> [String: Any] {
    try AuthorityV1Codec.checkEnvelopeSize(data)
    let response = try AuthorityV1Codec.parseCanonicalObject(data)
    try AuthorityV1Codec.exactKeys(
      response, ["major", "minor", "request_id", "result"])
    guard
      try AuthorityV1Codec.unsigned(response["major"], as: UInt16.self) == protocolMajor,
      try AuthorityV1Codec.unsigned(response["minor"], as: UInt16.self) == protocolMinor,
      try AuthorityV1Codec.identifier(response["request_id"]) == requestID
    else { throw AuthorityV1ValidationError.invalidContext }
    return try AuthorityV1Codec.dictionary(response["result"])
  }

  private static func version() -> [String: Any] {
    [
      "feature_bits": UInt64(0),
      "major": protocolMajor,
      "max_message_bytes": UInt32(AuthorityV1Limits.maximumEnvelopeBytes),
      "minimum_minor": protocolMinor,
      "minor": protocolMinor,
    ]
  }

  private static func validateVersion(_ value: [String: Any]) throws {
    try AuthorityV1Codec.exactKeys(
      value, ["feature_bits", "major", "max_message_bytes", "minimum_minor", "minor"])
    guard
      try AuthorityV1Codec.unsigned(value["feature_bits"], as: UInt64.self) == 0,
      try AuthorityV1Codec.unsigned(value["major"], as: UInt16.self) == protocolMajor,
      try AuthorityV1Codec.unsigned(value["max_message_bytes"], as: UInt32.self)
        == UInt32(AuthorityV1Limits.maximumEnvelopeBytes),
      try AuthorityV1Codec.unsigned(value["minimum_minor"], as: UInt16.self)
        == protocolMinor,
      try AuthorityV1Codec.unsigned(value["minor"], as: UInt16.self) == protocolMinor
    else { throw AuthorityV1ValidationError.unsupportedMinor(protocolMinor) }
  }

  private static func validateOptionalConsoleUID(_ value: Any?) throws {
    guard let value else { return }
    _ = try AuthorityV1Codec.unsigned(value, as: UInt32.self)
  }

  private static func validateOptionalFailure(_ value: Any?) throws {
    guard let value else { return }
    let failure = try AuthorityV1Codec.dictionary(value)
    try AuthorityV1Codec.exactKeys(failure, ["code"])
    guard let code = failure["code"] as? String,
      !code.isEmpty,
      code.utf8.count <= 64,
      code.utf8.allSatisfy({
        (97...122).contains($0) || (48...57).contains($0) || $0 == 45
      })
    else { throw AuthorityV1ValidationError.invalidState }
  }

  private static func validateOptionalReplayCursor(
    _ value: Any?,
    maximumRevision: UInt64
  ) throws {
    guard let value else { return }
    let cursor = try AuthorityV1Codec.dictionary(value)
    try AuthorityV1Codec.exactKeys(
      cursor,
      [
        "accepted_epoch", "accepted_generation", "installation_id",
        "previous_record_sha256", "revision", "schema_version",
      ])
    _ = try AuthorityV1Codec.identifier(cursor["installation_id"])
    guard
      try AuthorityV1Codec.unsigned(cursor["schema_version"], as: UInt16.self) == 1,
      try AuthorityV1Codec.unsigned(cursor["accepted_epoch"], as: UInt64.self) > 0,
      try AuthorityV1Codec.unsigned(cursor["accepted_generation"], as: UInt64.self) > 0
    else { throw AuthorityV1ValidationError.invalidContext }
    let cursorRevision = try AuthorityV1Codec.unsigned(
      cursor["revision"], as: UInt64.self)
    guard cursorRevision > 0, cursorRevision <= maximumRevision,
      let digest = cursor["previous_record_sha256"] as? String,
      digest.count == 64,
      digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    else { throw AuthorityV1ValidationError.invalidContext }
  }
}
