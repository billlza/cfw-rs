import Foundation

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
