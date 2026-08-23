import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWNativeBridge

@Test func malformedBridgeRequestFailsClosed() throws {
  #expect(throws: (any Error).self) {
    try NativeBridgeProtocolCodec.decodeRequest(Data("{}".utf8))
  }
}

@Test func nativeBridgeRequestEnforcesExactWireBound() {
  let maximum = NativeBridgeProtocolConstants.maximumRequestBytes
  #expect(throws: NativeBridgeProtocolError.malformedEnvelope) {
    try NativeBridgeProtocolCodec.decodeRequest(Data(repeating: 0x20, count: maximum))
  }
  #expect(
    throws: NativeBridgeProtocolError.messageTooLarge(
      actual: maximum + 1,
      maximum: maximum
    )
  ) {
    try NativeBridgeProtocolCodec.decodeRequest(Data(repeating: 0x20, count: maximum + 1))
  }
}

@Test func nativeFailureMessageEnforcesExactSafeWireBound() throws {
  let maximum = String(
    repeating: "a",
    count: NativeBridgeProtocolConstants.maximumFailureMessageBytes
  )
  let valid = NativeResponseEnvelope(
    requestID: nil,
    failure: NativeBridgeFailure(code: .unavailable, message: maximum)
  )
  let encoded = try NativeBridgeProtocolCodec.encodeResponse(valid)
  #expect(try JSONDecoder().decode(NativeResponseEnvelope.self, from: encoded) == valid)
  #expect(valid.failure?.message == NativeBridgeErrorCode.unavailable.stableMessage)

  let oversized = Data(
    "{\"code\":\"unavailable\",\"message\":\"\(maximum)a\"}".utf8
  )
  #expect(throws: NativeBridgeProtocolError.invalidResponse) {
    try JSONDecoder().decode(NativeBridgeFailure.self, from: oversized)
  }
  let controlled = Data(
    "{\"code\":\"unavailable\",\"message\":\"unsafe\\u0000message\"}".utf8
  )
  #expect(throws: NativeBridgeProtocolError.invalidResponse) {
    try JSONDecoder().decode(NativeBridgeFailure.self, from: controlled)
  }
}

private let requestID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private let installationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
private let credentialID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

private func decode(_ json: String) throws -> NativeRequestEnvelope {
  try NativeBridgeProtocolCodec.decodeRequest(Data(json.utf8))
}

private func contractFixture(_ name: String) throws -> Data {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 {
    root.deleteLastPathComponent()
  }
  return try Data(
    contentsOf:
      root
      .appendingPathComponent("contracts/native-bridge-v8", isDirectory: true)
      .appendingPathComponent(name)
  )
}

@Test func validMinimalQueryRequestIsAccepted() throws {
  let request = try decode(
    """
    {"schema_version":8,"request_id":"\(requestID)","command":{"opcode":"query_status"}}
    """
  )
  #expect(request.requestID.uuidString.lowercased() == requestID)
}

@Test func nativeBridgeV6RequestIsRejectedAfterMaintenanceTransactionExpansion() {
  #expect(throws: NativeBridgeProtocolError.unsupportedSchemaVersion(6)) {
    try decode(
      """
      {"schema_version":6,"request_id":"\(requestID)","command":{"opcode":"query_status"}}
      """
    )
  }
}

@Test func nativeBridgeV4RequestRemainsRejected() {
  #expect(throws: NativeBridgeProtocolError.unsupportedSchemaVersion(4)) {
    try decode(
      """
      {"schema_version":4,"request_id":"\(requestID)","command":{"opcode":"query_status"}}
      """
    )
  }
}

@Test func unknownEnvelopeCommandAndNestedKeysAreRejected() {
  #expect(throws: (any Error).self) {
    try decode(
      """
      {"schema_version":8,"request_id":"\(requestID)","command":{"opcode":"query_status"},"unexpected":true}
      """
    )
  }
  #expect(throws: (any Error).self) {
    try decode(
      """
      {"schema_version":8,"request_id":"\(requestID)","command":{"opcode":"query_status","unexpected":true}}
      """
    )
  }
  #expect(throws: (any Error).self) {
    try decode(
      """
      {"schema_version":8,"request_id":"\(requestID)","command":{"opcode":"stop_system_proxy","payload":{"context":{"installation_id":"\(installationID)","config_epoch":1,"generation":1,"unexpected":true}}}}
      """
    )
  }
  #expect(throws: (any Error).self) {
    try decode(
      """
      {"schema_version":8,"request_id":"\(requestID)","command":{"opcode":"preview_credential_garbage_collection","payload":{"request":{"snapshot_digest":"\(String(repeating: "ab", count: 32))","catalog":[{"audience":{"profile_id":"\(requestID)","profile_digest":"\(String(repeating: "ee", count: 32))"},"references":[{"id":"\(credentialID)","kind":"trojan_password","unexpected":true}]}]}}}}
      """
    )
  }
}

@Test func nativeBridgeV8ContractFixturesDecodeInSwift() throws {
  let query = try NativeBridgeProtocolCodec.decodeRequest(
    contractFixture("query-request.json")
  )
  guard case .queryStatus = query.command else {
    Issue.record("query fixture decoded as the wrong command")
    return
  }

  let maintenance = try NativeBridgeProtocolCodec.decodeRequest(
    contractFixture("maintenance-request.json")
  )
  guard
    case .maintainCurrentServices(.unregisterInstalled40019ProxyAgent) =
      maintenance.command
  else {
    Issue.record("maintenance fixture decoded as the wrong command")
    return
  }
  let maintenanceResponse = try JSONDecoder().decode(
    NativeResponseEnvelope.self,
    from: contractFixture("maintenance-response.json")
  )
  guard case .serviceMaintenance(let maintenanceResult) = maintenanceResponse.result else {
    Issue.record("maintenance response fixture decoded as the wrong result")
    return
  }
  #expect(maintenanceResult.action == .unregisterInstalled40019ProxyAgent)
  #expect(maintenanceResult.engineStatus == .off)
  #expect(
    maintenanceResult.offProofProfile == .installed40019EngineV5AuthorityV10)
  #expect(maintenanceResult.proxyAgent == .notRegistered)
  #expect(maintenanceResult.globalAuthority == .enabled)

  let recovery = try NativeBridgeProtocolCodec.decodeRequest(
    contractFixture("recovery-maintenance-request.json")
  )
  guard
    case .maintainCurrentServices(.recoverInstalled40019GlobalAuthority) =
      recovery.command
  else {
    Issue.record("recovery maintenance fixture decoded as the wrong command")
    return
  }
  let recoveryResponse = try JSONDecoder().decode(
    NativeResponseEnvelope.self,
    from: contractFixture("recovery-maintenance-response.json")
  )
  guard case .serviceMaintenance(let recoveryResult) = recoveryResponse.result else {
    Issue.record("recovery maintenance response fixture decoded as the wrong result")
    return
  }
  #expect(recoveryResult.action == .recoverInstalled40019GlobalAuthority)
  #expect(recoveryResult.engineStatus == .off)
  #expect(
    recoveryResult.offProofProfile == .installed40019RecoveryCurrentAuthorityV11)
  #expect(recoveryResult.proxyAgent == .notRegistered)
  #expect(recoveryResult.globalAuthority == .notRegistered)

  let request = try NativeBridgeProtocolCodec.decodeRequest(
    contractFixture("gc-preview-request.json")
  )
  guard case .previewCredentialGarbageCollection(let preview) = request.command else {
    Issue.record("GC fixture decoded as the wrong command")
    return
  }
  #expect(preview.snapshotDigest.hex == String(repeating: "ab", count: 32))
  #expect(preview.catalog.count == 1)
  #expect(
    preview.catalog[0].references.map(\.kind) == [
      .anytlsPassword, .tuicUUID, .tuicPassword,
    ])

  let response = try JSONDecoder().decode(
    NativeResponseEnvelope.self,
    from: contractFixture("gc-preview-response.json")
  )
  guard case .credentialGarbageCollectionPreview(let result) = response.result else {
    Issue.record("GC response fixture decoded as the wrong result")
    return
  }
  #expect(result.orphanCount == 1)
  #expect(result.vaultRevision.uuidString.lowercased() == "cccccccc-cccc-4ccc-8ccc-cccccccccccc")

  let conflict = try JSONDecoder().decode(
    NativeResponseEnvelope.self,
    from: contractFixture("endpoint-conflict-response.json")
  )
  #expect(conflict.result == nil)
  #expect(conflict.failure?.code == .controllerEndpointInUse)
  #expect(
    conflict.failure?.message == NativeBridgeErrorCode.controllerEndpointInUse.stableMessage)
}

@Test func nativePublicQueryJSONContractIsUnchanged() throws {
  let fixture = try contractFixture("query-request.json")
  let request = try NativeBridgeProtocolCodec.decodeRequest(fixture)
  let encoded = try JSONEncoder().encode(request)
  #expect(try NativeBridgeProtocolCodec.decodeRequest(encoded) == request)

  let expected = try #require(JSONSerialization.jsonObject(with: fixture) as? [String: Any])
  var actual = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  let encodedRequestID = try #require(actual["request_id"] as? String)
  actual["request_id"] = encodedRequestID.lowercased()
  #expect(NSDictionary(dictionary: actual) == NSDictionary(dictionary: expected))
}
