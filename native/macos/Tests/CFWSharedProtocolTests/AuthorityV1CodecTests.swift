import Foundation
import Testing

@testable import CFWSharedProtocol

private func authorityFixture(_ name: String) throws -> Data {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .appendingPathComponent("../../../..")
    .standardizedFileURL
  return try Data(contentsOf: root.appendingPathComponent("fixtures/authority-v1/\(name)"))
}

private func installed40019AuthorityFixture(_ name: String) throws -> Data {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .appendingPathComponent("../../../..")
    .standardizedFileURL
  return try Data(
    contentsOf: root.appendingPathComponent(
      "fixtures/installed-40019-authority-v1-0/\(name)"))
}

private func verifyFixture<T: AuthorityV1WireModel>(
  _ type: T.Type, _ name: String
) throws {
  let data = try authorityFixture(name)
  let value = try AuthorityV1Codec.decodeCanonical(type, from: data)
  #expect(try AuthorityV1Codec.encodeCanonical(value) == data)
}

@Test func authorityV1CanonicalFixturesAreSharedWithRust() throws {
  try verifyFixture(HandshakeRequest.self, "handshake.json")
  try verifyFixture(PrepareStartRequest.self, "prepare-start.json")
  try verifyFixture(GlobalLease.self, "global-lease.json")
  try verifyFixture(ReplayCursor.self, "replay-cursor.json")
  try verifyFixture(AuthoritySnapshot.self, "snapshot.json")
  try verifyFixture(ReadyAttestation.self, "ready-attestation.json")
  try verifyFixture(StoppedAttestation.self, "stopped-attestation.json")
  try verifyFixture(
    PreferenceMutationReceipt.self, "preference-mutation-receipt.json")
  try verifyFixture(
    AuthorityResponseEnvelope<HandshakeResponse>.self,
    "handshake-response-envelope.json")

  let request = try authorityFixture("handshake-request-envelope.json")
  let decoded = try AuthorityV1Codec.decodeRequest(request)
  #expect(
    decoded.requestID.rawValue.uuidString.lowercased()
      == "44444444-4444-4444-4444-444444444444")
  #expect(try AuthorityV1Codec.encode(decoded) == request)
}

@Test func authorityV1LimitsMatchTheProtocolContract() {
  #expect(AuthorityV1Limits.maximumEnvelopeBytes == 1_048_576)
  #expect(AuthorityV1Limits.maximumConfigurationBytes == 768 * 1_024)
  #expect(AuthorityV1Limits.maximumTotalSecretBytes == 256 * 1_024)
  #expect(AuthorityV1Limits.maximumCredentialSlots == 256)
  #expect(AuthorityV1Limits.maximumIndividualSecretBytes == 16 * 1_024)
  #expect(AuthorityV1Limits.maximumReadOnlyRequests == 64)
  #expect(AuthorityV1Limits.maximumMutatingTransactions == 1)
  #expect(AuthorityV1Limits.maximumQueuedEventsPerPeer == 32)
  #expect(AuthorityV1Limits.preparationLifetimeMilliseconds == 10_000)
  #expect(AuthorityV1Limits.commandTimeoutMilliseconds == 5_000)
  #expect(AuthorityV1Limits.stopAttestationTimeoutMilliseconds == 5_000)
  #expect(AuthorityV1Codec.maximumNestingDepth == 32)
}

@Test func installed40019AuthorityCompatibilityIsReadOnlyExactAndClosed() throws {
  let handshakeID = AuthorityIdentifier(
    try #require(UUID(uuidString: "44444444-4444-4444-8444-444444444444")))
  let snapshotID = AuthorityIdentifier(
    try #require(UUID(uuidString: "55555555-5555-4555-8555-555555555555")))
  #expect(
    try Installed40019AuthorityOffCodec.handshakeRequest(requestID: handshakeID)
      == installed40019AuthorityFixture("handshake-request.json"))
  try Installed40019AuthorityOffCodec.validateHandshakeResponse(
    installed40019AuthorityFixture("handshake-response.json"),
    requestID: handshakeID)
  #expect(
    try Installed40019AuthorityOffCodec.snapshotRequest(requestID: snapshotID)
      == installed40019AuthorityFixture("snapshot-request.json"))
  try Installed40019AuthorityOffCodec.validateOffSnapshotResponse(
    installed40019AuthorityFixture("off-snapshot-response.json"),
    requestID: snapshotID)

  let offSnapshotText = try #require(
    String(
      data: installed40019AuthorityFixture("off-snapshot-response.json"),
      encoding: .utf8))
  let currentProtocol = offSnapshotText.replacingOccurrences(
    of: "\"minimum_minor\":0,\"minor\":0",
    with: "\"minimum_minor\":1,\"minor\":1")
  #expect(throws: (any Error).self) {
    try Installed40019AuthorityOffCodec.validateOffSnapshotResponse(
      Data(currentProtocol.utf8), requestID: snapshotID)
  }

  let active = offSnapshotText.replacingOccurrences(
    of: "\"state\":\"off\"", with: "\"state\":\"active\"")
  #expect(throws: Installed40019AuthorityOffValidationError.notOff) {
    try Installed40019AuthorityOffCodec.validateOffSnapshotResponse(
      Data(active.utf8), requestID: snapshotID)
  }

  #expect(throws: (any Error).self) {
    try Installed40019AuthorityOffCodec.validateOffSnapshotResponse(
      installed40019AuthorityFixture("off-snapshot-response.json"),
      requestID: handshakeID)
  }
}

@Test func authorityV1ConfigurationAndSecretBoundsAreInclusive() throws {
  let digest = try SHA256Digest(hex: String(repeating: "a", count: 64))
  let identity = try SHA256Digest(hex: String(repeating: "b", count: 64))
  let maximum = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(AuthorityV1Limits.maximumConfigurationBytes),
    configSHA256: digest, identitySHA256: identity,
    credentialAudience: try testCredentialAudience(),
    credentialSlots: [], tunnelOptions: nil)
  #expect(maximum.byteCount == UInt32(768 * 1_024))
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthorityConfigurationDescriptor(
      byteCount: UInt32(AuthorityV1Limits.maximumConfigurationBytes + 1),
      configSHA256: digest, identitySHA256: identity,
      credentialAudience: try testCredentialAudience(),
      credentialSlots: [], tunnelOptions: nil)
  }

  let oneMaximumSecret = try AuthoritySecretSlot(
    reference: CredentialReference(id: UUID(), kind: .trojanPassword),
    copying: Data(repeating: 7, count: AuthorityV1Limits.maximumIndividualSecretBytes))
  #expect(oneMaximumSecret.byteCount == 16 * 1_024)
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data(
        repeating: 7, count: AuthorityV1Limits.maximumIndividualSecretBytes + 1))
  }

  let slots = try (0..<AuthorityV1Limits.maximumCredentialSlots).map { _ in
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data(repeating: 1, count: 1_024))
  }
  let material = try AuthoritySecretMaterial(slots: slots)
  #expect(material.slots.count == 256)
  #expect(material.totalByteCount == 256 * 1_024)

  let overflowSlot = try AuthoritySecretSlot(
    reference: CredentialReference(id: UUID(), kind: .trojanPassword),
    copying: Data([1]))
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretMaterial(slots: slots + [overflowSlot])
  }
  let totalOverflowSlots = try (0..<17).map { _ in
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data(
        repeating: 1, count: AuthorityV1Limits.maximumIndividualSecretBytes))
  }
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretMaterial(slots: totalOverflowSlots)
  }

  material.erase()
  overflowSlot.erase()
  for slot in totalOverflowSlots { slot.erase() }
  #expect(
    slots.allSatisfy { slot in
      (try? slot.transportCopy()) == nil
    })
}

@Test func secretBearingAuthorityTypesAreRedactedAndNotCodable() throws {
  let marker = Data("fixture-secret-marker".utf8)
  let bytes = try SensitiveBytes(copying: marker, maximumCount: 64)
  let ticket = try StartTicket(copying: Data(repeating: 9, count: 32))
  let description = String(describing: bytes) + String(describing: ticket)
  #expect(!description.contains("fixture-secret-marker"))
  #expect(!(bytes is any Encodable))
  #expect(!(ticket is any Encodable))
  bytes.erase()
  ticket.erase()
  #expect(bytes.isErased)
}

@Test func authorityV1RejectsDuplicateUnknownNoncanonicalAndIncompatibleInputBeforeDispatch() throws
{
  let canonical = try authorityFixture("handshake-request-envelope.json")
  let text = try #require(String(data: canonical, encoding: .utf8))
  let malformedInputs = [
    text.replacingOccurrences(
      of: "\"major\":1", with: "\"major\":1,\"major\":1",
      options: [], range: text.range(of: "\"major\":1")),
    text.replacingOccurrences(
      of: "\"major\":1", with: "\"extra\":0,\"major\":1",
      options: [], range: text.range(of: "\"major\":1")),
    text + " ",
  ]
  for malformed in malformedInputs {
    var dispatched = false
    do {
      _ = try AuthorityV1Codec.decodeRequest(Data(malformed.utf8))
      dispatched = true
    } catch {}
    #expect(!dispatched)
  }

  let unsupportedMajor = text.replacingOccurrences(
    of: "\"major\":1", with: "\"major\":2",
    options: [], range: text.range(of: "\"major\":1"))
  #expect(throws: AuthorityV1ValidationError.unsupportedMajor(2)) {
    try AuthorityV1Codec.decodeRequest(Data(unsupportedMajor.utf8))
  }
  let unsupportedMinor = text.replacingOccurrences(
    of: "\"minor\":1", with: "\"minor\":0",
    options: [], range: text.range(of: "\"minor\":1"))
  #expect(throws: AuthorityV1ValidationError.unsupportedMinor(0)) {
    try AuthorityV1Codec.decodeRequest(Data(unsupportedMinor.utf8))
  }
  let unsupportedFeature = text.replacingOccurrences(
    of: "\"required_feature_bits\":0", with: "\"required_feature_bits\":1")
  #expect(throws: AuthorityV1ValidationError.unsupportedRequiredFeatures(1)) {
    try AuthorityV1Codec.decodeRequest(Data(unsupportedFeature.utf8))
  }
  let unknownCommand = text.replacingOccurrences(of: "handshake", with: "future_command")
  #expect(throws: AuthorityV1ValidationError.unknownCommand) {
    try AuthorityV1Codec.decodeRequest(Data(unknownCommand.utf8))
  }
}

@Test func authorityV1RejectsInvalidTypesDepthAndEnvelopeSize() {
  #expect(throws: AuthorityV1ValidationError.noncanonicalRepresentation) {
    try AuthorityV1Codec.decodeRequest(Data("{\"command\":1.0}".utf8))
  }

  let deep =
    "{\"x\":" + String(repeating: "[", count: 32) + "0"
    + String(repeating: "]", count: 32) + "}"
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthorityV1Codec.decodeRequest(Data(deep.utf8))
  }

  let oversized = Data(repeating: 0x20, count: AuthorityV1Limits.maximumEnvelopeBytes + 1)
  #expect(
    throws: AuthorityV1ValidationError.messageTooLarge(
      actual: AuthorityV1Limits.maximumEnvelopeBytes + 1,
      maximum: AuthorityV1Limits.maximumEnvelopeBytes)
  ) {
    try AuthorityV1Codec.decodeRequest(oversized)
  }
}
