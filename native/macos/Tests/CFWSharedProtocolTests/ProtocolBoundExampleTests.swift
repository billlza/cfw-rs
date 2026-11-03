import Foundation
import Testing

@testable import CFWSharedProtocol

// Task 2.6 examples: the protocol's exact bounds, and unsupported versions and
// features rejected at the model.
// MARK: - Exact protocol bounds

@Test func exactProtocolBoundConstantsMatchTheV1Contract() {
  #expect(AuthorityV1Limits.maximumEnvelopeBytes == 1_048_576)
  #expect(AuthorityV1Limits.maximumConfigurationBytes == 4 * 1_024 * 1_024)
  #expect(AuthorityV1Limits.maximumTotalSecretBytes == 262_144)
  #expect(AuthorityV1Limits.maximumCredentialSlots == 2_048)
  #expect(AuthorityV1Limits.maximumIndividualSecretBytes == 16_384)
  #expect(AuthorityV1Limits.maximumReadOnlyRequests == 64)
  #expect(AuthorityV1Limits.maximumMutatingTransactions == 1)
  #expect(AuthorityV1Limits.maximumQueuedEventsPerPeer == 32)
  #expect(AuthorityV1Limits.preparationLifetimeMilliseconds == 10_000)
  #expect(AuthorityV1Limits.commandTimeoutMilliseconds == 5_000)
  #expect(AuthorityV1Limits.stopAttestationTimeoutMilliseconds == 5_000)
  #expect(AuthorityV1Limits.ticketBytes == 32)
  #expect(AuthorityV1Limits.capabilityBytes == 32)
}

@Test func envelopeSizeBoundRejectsInputOneByteOverTheLimit() {
  let overLimit = AuthorityV1Limits.maximumEnvelopeBytes + 1
  let oversized = Data(repeating: 0x20, count: overLimit)
  #expect(
    throws: AuthorityV1ValidationError.messageTooLarge(
      actual: overLimit, maximum: AuthorityV1Limits.maximumEnvelopeBytes)
  ) {
    try AuthorityV1Codec.decodeRequest(oversized)
  }
}

@Test func configurationByteBoundIsInclusiveAndRejectsOverflow() throws {
  let config = try exampleDigest("a")
  let identity = try exampleDigest("b")
  let atLimit = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(AuthorityV1Limits.maximumConfigurationBytes),
    configSHA256: config, identitySHA256: identity,
    credentialAudience: try testCredentialAudience(),
    credentialSlots: [], tunnelOptions: nil)
  #expect(atLimit.byteCount == 4 * 1_024 * 1_024)
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthorityConfigurationDescriptor(
      byteCount: UInt32(AuthorityV1Limits.maximumConfigurationBytes + 1),
      configSHA256: config, identitySHA256: identity,
      credentialAudience: try testCredentialAudience(),
      credentialSlots: [], tunnelOptions: nil)
  }
}

@Test func individualSecretByteBoundIsInclusiveAndRejectsOverflow() throws {
  let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let atLimit = try AuthoritySecretSlot(
    reference: reference,
    copying: Data(repeating: 7, count: AuthorityV1Limits.maximumIndividualSecretBytes))
  #expect(atLimit.byteCount == 16_384)
  atLimit.erase()
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretSlot(
      reference: reference,
      copying: Data(
        repeating: 7, count: AuthorityV1Limits.maximumIndividualSecretBytes + 1))
  }
}

@Test func totalSecretAndSlotBoundsAreInclusiveAndRejectOverflow() throws {
  let fullSlots = try (0..<AuthorityV1Limits.maximumCredentialSlots).map { _ in
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data(
        repeating: 1,
        count: AuthorityV1Limits.maximumTotalSecretBytes / AuthorityV1Limits.maximumCredentialSlots)
    )
  }
  let material = try AuthoritySecretMaterial(slots: fullSlots)
  #expect(material.slots.count == 2_048)
  #expect(material.totalByteCount == 262_144)
  material.erase()

  let extraSlot = try AuthoritySecretSlot(
    reference: CredentialReference(id: UUID(), kind: .trojanPassword),
    copying: Data([1]))
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretMaterial(slots: fullSlots + [extraSlot])
  }

  let oversizedTotal = try (0..<17).map { _ in
    try AuthoritySecretSlot(
      reference: CredentialReference(id: UUID(), kind: .trojanPassword),
      copying: Data(repeating: 2, count: AuthorityV1Limits.maximumIndividualSecretBytes))
  }
  #expect(throws: AuthorityV1ValidationError.boundViolation) {
    try AuthoritySecretMaterial(slots: oversizedTotal)
  }
  for slot in oversizedTotal { slot.erase() }
  extraSlot.erase()
}

@Test func ticketAndCapabilityLengthBoundsAreExact() {
  #expect(throws: AuthorityV1ValidationError.invalidTicket) {
    try StartTicket(copying: Data(repeating: 9, count: AuthorityV1Limits.ticketBytes - 1))
  }
  #expect(throws: AuthorityV1ValidationError.invalidTicket) {
    try StartTicket(copying: Data(repeating: 9, count: AuthorityV1Limits.ticketBytes + 1))
  }
  #expect(throws: AuthorityV1ValidationError.invalidCapability) {
    try OwnerCapability(
      copying: Data(repeating: 9, count: AuthorityV1Limits.capabilityBytes - 1))
  }
}

@Test func queuedEventBoundCoalescesSnapshotsAndDisconnectsAtThirtyThree() throws {
  let queue = BoundedAuthorityEventQueue()
  for _ in 0..<AuthorityV1Limits.maximumQueuedEventsPerPeer {
    #expect(queue.enqueue(try exampleStopEvent()) == .queued)
  }
  #expect(queue.count == 32)
  // A non-snapshot event beyond the per-peer bound forces the peer to disconnect
  // rather than dropping a revocation or stop command.
  #expect(queue.enqueue(try exampleStopEvent()) == .peerMustDisconnect)

  // Snapshots coalesce onto the single queued snapshot instead of growing.
  let snapshotQueue = BoundedAuthorityEventQueue()
  #expect(snapshotQueue.enqueue(try exampleSnapshotEvent()) == .queued)
  #expect(snapshotQueue.enqueue(try exampleSnapshotEvent()) == .queued)
  #expect(snapshotQueue.count == 1)
}

// MARK: - Unsupported version and feature rejection

@Test func unsupportedProtocolMajorMinorAndFeaturesAreRejectedAtTheModel() {
  #expect(throws: AuthorityV1ValidationError.unsupportedMajor(2)) {
    try AuthorityProtocolVersion(major: 2)
  }
  #expect(throws: AuthorityV1ValidationError.unsupportedMinor(0)) {
    try AuthorityProtocolVersion(minor: 0, minimumMinor: 0)
  }
  #expect(throws: AuthorityV1ValidationError.unsupportedRequiredFeatures(1)) {
    try AuthorityProtocolVersion(featureBits: 1)
  }
  // The supported v1 tuple is accepted.
  #expect(throws: Never.self) { try AuthorityProtocolVersion() }
}
