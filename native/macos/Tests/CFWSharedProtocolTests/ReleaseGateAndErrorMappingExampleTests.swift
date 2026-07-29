import Foundation
import Testing

@testable import CFWSharedProtocol

// Example (non-property) tests for task 2.6. These cover the exact protocol
// bounds, unsupported feature/version rejection, the missing/unavailable
// Authority failure path, the stable cross-language error mapping, and the
// absence of mutation/fallback on the Release gate path. All boundaries are
// exercised with pure in-memory fakes; no real launchd or Network Extension
// is involved. The canonical fixtures are read from disk rather than
// duplicated inline.

// MARK: - Shared in-memory factories

private func exampleDigest(_ byte: Character) throws -> SHA256Digest {
  try SHA256Digest(hex: String(repeating: byte, count: 64))
}

private func exampleTunnelOperation() throws -> OperationContext {
  let root = try RootContext(
    installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)
  return try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .tunnel,
    configSHA256: try exampleDigest("a"), identitySHA256: try exampleDigest("b"),
    ownerUID: 501, authorityRevision: 1)
}

private func exampleProxyOperation() throws -> OperationContext {
  let root = try RootContext(
    installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)
  return try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .systemProxy,
    configSHA256: try exampleDigest("a"), identitySHA256: try exampleDigest("b"),
    ownerUID: 501, authorityRevision: 1)
}

private func exampleStopEvent() throws -> AuthorityEvent {
  let operation = try exampleTunnelOperation()
  let directive = try StopDirective(
    operation: operation, leaseID: AuthorityIdentifier(UUID()),
    deadlineMonotonic: 1_000, revision: operation.authorityRevision)
  return .stop(directive)
}

private func exampleSnapshotEvent() throws -> AuthorityEvent {
  let cursor = try ReplayCursor(
    installationID: AuthorityIdentifier(UUID()), acceptedEpoch: 1,
    acceptedGeneration: 1, revision: 1, previousRecordSHA256: try exampleDigest("c"))
  let snapshot = try AuthoritySnapshot(
    protocolVersion: try AuthorityProtocolVersion(), state: .off, revision: 1,
    replayCursor: cursor, leaseView: nil, lastFailure: nil, consoleUID: nil)
  return .snapshot(snapshot)
}

// MARK: - Exact protocol bounds

@Test func exactProtocolBoundConstantsMatchTheV1Contract() {
  #expect(AuthorityV1Limits.maximumEnvelopeBytes == 1_048_576)
  #expect(AuthorityV1Limits.maximumConfigurationBytes == 786_432)
  #expect(AuthorityV1Limits.maximumTotalSecretBytes == 262_144)
  #expect(AuthorityV1Limits.maximumCredentialSlots == 256)
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
  #expect(atLimit.byteCount == 786_432)
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
      copying: Data(repeating: 1, count: 1_024))
  }
  let material = try AuthoritySecretMaterial(slots: fullSlots)
  #expect(material.slots.count == 256)
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
  #expect(throws: AuthorityV1ValidationError.unsupportedMinor(1)) {
    try AuthorityProtocolVersion(minor: 1)
  }
  #expect(throws: AuthorityV1ValidationError.unsupportedRequiredFeatures(1)) {
    try AuthorityProtocolVersion(featureBits: 1)
  }
  // The supported v1 tuple is accepted.
  #expect(throws: Never.self) { try AuthorityProtocolVersion() }
}

// MARK: - Missing/unavailable Authority produces a stable typed failure

/// Records every remote call and always reports the Authority as unavailable.
private final class UnavailableAuthorityRemote: AuthorityRemoteCalling, @unchecked Sendable {
  private let lock = NSLock()
  private var invoked: [AuthorityXPCMethod] = []

  var invokedMethods: [AuthorityXPCMethod] { lock.withLock { invoked } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    lock.withLock { invoked.append(method) }
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func invalidate() async {}
}

private final class OperationAcknowledgementRemote:
  AuthorityRemoteCalling, @unchecked Sendable
{
  enum Reply: Equatable {
    case exact
    case wrongOperation
    case wrongRevision
  }

  private let lock = NSLock()
  private let reply: Reply
  private var methodCounts: [String: Int] = [:]
  private var ownerStoppedCountValue = 0

  init(reply: Reply) { self.reply = reply }

  func count(_ method: AuthorityXPCMethod) -> Int {
    lock.withLock { methodCounts["\(method)"] ?? 0 }
  }

  var ownerStoppedCount: Int { lock.withLock { ownerStoppedCountValue } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    let envelope = try AuthorityV1Codec.decodeRequest(request)
    if method == .handshake {
      return AuthorityXPCReply(
        response: try AuthorityV1Codec.encodeResponse(
          AuthorityResponseEnvelope(
            requestID: envelope.requestID,
            operationID: nil,
            result: try HandshakeResponse.v1())))
    }
    lock.withLock { methodCounts["\(method)", default: 0] += 1 }
    let operation: OperationContext
    let exactRevision: UInt64
    switch (method, envelope.command) {
    case (.cancelPrepared, .cancelPrepared(let cancellation)):
      operation = cancellation.operation
      exactRevision = cancellation.expectedRevision + 2
    case (.attestReady, .attestReady(let attestation)):
      operation = attestation.operation
      exactRevision = attestation.operation.authorityRevision + 3
    case (.attestStopped, .attestStopped(let attestation)):
      operation = attestation.operation
      exactRevision = attestation.operation.authorityRevision + 3
    default:
      throw AuthorityDomainError(code: .invalidMessage)
    }
    let acknowledgement = try AuthorityAcknowledgement(
      operationID:
        reply == .wrongOperation
        ? AuthorityIdentifier(UUID()) : operation.operationID,
      revision:
        reply == .wrongRevision
        ? exactRevision - 1 : exactRevision)
    return AuthorityXPCReply(
      response: try AuthorityV1Codec.encodeResponse(
        AuthorityResponseEnvelope(
          requestID: envelope.requestID,
          operationID: operation.operationID,
          result: acknowledgement)))
  }

  func noteOwnerStopped() async {
    lock.withLock { ownerStoppedCountValue += 1 }
  }

  func invalidate() async {}
}

private final class ProxyBindReplyRemote: AuthorityRemoteCalling, @unchecked Sendable {
  private let lock = NSLock()
  private let leaseState: AuthorityLeaseState
  private var confirmedClaimsValue = 0

  init(leaseState: AuthorityLeaseState) { self.leaseState = leaseState }

  var confirmedClaims: Int { lock.withLock { confirmedClaimsValue } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    let envelope = try AuthorityV1Codec.decodeRequest(request)
    if method == .handshake {
      return AuthorityXPCReply(
        response: try AuthorityV1Codec.encodeResponse(
          AuthorityResponseEnvelope(
            requestID: envelope.requestID,
            operationID: nil,
            result: try HandshakeResponse.v1())))
    }
    guard method == .bindProxyOwner,
      case .bindProxyOwner(let binding) = envelope.command
    else { throw AuthorityDomainError(code: .invalidMessage) }
    defer { binding.capability.erase() }
    let lease = try LeaseView(
      leaseID: binding.leaseID,
      operation: binding.operation,
      state: leaseState,
      expiryMonotonic: 10_000)
    return AuthorityXPCReply(
      response: try AuthorityV1Codec.encodeResponse(
        AuthorityResponseEnvelope(
          requestID: envelope.requestID,
          operationID: binding.operation.operationID,
          result: lease)))
  }

  func confirmOwnerClaim() async throws {
    lock.withLock { confirmedClaimsValue += 1 }
  }

  func invalidate() async {}
}

@Test func unavailableAuthorityFailsClosedWithoutReachingAnyMutation() async throws {
  let remote = UnavailableAuthorityRemote()
  let client = BoundedAuthorityXPCClient(remote: remote)

  let operation = try exampleTunnelOperation()
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: 512, configSHA256: operation.configSHA256,
    identitySHA256: operation.identitySHA256,
    credentialAudience: try testCredentialAudience(), credentialSlots: [],
    tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: operation.authorityRevision,
    configuration: descriptor)
  let configuration = try SensitiveBytes(
    copying: Data(repeating: 0x41, count: 512), maximumCount: 512)
  let secrets = try SensitiveBytes(
    copying: Data(repeating: 0x42, count: 32), maximumCount: 32)

  var thrown: AuthorityDomainError?
  do {
    _ = try await client.prepare(request, configuration: configuration, secrets: secrets)
  } catch let error as AuthorityDomainError {
    thrown = error
  }

  // The failure is the stable typed Authority-unavailable error.
  #expect(thrown?.code == .globalAuthorityUnavailable)
  #expect(thrown?.nativeBridgeFailure.code == .globalAuthorityUnavailable)
  // Only the read-only handshake was attempted; the prepare mutation never
  // reached the remote, and there is no fallback call.
  #expect(remote.invokedMethods == [.handshake])
  #expect(!remote.invokedMethods.contains(.prepareStart))
  // Transported secret material is erased on the failure path.
  #expect(configuration.isErased)
  #expect(secrets.isErased)
}

@Test func cancellationAcceptsOnlyTheExactOperationAndDurableRevision() async throws {
  let operation = try exampleTunnelOperation()

  let exactRemote = OperationAcknowledgementRemote(reply: .exact)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  try await exactClient.cancelPrepared(
    operation,
    revision: operation.authorityRevision + 1)
  #expect(exactRemote.count(.cancelPrepared) == 1)

  for fault in [
    OperationAcknowledgementRemote.Reply.wrongOperation,
    .wrongRevision,
  ] {
    let remote = OperationAcknowledgementRemote(reply: fault)
    let client = BoundedAuthorityXPCClient(remote: remote)
    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      try await client.cancelPrepared(
        operation,
        revision: operation.authorityRevision + 1)
    }
    // A semantically invalid mutation ACK is terminal and is never retried.
    #expect(remote.count(.cancelPrepared) == 1)
  }
}

@Test func readyAcceptsOnlyTheExactOperationAndDurableRevision() async throws {
  let operation = try exampleTunnelOperation()
  let attestation = try ReadyAttestation(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()),
    runtimeDigest: operation.identitySHA256,
    ownerRole: .provider,
    readyFlags: .all,
    packetPumpLimits: PacketPumpLimits(
      maximumQueuedPackets: 32,
      maximumQueuedBytes: 131_072,
      maximumPacketBytes: 1_500,
      maximumReadBatch: 16),
    monotonicTimestamp: 2_000)

  let exactRemote = OperationAcknowledgementRemote(reply: .exact)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  try await exactClient.attestReady(attestation)
  #expect(exactRemote.count(.attestReady) == 1)

  for fault in [
    OperationAcknowledgementRemote.Reply.wrongOperation,
    .wrongRevision,
  ] {
    let remote = OperationAcknowledgementRemote(reply: fault)
    let client = BoundedAuthorityXPCClient(remote: remote)
    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      try await client.attestReady(attestation)
    }
    #expect(remote.count(.attestReady) == 1)
  }
}

@Test func stoppedAcceptsOnlyTheExactOperationAndLifecycleRevisionWindow() async throws {
  let operation = try exampleTunnelOperation()
  let attestation = try StoppedAttestation(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()),
    libboxStopped: true,
    transportClosed: true,
    osRestored: true,
    monotonicTimestamp: 3_000)

  let exactRemote = OperationAcknowledgementRemote(reply: .exact)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  try await exactClient.attestStopped(attestation)
  #expect(exactRemote.count(.attestStopped) == 1)
  #expect(exactRemote.ownerStoppedCount == 1)

  for fault in [
    OperationAcknowledgementRemote.Reply.wrongOperation,
    .wrongRevision,
  ] {
    let remote = OperationAcknowledgementRemote(reply: fault)
    let client = BoundedAuthorityXPCClient(remote: remote)
    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      try await client.attestStopped(attestation)
    }
    #expect(remote.count(.attestStopped) == 1)
    #expect(remote.ownerStoppedCount == 1)
  }
}

@Test func ownerHeartbeatStartsOnlyAfterAnExactStartingLeaseIsValidated() async throws {
  let operation = try exampleProxyOperation()
  let context = try ProxyOwnerContext(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()))

  let exactRemote = ProxyBindReplyRemote(leaseState: .starting)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  let exactLease = try await exactClient.bind(
    OwnerCapability(
      copying: Data(repeating: 0x41, count: AuthorityV1Limits.capabilityBytes)),
    context: context)
  #expect(exactLease.operation == operation)
  #expect(exactLease.leaseID == context.leaseID)
  #expect(exactRemote.confirmedClaims == 1)

  let invalidRemote = ProxyBindReplyRemote(leaseState: .active)
  let invalidClient = BoundedAuthorityXPCClient(remote: invalidRemote)
  await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
    _ = try await invalidClient.bind(
      OwnerCapability(
        copying: Data(repeating: 0x42, count: AuthorityV1Limits.capabilityBytes)),
      context: context)
  }
  #expect(invalidRemote.confirmedClaims == 0)
}

// MARK: - Stable cross-language error mapping

private struct ErrorContractFixture: Decodable {
  struct Entry: Decodable {
    let code: String
    let retry: String
    let message: String
  }

  let errors: [Entry]
}

private func errorContractData() throws -> Data {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  return try Data(
    contentsOf: root.appendingPathComponent("fixtures/authority-v1/error-contract.json"))
}

@Test func authorityErrorCodesMapOneToOneToTheSharedContractFixture() throws {
  let contract = try JSONDecoder().decode(
    ErrorContractFixture.self, from: errorContractData())
  let byCode = Dictionary(uniqueKeysWithValues: contract.errors.map { ($0.code, $0) })

  // Every Swift AuthorityErrorCode has exactly one contract entry with a
  // matching wire code, stable message, retry directive, and NativeBridge code.
  #expect(byCode.count == AuthorityErrorCode.allCases.count)
  for code in AuthorityErrorCode.allCases {
    let entry = try #require(byCode[code.rawValue])
    #expect(code.nativeBridgeCode.rawValue == entry.code)
    #expect(code.stableMessage == entry.message)
    #expect(code.nativeBridgeCode.stableMessage == entry.message)
    #expect(code.retryDirective.rawValue == entry.retry)

    // NativeBridgeErrorCode round-trips over its stable wire representation.
    let encoded = try JSONEncoder().encode(code.nativeBridgeCode)
    #expect(
      try JSONDecoder().decode(NativeBridgeErrorCode.self, from: encoded)
        == code.nativeBridgeCode)
  }
}

@Test func nativeFailureIgnoresUntrustedTextAndUnknownCodesFailClosed() throws {
  // Localized/untrusted supplied text is discarded in favor of the stable message.
  let failure = NativeBridgeFailure(
    code: .globalLeaseConflict, message: "untrusted localized text")
  let encoded = try JSONEncoder().encode(failure)
  let decoded = try JSONDecoder().decode(NativeBridgeFailure.self, from: encoded)
  #expect(decoded == failure)
  #expect(decoded.message == NativeBridgeErrorCode.globalLeaseConflict.stableMessage)
  #expect(!decoded.message.contains("untrusted"))

  // An unknown wire code decodes to the internal fail-closed code with a
  // redacted stable message.
  let unknown = Data(
    "{\"code\":\"future_authority_code\",\"message\":\"/private/path secret\"}".utf8)
  let fallback = try JSONDecoder().decode(NativeBridgeFailure.self, from: unknown)
  #expect(fallback.code == .internal)
  #expect(fallback.message == NativeBridgeErrorCode.internal.stableMessage)
  #expect(!fallback.message.contains("private"))
  #expect(!fallback.message.contains("secret"))
}

// MARK: - Release gate emits no mutation or fallback action

private enum StartAction: Equatable {
  case libboxStart
  case systemProxyApply
  case tunnelStart
  case fallback
}

/// Pure fake that records any data-plane action a start pipeline would take.
private final class RecordingStartActuator {
  private(set) var actions: [StartAction] = []

  func performProvenStart() {
    actions.append(.libboxStart)
    actions.append(.tunnelStart)
  }
}

/// A start pipeline that consults the Release gate before any mutation and has
/// no fallback branch. Mutation is reachable only after a proven gate.
private func gatedStart(
  proof: GlobalAuthorityProofStatus, actuator: RecordingStartActuator
) throws {
  try GlobalAuthorityReleaseGate.validate(proof)
  actuator.performProvenStart()
}

@Test func unprovenReleaseGateEmitsNoMutationOrFallbackAction() {
  for status in GlobalAuthorityProofStatus.allCases where status != .proven {
    let actuator = RecordingStartActuator()
    #expect(throws: GlobalAuthorityGateError.proofMissing(status)) {
      try gatedStart(proof: status, actuator: actuator)
    }
    // No libbox start, System Proxy apply, Tunnel start, or fallback occurs.
    #expect(actuator.actions.isEmpty)
    #expect(!actuator.actions.contains(.fallback))
  }
}

@Test func provenReleaseGateIsTheOnlyPathThatPermitsAStart() throws {
  let actuator = RecordingStartActuator()
  try gatedStart(proof: .proven, actuator: actuator)
  #expect(actuator.actions == [.libboxStart, .tunnelStart])
  #expect(!actuator.actions.contains(.fallback))
}
