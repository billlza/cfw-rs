import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWGlobalAuthority

private let reducerConfigDigest = try! SHA256Digest(hex: String(repeating: "a", count: 64))
private let reducerIdentityDigest = try! SHA256Digest(hex: String(repeating: "b", count: 64))
private let reducerNonce = try! SHA256Digest(hex: String(repeating: "c", count: 64))
private let otherReducerNonce = try! SHA256Digest(hex: String(repeating: "d", count: 64))
private let reducerRecordDigest = try! SHA256Digest(hex: String(repeating: "e", count: 64))

private struct PrepareFixture {
  let input: AuthorityPrepareInput
  var operation: OperationContext { input.request.operation }
  var leaseID: AuthorityIdentifier { input.leaseID }
}

private func prepareFixture(
  installationID: AuthorityIdentifier, epoch: UInt64, generation: UInt64,
  revision: UInt64, mode: AuthorityMode = .systemProxy,
  ownerUID: UInt32 = 501
) throws -> PrepareFixture {
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: installationID, epoch: epoch, generation: generation),
    mode: mode, configSHA256: reducerConfigDigest,
    identitySHA256: reducerIdentityDigest, ownerUID: ownerUID,
    authorityRevision: revision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: 3, configSHA256: reducerConfigDigest,
    identitySHA256: reducerIdentityDigest, credentialSlots: [],
    tunnelOptions: mode == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil)
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: revision, configuration: descriptor)
  return PrepareFixture(
    input: AuthorityPrepareInput(
      request: request, leaseID: AuthorityIdentifier(UUID()),
      ownerConnectionNonce: reducerNonce, issuedMonotonic: 1_000,
      expiryMonotonic: 11_000, retainsSecretBuffer: mode == .tunnel))
}
private func authorityErrorCode(_ body: () throws -> Void) -> AuthorityErrorCode? {
  do {
    try body()
    return nil
  } catch let error as AuthorityDomainError {
    return error.code
  } catch {
    return nil
  }
}

private func exactOffProof() -> GlobalOffProof {
  GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .reconciledBoth(
      proxyListenerClosed: true, systemConfigurationRestored: true,
      providerLibboxStopped: true, packetPumpClosed: true),
    managedTunnel: .disconnected)
}

private func binding(
  _ fixture: PrepareFixture, ownerUID: UInt32 = 501,
  nonce: SHA256Digest = reducerNonce
) -> AuthorityOwnerBinding {
  AuthorityOwnerBinding(
    operation: fixture.operation, leaseID: fixture.leaseID,
    leaseOwnerUID: ownerUID, connectionNonce: nonce,
    role: fixture.operation.mode == .tunnel ? .provider : .proxyAgent,
    mode: fixture.operation.mode)
}

private func readyAttestation(_ fixture: PrepareFixture) throws -> ReadyAttestation {
  try ReadyAttestation(
    operation: fixture.operation, leaseID: fixture.leaseID,
    runtimeDigest: reducerConfigDigest,
    ownerRole: fixture.operation.mode == .tunnel ? .provider : .proxyAgent,
    readyFlags: .all,
    packetPumpLimits: fixture.operation.mode == .tunnel
      ? PacketPumpLimits(
        maximumQueuedPackets: 16, maximumQueuedBytes: 65_536,
        maximumPacketBytes: 1_500, maximumReadBatch: 8)
      : nil,
    monotonicTimestamp: 2_000)
}

private func stoppedAttestation(_ fixture: PrepareFixture) throws -> StoppedAttestation {
  try StoppedAttestation(
    operation: fixture.operation, leaseID: fixture.leaseID,
    libboxStopped: true, transportClosed: true, osRestored: true,
    monotonicTimestamp: 3_000)
}

@Test func prepareCASConsumesTupleAndKeepsInstallationImmutable() throws {
  let installation = AuthorityIdentifier(UUID())
  var reducer = try GlobalAuthorityReducer.unEnrolledOff()
  let first = try prepareFixture(
    installationID: installation, epoch: 1, generation: 1,
    revision: reducer.revision)

  let authorization = try reducer.prepare(first.input)
  #expect(authorization.committedRevision == 2)
  #expect(reducer.state == .preparing)
  #expect(reducer.lease?.operation == first.operation)
  #expect(reducer.replayCursor?.acceptedGeneration == 1)
  #expect(reducer.lastMutation == .enrollAndPrepare)

  let concurrent = try prepareFixture(
    installationID: installation, epoch: 1, generation: 2,
    revision: reducer.revision)
  #expect(
    authorityErrorCode { try reducer.prepare(concurrent.input) }
      == .globalLeaseConflict)
  #expect(reducer.revision == 2)

  try reducer.abortPrepared(operation: first.operation, expectedRevision: 2)
  #expect(
    try reducer.applyOffProof(exactOffProof(), expectedRevision: 3)
      == .off(revision: 4))

  let consumed = try prepareFixture(
    installationID: installation, epoch: 1, generation: 1,
    revision: reducer.revision)
  #expect(
    authorityErrorCode { try reducer.prepare(consumed.input) }
      == .replayRejected)

  let replacement = try prepareFixture(
    installationID: AuthorityIdentifier(UUID()), epoch: 2, generation: 1,
    revision: reducer.revision)
  #expect(
    authorityErrorCode { try reducer.prepare(replacement.input) }
      == .replayRejected)
  #expect(reducer.revision == 4)

  let newer = try prepareFixture(
    installationID: installation, epoch: 1, generation: 2,
    revision: reducer.revision)
  try reducer.prepare(newer.input)
  #expect(reducer.replayCursor?.acceptedGeneration == 2)
  #expect(reducer.lastMutation == .prepare)
}
@Test func lexicographicReplayOrderingAndExpectedRevisionAreExact() throws {
  let installation = AuthorityIdentifier(UUID())
  let cursor = try ReplayCursor(
    installationID: installation, acceptedEpoch: 4, acceptedGeneration: 99,
    revision: 7, previousRecordSHA256: reducerRecordDigest)
  var reducer = try GlobalAuthorityReducer(
    state: .off, revision: 7, replayCursor: cursor)

  let staleRevision = try prepareFixture(
    installationID: installation, epoch: 5, generation: 1, revision: 6)
  #expect(
    authorityErrorCode { try reducer.prepare(staleRevision.input) }
      == .staleOperation)

  let sameEpochLowerGeneration = try prepareFixture(
    installationID: installation, epoch: 4, generation: 98, revision: 7)
  #expect(
    authorityErrorCode { try reducer.prepare(sameEpochLowerGeneration.input) }
      == .replayRejected)

  let newerEpoch = try prepareFixture(
    installationID: installation, epoch: 5, generation: 1, revision: 7)
  try reducer.prepare(newerEpoch.input)
  #expect(reducer.replayCursor?.acceptedEpoch == 5)
  #expect(reducer.replayCursor?.acceptedGeneration == 1)
}

@Test func leaseCannotTransferAcrossUsersOrConnectionsAndActiveNeedsExactAgreement() throws {
  let fixture = try prepareFixture(
    installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1,
    revision: 1)
  var reducer = try GlobalAuthorityReducer.unEnrolledOff()
  try reducer.prepare(fixture.input)

  #expect(
    authorityErrorCode { try reducer.bindOwner(binding(fixture, ownerUID: 502)) }
      == .globalAuthorityIdentityRejected)
  #expect(
    authorityErrorCode { try reducer.bindOwner(binding(fixture, nonce: otherReducerNonce)) }
      == .globalAuthorityIdentityRejected)
  try reducer.bindOwner(binding(fixture))

  let ready = try readyAttestation(fixture)
  let wrongOS = AuthorityOSReadyObservation(
    operation: fixture.operation, configSHA256: reducerConfigDigest,
    state: .managedTunnelConnected)
  #expect(
    authorityErrorCode {
      try reducer.attestReady(
        ready, osObservation: wrongOS, ownerUID: 501,
        connectionNonce: reducerNonce)
    } == .staleOperation)
  #expect(reducer.state == .starting)

  let exactOS = AuthorityOSReadyObservation(
    operation: fixture.operation, configSHA256: reducerConfigDigest,
    state: .systemProxyEffective)
  try reducer.attestReady(
    ready, osObservation: exactOS, ownerUID: 501,
    connectionNonce: reducerNonce)
  #expect(reducer.state == .active)
  #expect(reducer.lease?.state == .active)
  #expect(
    authorityErrorCode {
      _ = try reducer.leaseForOwner(ownerUID: 502, connectionNonce: reducerNonce)
    } == .globalAuthorityIdentityRejected)

  try reducer.revokeForConsoleChange(
    liveConsoleUID: 502, ownerConnectionNonce: reducerNonce)
  #expect(reducer.state == .stopping)
  #expect(reducer.lease?.state == .revoked)
  #expect(
    authorityErrorCode {
      try reducer.attestStopped(
        stoppedAttestation(fixture), ownerUID: 502,
        connectionNonce: reducerNonce)
    } == .globalAuthorityIdentityRejected)
  try reducer.attestStopped(
    stoppedAttestation(fixture), ownerUID: 501,
    connectionNonce: reducerNonce)
}
@Test func anyOffAmbiguityQuarantinesAndCannotAdmitAnotherOwner() throws {
  let installation = AuthorityIdentifier(UUID())
  let fixture = try prepareFixture(
    installationID: installation, epoch: 1, generation: 1, revision: 1)
  var reducer = try GlobalAuthorityReducer.unEnrolledOff()
  try reducer.prepare(fixture.input)
  try reducer.bindOwner(binding(fixture))
  try reducer.beginStop(
    BeginStopRequest(
      operation: fixture.operation, leaseID: fixture.leaseID,
      expectedRevision: reducer.revision))
  try reducer.attestStopped(
    stoppedAttestation(fixture), ownerUID: 501,
    connectionNonce: reducerNonce)

  let ambiguous = GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .systemProxy(listenerClosed: true, systemConfigurationRestored: false),
    managedTunnel: .disconnected)
  let beforeQuarantine = reducer.revision
  let quarantineRevision = beforeQuarantine + 1
  #expect(
    try reducer.applyOffProof(
      ambiguous, expectedRevision: beforeQuarantine)
      == .quarantined(revision: quarantineRevision))
  #expect(reducer.state == .quarantined)

  let next = try prepareFixture(
    installationID: installation, epoch: 1, generation: 2,
    revision: reducer.revision)
  #expect(authorityErrorCode { try reducer.prepare(next.input) } == .quarantined)
  let beforeOff = reducer.revision
  #expect(
    try reducer.applyOffProof(
      exactOffProof(), expectedRevision: beforeOff)
      == .off(revision: beforeOff + 1))
  #expect(reducer.state == .off)
  #expect(reducer.lease == nil)
}

@Test func recoveryNeverConvertsUnknownCleanupToOff() throws {
  let installation = AuthorityIdentifier(UUID())
  let cursor = try ReplayCursor(
    installationID: installation, acceptedEpoch: 8, acceptedGeneration: 13,
    revision: 21, previousRecordSHA256: reducerRecordDigest)
  var reducer = try GlobalAuthorityReducer.recovering(
    revision: 21, replayCursor: cursor)
  let unknown = GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .unknown, managedTunnel: .unknown)

  #expect(
    try reducer.applyOffProof(unknown, expectedRevision: 21)
      == .quarantined(revision: 22))
  #expect(reducer.state == .quarantined)
  #expect(reducer.replayCursor == cursor)

  #expect(
    try reducer.applyOffProof(exactOffProof(), expectedRevision: 22)
      == .off(revision: 23))
  #expect(reducer.state == .off)
  #expect(reducer.replayCursor?.acceptedGeneration == 13)
}
