import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

// Additional task 9.11 example coverage for the authenticated Authority *service*
// boundary (`AuthenticatedAuthorityPeerService` + `GlobalAuthorityServiceCore`)
// that the rest of the suite does not already own:
//
//   * secret-material bound violations mapped through the full `prepareStart`
//     decode path to the stable `secretBoundsExceeded` code before any mutation;
//   * a System Proxy preparation rejecting an attached secret payload;
//   * startup recovery/quarantine gating observed through the service (starts are
//     rejected while Recovering/Quarantined and an un-enrolled store discloses no
//     replay state); and
//   * the fail-closed rule that a snapshot never discloses lease state to a peer
//     that is not the current lease owner.
//
// Behaviors already covered elsewhere are intentionally NOT duplicated here:
//   * handshake negotiation, unsupported version/feature, identity rejection,
//     ticket duplicate/expiry, and redacted diagnostics live in
//     AuthorityProtocolServiceExampleTests.swift;
//   * malformed/oversize/wrong-command rejection and canonical correlation live
//     in AuthorityServiceTests.swift;
//   * busy/resource-exhausted backpressure and the bounded event queue live in
//     AuthorityBackpressureTests.swift;
//   * durable-write fault injection and journal recovery live in
//     AuthorityJournalTests.swift / AuthorityLivenessTests.swift;
//   * the exact ticket/secret lifecycle bounds and terminal erasure live in
//     TunnelSecretLifecycleTests.swift;
//   * the audit-token authorization conjunction lives in PeerAuthorizationTests.swift.
//
// Every boundary is a pure fake: no real launchd, Network Extension,
// SystemConfiguration, Security.framework, wall clock, or randomness is used.

// MARK: - Deterministic fakes

private final class BoundsJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var states: [AuthorityCommittedState] = []

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      states.append(state)
      return try AuthorityJournalHead(
        sequence: UInt64(states.count), committedLength: UInt64(states.count),
        recordSHA256: boundsDigest(Data("journal-\(states.count)".utf8)))
    }
  }

  var count: Int { lock.withLock { states.count } }
}

private struct BoundsRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

private struct BoundsClock: AuthorityMonotonicClock {
  func nowMilliseconds() -> UInt64 { 1_000 }
}

private func boundsDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

private func boundsPeer(_ role: AuthorityRole, ownerUID: UInt32 = 501) throws -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: try boundsDigest(Data("connection".utf8)),
    pid: 42, euid: role == .provider ? 0 : ownerUID,
    auditSessionID: role == .provider ? 0 : 7,
    role: role, consoleUID: 501)
}

private func authorityError(_ value: NSError?) -> AuthorityErrorCode? {
  guard let value,
    let raw = value.userInfo[AuthorityXPCErrorContract.stableCodeKey] as? String
  else { return nil }
  return AuthorityErrorCode(rawValue: raw)
}

private func service(
  for core: GlobalAuthorityServiceCore, role: AuthorityRole = .host, ownerUID: UInt32 = 501
) throws -> AuthenticatedAuthorityPeerService {
  let peer = try boundsPeer(role, ownerUID: ownerUID)
  return AuthenticatedAuthorityPeerService(
    peerID: UUID(), peer: peer, reauthorize: { peer }, core: core,
    concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
}

private func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
  var bigEndian = value.bigEndian
  withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
}

// MARK: - Fixtures

private func tunnelRequest(
  ownerUID: UInt32 = 501, revision: UInt64 = 1
) throws -> (request: PrepareStartRequest, configuration: Data) {
  let configuration = Data("{\"outbounds\":[]}".utf8)
  let configDigest = try boundsDigest(configuration)
  let identityDigest = try boundsDigest(Data("identity".utf8))
  let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let slot = try CredentialSlot(
    reference: reference, target: .trojanPassword,
    outboundIndex: 0, jsonPointer: "/outbounds/0/password")
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1),
    mode: .tunnel, configSHA256: configDigest,
    identitySHA256: identityDigest, ownerUID: ownerUID, authorityRevision: revision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count), configSHA256: configDigest,
    identitySHA256: identityDigest,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identityDigest),
    credentialSlots: [slot],
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: revision, configuration: descriptor)
  return (request, configuration)
}

private func systemProxyRequest(
  ownerUID: UInt32 = 501, revision: UInt64 = 1
) throws -> (request: PrepareStartRequest, configuration: Data) {
  let configuration = Data("{\"inbounds\":[]}".utf8)
  let configDigest = try boundsDigest(configuration)
  let identityDigest = try boundsDigest(Data("identity".utf8))
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1),
    mode: .systemProxy, configSHA256: configDigest,
    identitySHA256: identityDigest, ownerUID: ownerUID, authorityRevision: revision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count), configSHA256: configDigest,
    identitySHA256: identityDigest,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identityDigest),
    credentialSlots: [], tunnelOptions: nil)
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: revision, configuration: descriptor)
  return (request, configuration)
}

private func makeCore(
  reducer: GlobalAuthorityReducer
) -> (journal: BoundsJournal, core: GlobalAuthorityServiceCore) {
  let journal = BoundsJournal()
  let core = GlobalAuthorityServiceCore(
    reducer: reducer, journal: journal,
    randomness: BoundsRandomness(), clock: BoundsClock())
  return (journal, core)
}

private func boundsCursor() throws -> ReplayCursor {
  try ReplayCursor(
    installationID: AuthorityIdentifier(UUID()), acceptedEpoch: 4,
    acceptedGeneration: 9, revision: 7,
    previousRecordSHA256: try boundsDigest(Data("cursor".utf8)))
}

// MARK: - Secret-material bounds through the full prepareStart path

@Test func prepareStartMapsOverIndividualSecretBoundToSecretBoundsExceeded() throws {
  let objects = makeCore(reducer: try .unEnrolledOff())
  let host = try service(for: objects.core)
  let (request, configuration) = try tunnelRequest()

  // A canonical-looking secret payload whose single slot exceeds the 16 KiB
  // individual-secret bound must be rejected as `secretBoundsExceeded` before any
  // durable mutation, and no ticket/secret may be retained.
  var payload = Data("CFWASV01".utf8)
  appendBigEndian(UInt16(1), to: &payload)
  let overLimit = AuthorityV1Limits.maximumIndividualSecretBytes + 1
  appendBigEndian(UInt32(overLimit), to: &payload)
  payload.append(Data(repeating: 0x41, count: overLimit))

  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .prepareStart(request)))
  var observed: AuthorityErrorCode?
  host.prepareStart(envelope, configuration: configuration, secretPayload: payload) {
    _, error in observed = authorityError(error)
  }
  #expect(observed == .secretBoundsExceeded)
  #expect(objects.journal.count == 0)
}

@Test func prepareStartMapsMalformedSecretPayloadToSecretBoundsExceeded() throws {
  let objects = makeCore(reducer: try .unEnrolledOff())
  let host = try service(for: objects.core)
  let (request, configuration) = try tunnelRequest()

  // A truncated payload shorter than the fixed header is a bound violation and is
  // rejected before mutation rather than being partially interpreted.
  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .prepareStart(request)))
  var observed: AuthorityErrorCode?
  host.prepareStart(
    envelope, configuration: configuration, secretPayload: Data([0x00, 0x01, 0x02])
  ) { _, error in observed = authorityError(error) }
  #expect(observed == .secretBoundsExceeded)
  #expect(objects.journal.count == 0)
}

@Test func systemProxyPrepareRejectsAttachedSecretPayload() throws {
  let objects = makeCore(reducer: try .unEnrolledOff())
  let host = try service(for: objects.core)
  let (request, configuration) = try systemProxyRequest()

  // System Proxy never carries Tunnel secret material; an attached payload is an
  // invalid message and must not advance any durable state.
  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .prepareStart(request)))
  var observed: AuthorityErrorCode?
  host.prepareStart(
    envelope, configuration: configuration, secretPayload: Data("unexpected".utf8)
  ) { _, error in observed = authorityError(error) }
  #expect(observed == .invalidMessage)
  #expect(objects.journal.count == 0)
}

// MARK: - Startup recovery and quarantine gating through the service

@Test func snapshotOnUnenrolledStoreReportsStrictOffWithoutInventingReplayState() throws {
  // An un-enrolled store has no durable replay cursor. It reports the exact Off
  // posture and current revision so the first prepare can enroll atomically.
  let objects = makeCore(reducer: try .unEnrolledOff())
  let host = try service(for: objects.core)
  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .snapshot(SnapshotRequest())))

  var response: Data?
  var observed: AuthorityErrorCode?
  host.snapshot(envelope) { data, error in
    response = data
    observed = authorityError(error)
  }
  #expect(observed == nil)
  let decoded = try AuthorityV1Codec.decodeResponse(
    AuthoritySnapshot.self, from: try #require(response))
  #expect(decoded.result.state == .off)
  #expect(decoded.result.replayCursor == nil)
  #expect(decoded.result.leaseView == nil)
  #expect(decoded.result.revision == 1)
}

@Test func recoveringAuthorityRejectsNewStartsThroughService() throws {
  let cursor = try boundsCursor()
  let objects = makeCore(
    reducer: try .recovering(revision: cursor.revision, replayCursor: cursor))
  let host = try service(for: objects.core)
  let (request, configuration) = try systemProxyRequest(revision: cursor.revision)

  // A start submitted while Recovering is rejected before any mutation.
  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .prepareStart(request)))
  var startError: AuthorityErrorCode?
  host.prepareStart(envelope, configuration: configuration, secretPayload: nil) {
    _, error in startError = authorityError(error)
  }
  #expect(startError == .globalAuthorityRecovering)
  #expect(objects.journal.count == 0)

  // A read-only snapshot succeeds (the cursor exists) and discloses the Recovering
  // state with no lease.
  let snapshotEnvelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .snapshot(SnapshotRequest())))
  var snapshotData: Data?
  host.snapshot(snapshotEnvelope) { data, error in
    #expect(error == nil)
    snapshotData = data
  }
  let snapshot = try AuthorityV1Codec.decodeResponse(
    AuthoritySnapshot.self, from: try #require(snapshotData))
  #expect(snapshot.result.state == .recovering)
  #expect(snapshot.result.leaseView == nil)
}

@Test func quarantinedAuthorityRejectsNewStartsThroughService() throws {
  let cursor = try boundsCursor()
  let objects = makeCore(
    reducer: try GlobalAuthorityReducer(
      state: .quarantined, revision: cursor.revision, replayCursor: cursor))
  let host = try service(for: objects.core)
  let (request, configuration) = try systemProxyRequest(revision: cursor.revision)

  let envelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .prepareStart(request)))
  var observed: AuthorityErrorCode?
  host.prepareStart(envelope, configuration: configuration, secretPayload: nil) {
    _, error in observed = authorityError(error)
  }
  #expect(observed == .quarantined)
  #expect(objects.journal.count == 0)
}

// MARK: - Non-disclosure of lease state to another user

@Test func snapshotNeverDisclosesLeaseStateToADifferentUser() throws {
  // Establish a prepared lease owned by console UID 501.
  let objects = makeCore(reducer: try .unEnrolledOff())
  let owner = try service(for: objects.core, ownerUID: 501)
  let (request, configuration) = try systemProxyRequest(ownerUID: 501)
  let prepareEnvelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .prepareStart(request)))
  owner.prepareStart(prepareEnvelope, configuration: configuration, secretPayload: nil) {
    _, error in #expect(error == nil)
  }
  #expect(objects.journal.count == 2)

  // A Host peer belonging to a different user (UID 999) is refused any snapshot of
  // the current owner's lease; state is never disclosed across users.
  let intruder = try service(for: objects.core, ownerUID: 999)
  let snapshotEnvelope = try AuthorityV1Codec.encode(
    try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .snapshot(SnapshotRequest())))
  var observed: AuthorityErrorCode?
  var disclosed: Data?
  intruder.snapshot(snapshotEnvelope) { data, error in
    observed = authorityError(error)
    disclosed = data
  }
  #expect(observed == .globalAuthorityIdentityRejected)
  #expect(disclosed == nil)
}
