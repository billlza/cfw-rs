import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

// MARK: - Deterministic fakes (no real launchd / NE / SystemConfiguration / clock)

private final class LivenessJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var states: [AuthorityCommittedState] = []

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      states.append(state)
      return try AuthorityJournalHead(
        sequence: UInt64(states.count), committedLength: UInt64(states.count),
        recordSHA256: livenessDigest(Data("journal-\(states.count)".utf8)))
    }
  }
}

private struct LivenessRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

private final class MutableClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64
  init(_ value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func set(_ next: UInt64) { lock.withLock { value = next } }
}

private struct FixedConsoleResolver: LiveConsoleUserResolving {
  let uid: uid_t?
  func liveConsoleUID() -> uid_t? { uid }
}

private func livenessDigest(_ data: Data) -> CFWSharedProtocol.SHA256Digest {
  try! CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map {
      String(format: "%02x", $0)
    }.joined())
}

private let livenessNonce = try! SHA256Digest(hex: String(repeating: "c", count: 64))
private let livenessIdentity = try! SHA256Digest(hex: String(repeating: "b", count: 64))
private let livenessRecord = try! SHA256Digest(hex: String(repeating: "e", count: 64))

// MARK: - Fixtures

private struct ActiveFixture {
  let core: GlobalAuthorityServiceCore
  let installation: AuthorityIdentifier
  let ownerUID: UInt32
}

private func activeSystemProxyCore(
  ownerUID: UInt32 = 501, epoch: UInt64 = 1, generation: UInt64 = 1,
  revision: UInt64 = 4, clock: MutableClock
) throws -> ActiveFixture {
  let installation = AuthorityIdentifier(UUID())
  let configDigest = try SHA256Digest(hex: String(repeating: "a", count: 64))
  let root = try RootContext(
    installationID: installation, epoch: epoch, generation: generation)
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .systemProxy,
    configSHA256: configDigest, identitySHA256: livenessIdentity,
    ownerUID: ownerUID, authorityRevision: revision)
  let lease = try GlobalLease(
    leaseID: AuthorityIdentifier(UUID()), operation: operation, state: .active,
    issuedMonotonic: 1_000, expiryMonotonic: 11_000,
    ownerConnectionNonce: livenessNonce)
  let cursor = try ReplayCursor(
    installationID: installation, acceptedEpoch: epoch,
    acceptedGeneration: generation, revision: revision,
    previousRecordSHA256: livenessRecord)
  let binding = AuthorityOwnerBinding(
    operation: operation, leaseID: lease.leaseID, leaseOwnerUID: ownerUID,
    connectionNonce: livenessNonce, role: .proxyAgent, mode: .systemProxy)
  let reducer = try GlobalAuthorityReducer(
    state: .active, revision: revision, replayCursor: cursor, lease: lease,
    ownerBinding: binding, retainsCapabilityOrTicket: true)
  let core = GlobalAuthorityServiceCore(
    reducer: reducer, journal: LivenessJournal(),
    randomness: LivenessRandomness(), clock: clock)
  return ActiveFixture(core: core, installation: installation, ownerUID: ownerUID)
}

private func hostPeer(ownerUID: UInt32) -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: livenessDigest(Data("connection".utf8)),
    pid: 7, euid: ownerUID, auditSessionID: 3,
    role: .host, consoleUID: ownerUID)
}

private func systemProxyPrepare(
  ownerUID: UInt32, installation: AuthorityIdentifier, epoch: UInt64,
  generation: UInt64, revision: UInt64
) throws -> (request: PrepareStartRequest, configuration: Data) {
  let configuration = Data("{\"inbounds\":[]}".utf8)
  let configDigest = livenessDigest(configuration)
  let root = try RootContext(
    installationID: installation, epoch: epoch, generation: generation)
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .systemProxy,
    configSHA256: configDigest, identitySHA256: livenessIdentity,
    ownerUID: ownerUID, authorityRevision: revision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count), configSHA256: configDigest,
    identitySHA256: livenessIdentity,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: livenessIdentity),
    credentialSlots: [], tunnelOptions: nil)
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: revision, configuration: descriptor)
  return (request, configuration)
}

private func authorityCode(_ body: () throws -> Void) -> AuthorityErrorCode? {
  do {
    try body()
    return nil
  } catch let error as AuthorityDomainError {
    return error.code
  } catch {
    return nil
  }
}

private func exactOff() -> GlobalOffProof {
  GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .reconciledBoth(
      proxyListenerClosed: true, systemConfigurationRestored: true,
      providerLibboxStopped: true, packetPumpClosed: true),
    managedTunnel: .disconnected)
}

// MARK: - Tests

@Test func restartReconcilesToExactHighWaterAndRejectsStartsWhileRecovering() throws {
  let installation = AuthorityIdentifier(UUID())
  let committed = try AuthorityCommittedState(
    installationID: installation, epoch: 8, generation: 13, revision: 21,
    transition: .globalOff, state: .off, operationID: nil, mode: nil,
    configSHA256: nil, leaseID: nil, ownerUID: nil)
  let head = try AuthorityJournalHead(
    sequence: 5, committedLength: 640, recordSHA256: livenessRecord)
  let recovery = AuthorityJournalRecovery(
    committedState: committed, head: head, posture: .recovering(.verifyOff))

  var reducer = try GlobalAuthorityReducer.reconciled(from: recovery)
  #expect(reducer.state == .recovering)
  #expect(reducer.revision == 21)
  #expect(reducer.replayCursor?.acceptedEpoch == 8)
  #expect(reducer.replayCursor?.acceptedGeneration == 13)
  #expect(reducer.replayCursor?.previousRecordSHA256 == livenessRecord)

  // Recovering rejects any new start until Off is reconciled.
  let start = try prepareForRecovering(installation: installation, revision: 21)
  #expect(authorityCode { try reducer.prepare(start) } == .globalAuthorityRecovering)
}

private func prepareForRecovering(
  installation: AuthorityIdentifier, revision: UInt64
) throws -> AuthorityPrepareInput {
  let root = try RootContext(installationID: installation, epoch: 9, generation: 1)
  let configDigest = try SHA256Digest(hex: String(repeating: "a", count: 64))
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .systemProxy,
    configSHA256: configDigest, identitySHA256: livenessIdentity,
    ownerUID: 501, authorityRevision: revision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: 3, configSHA256: configDigest, identitySHA256: livenessIdentity,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: livenessIdentity),
    credentialSlots: [], tunnelOptions: nil)
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: revision, configuration: descriptor)
  return AuthorityPrepareInput(
    request: request, leaseID: AuthorityIdentifier(UUID()),
    ownerConnectionNonce: livenessNonce, issuedMonotonic: 1_000,
    expiryMonotonic: 11_000, retainsSecretBuffer: false)
}

@Test func consoleUIDChangeForcesStopWithoutLeaseTransfer() throws {
  let clock = MutableClock(2_000)
  let fixture = try activeSystemProxyCore(clock: clock)
  let supervisor = AuthorityLivenessSupervisor(
    core: fixture.core, clock: clock,
    consoleResolver: FixedConsoleResolver(uid: 502))

  let action = try supervisor.observeConsoleUser()
  #expect(action == .forcedStop(.consoleUserChange))
  #expect(fixture.core.authorityState == .stopping)
  // The lease is revoked in place and never handed to the new console user.
  #expect(fixture.core.leaseOwnerUID == fixture.ownerUID)

  // The new user cannot acquire a start until proven Off (no transfer).
  let (request, configuration) = try systemProxyPrepare(
    ownerUID: 502, installation: fixture.installation, epoch: 1,
    generation: 2, revision: fixture.core.currentRevision)
  #expect(
    authorityCode {
      _ = try fixture.core.prepare(
        request, configuration: configuration, secretPayload: nil,
        peer: hostPeer(ownerUID: 502))
    } == .globalLeaseConflict)

  // A second observation of the same changed UID is idempotent (already stopping).
  #expect(try supervisor.observeConsoleUser() == AuthorityLivenessAction.none)
}

@Test func missedHeartbeatRevokesAndOwnerStopTimeoutQuarantines() throws {
  let clock = MutableClock(1_000)
  let fixture = try activeSystemProxyCore(clock: clock)
  let supervisor = AuthorityLivenessSupervisor(
    core: fixture.core, clock: clock,
    consoleResolver: FixedConsoleResolver(uid: 501))

  supervisor.recordHeartbeat()
  clock.set(3_000)
  #expect(try supervisor.evaluate() == AuthorityLivenessAction.none)

  // Heartbeat older than the five-second bound forces a stop.
  clock.set(7_000)
  #expect(try supervisor.evaluate() == .forcedStop(.missedHeartbeat))
  #expect(fixture.core.authorityState == .stopping)

  // Owner does not attest stopped within five seconds -> Quarantined (cleanup unproven).
  clock.set(13_000)
  #expect(try supervisor.evaluate() == .quarantinedForUnprovenCleanup)
  #expect(fixture.core.authorityState == .quarantined)
}

@Test func repeatedStopDeliveryCannotExtendTheOriginalQuarantineDeadline() throws {
  let clock = MutableClock(1_000)
  let fixture = try activeSystemProxyCore(clock: clock)
  let supervisor = AuthorityLivenessSupervisor(
    core: fixture.core, clock: clock,
    consoleResolver: FixedConsoleResolver(uid: 501))

  #expect(try supervisor.forceStop(.connectionLoss) == .forcedStop(.connectionLoss))
  let stopRevision = fixture.core.currentRevision
  #expect(fixture.core.authorityState == .stopping)

  // A replay of the same durable stop claim must not restart its five-second
  // timeout. Otherwise an ACK retry loop could keep an unproven owner forever.
  clock.set(4_000)
  supervisor.noteStopOrdered(
    revision: stopRevision,
    deadlineMonotonic: 9_000)
  clock.set(6_001)
  #expect(try supervisor.evaluate() == .quarantinedForUnprovenCleanup)
  #expect(fixture.core.authorityState == .quarantined)
}

@Test func delayedStopDeliveryStillUsesTheDurableDirectiveDeadline() throws {
  let clock = MutableClock(1_000)
  let fixture = try activeSystemProxyCore(clock: clock)
  let supervisor = AuthorityLivenessSupervisor(
    core: fixture.core, clock: clock,
    consoleResolver: FixedConsoleResolver(uid: 501))
  let outcome = try #require(
    try fixture.core.forceStop(trigger: .connectionLoss))
  let directive = try #require(outcome.directive)
  #expect(directive.deadlineMonotonic == 6_000)

  // Recording is deliberately delayed. Enforcement remains tied to the
  // Authority's directive, not to local delivery latency.
  clock.set(4_000)
  supervisor.noteStopOrdered(
    revision: directive.revision,
    deadlineMonotonic: directive.deadlineMonotonic)
  clock.set(6_001)
  #expect(try supervisor.evaluate() == .quarantinedForUnprovenCleanup)
  #expect(fixture.core.authorityState == .quarantined)
}

@Test func ambiguousCleanupRetainsQuarantineUntilExactOffProven() throws {
  let clock = MutableClock(2_000)
  let fixture = try activeSystemProxyCore(clock: clock)
  _ = try fixture.core.forceStop(trigger: .connectionLoss)
  #expect(fixture.core.authorityState == .stopping)

  let ambiguous = GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .systemProxy(listenerClosed: true, systemConfigurationRestored: false),
    managedTunnel: .disconnected)
  #expect(
    try fixture.core.resolveOff(ambiguous)
      == .quarantined(
        revision: fixture.core.currentRevision))
  #expect(fixture.core.authorityState == .quarantined)

  let resolved = try fixture.core.resolveOff(exactOff())
  guard case .off = resolved else {
    Issue.record("expected Off after exact proof, got \(resolved)")
    return
  }
  #expect(fixture.core.authorityState == .off)
  #expect(fixture.core.leaseOwnerUID == nil)
}

@Test func ownersFailClosedWithinGracePeriodOnAuthorityLoss() {
  let grace = AuthorityGracePeriod(graceMilliseconds: 5_000)
  #expect(!grace.mustFailClosed(lastAuthorityContactMonotonic: 1_000, now: 1_000))
  #expect(!grace.mustFailClosed(lastAuthorityContactMonotonic: 1_000, now: 4_999))
  #expect(grace.mustFailClosed(lastAuthorityContactMonotonic: 1_000, now: 6_000))
  #expect(grace.mustFailClosed(lastAuthorityContactMonotonic: 1_000, now: 6_001))
}
