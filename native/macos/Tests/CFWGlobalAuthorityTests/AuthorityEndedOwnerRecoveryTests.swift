import CryptoKit
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority
@testable import CFWSharedProtocol

private func recoveryDigest(_ text: String) -> CFWSharedProtocol.SHA256Digest {
  try! CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined())
}

/// Keeps every committed record with the head it returned.
private final class RecordingJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private var commits: [AuthorityJournalCommit] = []

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      let sequence = UInt64(commits.count + 1)
      let head = try AuthorityJournalHead(
        sequence: sequence, committedLength: sequence * 128,
        recordSHA256: recoveryDigest("record-\(sequence)"))
      commits.append(AuthorityJournalCommit(state: state, head: head))
      return head
    }
  }

  var count: Int { lock.withLock { commits.count } }
  var last: AuthorityJournalCommit? { lock.withLock { commits.last } }
}

/// The processes a test says the kernel holds, by pid.
private final class FakeProcessTable: AuthorityProcessTable, @unchecked Sendable {
  private let lock = NSLock()
  private var processes: [pid_t: KernelProcessIdentity] = [:]
  private var unreadable = false

  func start(_ pid: pid_t, at seconds: UInt64, microseconds: UInt64 = 250, uid: uid_t = 501) {
    lock.withLock {
      processes[pid] = KernelProcessIdentity(
        processIdentifier: pid, effectiveUserIdentifier: uid, realUserIdentifier: uid,
        startSeconds: seconds, startMicroseconds: microseconds)
    }
  }

  func end(_ pid: pid_t) { lock.withLock { processes[pid] = nil } }
  func setUnreadable(_ value: Bool) { lock.withLock { unreadable = value } }

  func lookup(_ processIdentifier: pid_t) throws -> KernelProcessIdentity? {
    try lock.withLock {
      if unreadable { throw KernelProcessTableError.unreadable(EIO) }
      return processes[processIdentifier]
    }
  }
}

/// For tests whose owners are no processes of this machine: the kernel holds
/// none of their pids, so no quarantine of theirs waits for an owner to end.
struct EmptyAuthorityProcessTable: AuthorityProcessTable {
  func lookup(_ processIdentifier: pid_t) throws -> KernelProcessIdentity? { nil }
}

private struct FixedRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

private final class ManualClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64 = 1_000
  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func advance(by milliseconds: UInt64) { lock.withLock { value += milliseconds } }
}

private struct FixedConsole: LiveConsoleUserResolving {
  let uid: uid_t?
  func liveConsoleUID() -> uid_t? { uid }
}

private let ownerPID: pid_t = 4_242
private let ownerStart: UInt64 = 1_760_000_000

private func host(uid: UInt32) -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: recoveryDigest("host-\(uid)"), pid: 300, euid: uid,
    auditSessionID: 17, role: .host, consoleUID: uid)
}

private func owner(role: AuthorityRole, uid: UInt32, pid: pid_t = ownerPID) -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: recoveryDigest("owner-\(role.rawValue)"), pid: pid,
    euid: role == .provider ? 0 : uid, auditSessionID: role == .provider ? 0 : 17, role: role,
    consoleUID: uid)
}

/// An Authority whose owner bound a lease of `mode` and then lost its
/// connection without attesting Stopped, past the stop deadline.
private struct QuarantinedOwner {
  let core: GlobalAuthorityServiceCore
  let journal: RecordingJournal
  let processes: FakeProcessTable
  let clock: ManualClock
  let supervisor: AuthorityLivenessSupervisor
  let operation: OperationContext
  let ownerPeerID: UUID
}

/// Prepares a lease of `mode` for `ownerUID` and binds it from `pid` as
/// `peerID`. The table holds the process at bind only when `knownAtBind`, and
/// then as `uidAtBind` when given, else as the owner's user.
private func bindOwner(
  core: GlobalAuthorityServiceCore, processes: FakeProcessTable, mode: AuthorityMode,
  ownerUID: UInt32, pid: pid_t, generation: UInt64, knownAtBind: Bool = true,
  uidAtBind: uid_t? = nil, readableAtBind: Bool = true, peerID: UUID = UUID()
) throws -> OperationContext {
  let configuration = Data("{\"inbounds\":[]}".utf8)
  let configurationDigest = recoveryDigest("{\"inbounds\":[]}")
  let identity = recoveryDigest("identity-\(mode.rawValue)")
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: installationID, epoch: 3, generation: generation),
    mode: mode, configSHA256: configurationDigest, identitySHA256: identity,
    ownerUID: ownerUID, authorityRevision: core.currentRevision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count), configSHA256: configurationDigest,
    identitySHA256: identity,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identity),
    credentialSlots: [],
    tunnelOptions: mode == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500) : nil)
  let prepared = try core.prepare(
    PrepareStartRequest(
      operation: operation, expectedRevision: core.currentRevision, configuration: descriptor),
    configuration: configuration, secretPayload: nil, peer: host(uid: ownerUID))
  if knownAtBind {
    processes.start(pid, at: ownerStart, uid: uidAtBind ?? (mode == .tunnel ? 0 : uid_t(ownerUID)))
  }
  processes.setUnreadable(!readableAtBind)
  defer { processes.setUnreadable(false) }
  switch mode {
  case .tunnel:
    let redeemed = try core.redeemTunnelTicket(
      RedeemTunnelTicketRequest(ticket: #require(prepared.ticket)),
      peer: owner(role: .provider, uid: ownerUID, pid: pid), peerID: peerID)
    redeemed.transport.erase()
  case .localProxy, .systemProxy:
    _ = try core.bindProxyOwner(
      BindProxyOwnerRequest(
        operation: operation, leaseID: prepared.leaseID,
        capability: #require(prepared.ownerCapability)),
      peer: owner(role: .proxyAgent, uid: ownerUID, pid: pid), peerID: peerID)
  }
  return operation
}

private let installationID = AuthorityIdentifier(UUID())

private func quarantinedOwner(
  mode: AuthorityMode, ownerUID: UInt32 = 501, ownerKnownAtBind: Bool = true,
  ownerUIDAtBind: uid_t? = nil, tableReadableAtBind: Bool = true
) throws -> QuarantinedOwner {
  let journal = RecordingJournal()
  let processes = FakeProcessTable()
  let clock = ManualClock()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: journal, randomness: FixedRandomness(),
    clock: clock, processTable: processes)
  let supervisor = AuthorityLivenessSupervisor(
    core: core, consoleResolver: FixedConsole(uid: uid_t(ownerUID)))
  let ownerPeerID = UUID()
  let operation = try bindOwner(
    core: core, processes: processes, mode: mode, ownerUID: ownerUID, pid: ownerPID,
    generation: 9, knownAtBind: ownerKnownAtBind, uidAtBind: ownerUIDAtBind,
    readableAtBind: tableReadableAtBind, peerID: ownerPeerID)
  #expect(try supervisor.forceStop(.connectionLoss) == .forcedStop(.connectionLoss))
  clock.advance(by: AuthorityV1Limits.stopAttestationTimeoutMilliseconds)
  #expect(try supervisor.evaluate() == .quarantinedForUnprovenCleanup)
  #expect(core.authorityState == .quarantined)
  return QuarantinedOwner(
    core: core, journal: journal, processes: processes, clock: clock, supervisor: supervisor,
    operation: operation, ownerPeerID: ownerPeerID)
}

private func reconcile(
  _ subject: QuarantinedOwner, as peer: PeerIdentity
) throws -> ReconcileOffReceipt {
  try reconcile(subject.core, as: peer)
}

private func reconcile(
  _ core: GlobalAuthorityServiceCore, as peer: PeerIdentity
) throws -> ReconcileOffReceipt {
  // A Host asks with the revision its replay cursor names, which matches the
  // Authority's own only once it is Recovering.
  let cursor = try #require(try core.snapshot(peer: peer).replayCursor)
  return try core.reconcileOff(
    ReconcileOffRequest(
      expectedRevision: cursor.revision, replayCursor: cursor,
      proxy: RecoveryProxyOffEvidence(
        ownershipCleared: true, listenerClosed: true,
        effectiveSystemConfigurationRestored: true),
      provider: RecoveryProviderOffEvidence(
        ownershipCleared: true, libboxStopped: true, packetPumpClosed: true),
      managedTunnel: .disconnected),
    peer: peer)
}

private func authorityCode(_ body: () throws -> Void) -> AuthorityErrorCode? {
  do {
    try body()
    return nil
  } catch let error as AuthorityDomainError {
    return error.code
  } catch {
    Issue.record("unexpected error \(error)")
    return nil
  }
}

/// Once the owner's process has ended, nothing it ran is left to wait for, so
/// the quarantine becomes the Recovering state restarting the Authority would
/// make from the same journal, and the Host can prove Off without a restart.
@Test(arguments: [AuthorityMode.systemProxy, .localProxy, .tunnel])
func quarantineOfAnEndedOwnerRecoversAsARestartWould(mode: AuthorityMode) throws {
  let subject = try quarantinedOwner(mode: mode)
  let quarantine = try #require(subject.journal.last)
  let records = subject.journal.count
  #expect(quarantine.state.state == .quarantined)

  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  #expect(subject.core.authorityState == .recovering)
  #expect(subject.journal.count == records, "recovery wrote a journal record")
  let snapshot = try subject.core.snapshot(peer: host(uid: 501))
  #expect(snapshot.state == .recovering)
  #expect(snapshot.revision == quarantine.state.revision)
  #expect(snapshot.leaseView == nil)
  #expect(
    snapshot.replayCursor
      == (try ReplayCursor(
        installationID: subject.operation.root.installationID,
        acceptedEpoch: subject.operation.root.epoch,
        acceptedGeneration: subject.operation.root.generation,
        revision: quarantine.state.revision,
        previousRecordSHA256: quarantine.head.recordSHA256)))
  // A restart reconstructs the same Authority from the quarantine's record.
  let restarted = GlobalAuthorityServiceCore(
    reducer: try GlobalAuthorityReducer.reconciled(
      from: AuthorityJournalRecovery(
        committedState: quarantine.state, head: quarantine.head,
        posture: .recovering(.stopOwner))),
    journal: RecordingJournal(), processTable: FakeProcessTable())
  #expect(try restarted.snapshot(peer: host(uid: 501)) == snapshot)
  // The ended owner's connection holds nothing any more.
  #expect(subject.core.ownerPeerID() == nil)
  #expect(try subject.supervisor.forceStop(.connectionLoss) == .none)
  #expect(try subject.supervisor.evaluate() == .none)

  let receipt = try reconcile(subject, as: host(uid: 501))
  #expect(receipt.revision == quarantine.state.revision + 1)
  #expect(subject.core.authorityState == .off)
  #expect(subject.journal.last?.state.transition == .reconcileOff)
  #expect(subject.journal.last?.state.state == .off)
}

@Test func quarantineLastsWhileTheOwnerStillRuns() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  for _ in 0..<3 {
    #expect(try subject.supervisor.evaluate() == .none)
  }
  #expect(subject.core.authorityState == .quarantined)
  #expect(
    authorityCode { _ = try reconcile(subject, as: host(uid: 501)) } == .quarantined)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
}

@Test func aPidNowNamingAnotherProcessIsAnEndedOwner() throws {
  let subject = try quarantinedOwner(mode: .tunnel)
  subject.processes.start(ownerPID, at: ownerStart + 60)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  #expect(subject.core.authorityState == .recovering)
}

/// The kernel records a start to the microsecond, so a process that took the
/// pid within the owner's second is still another process.
@Test func aPidTakenWithinTheOwnersSecondIsAnEndedOwner() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  subject.processes.start(ownerPID, at: ownerStart, microseconds: 251)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
}

/// At bind the pid may already name another user's process, once the binding
/// owner ended. That process is not the owner, so the quarantine lasts until
/// restart, as for an owner unknown at bind.
@Test func aBindWhosePidRunsAsAnotherUserRecordsNoOwner() throws {
  let subject = try quarantinedOwner(mode: .systemProxy, ownerUIDAtBind: 777)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .none)
  #expect(subject.core.authorityState == .quarantined)
}

@Test func anUnreadableProcessTableProvesNothing() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  subject.processes.end(ownerPID)
  subject.processes.setUnreadable(true)
  #expect(try subject.supervisor.evaluate() == .none)
  #expect(subject.core.authorityState == .quarantined)
  subject.processes.setUnreadable(false)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
}

/// Without the owner's start time at bind, its end cannot be told apart from a
/// later process with its pid, so the quarantine lasts until restart.
@Test(arguments: [(false, true), (true, false)])
func anOwnerUnknownAtBindKeepsItsQuarantine(knownAtBind: Bool, readableAtBind: Bool) throws {
  let subject = try quarantinedOwner(
    mode: .systemProxy, ownerKnownAtBind: knownAtBind, tableReadableAtBind: readableAtBind)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .none)
  #expect(subject.core.authorityState == .quarantined)
}

/// Only a stop whose deadline passed waits for its owner. A quarantine a
/// restart reconstructed knows no owner process, so it stays; one for unproven
/// cleanup reported otherwise stays too (aQuarantineRecordDoesNotOutliveItsQuarantine).
@Test func onlyAnExpiredStopRecoversWhenItsOwnerEnds() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  _ = try reconcile(subject, as: host(uid: 501))

  let restartedQuarantine = GlobalAuthorityServiceCore(
    reducer: try GlobalAuthorityReducer(state: .quarantined, revision: 3),
    journal: RecordingJournal(), processTable: FakeProcessTable())
  #expect(
    try AuthorityLivenessSupervisor(
      core: restartedQuarantine, consoleResolver: FixedConsole(uid: 501)
    ).evaluate() == .none)
  #expect(restartedQuarantine.authorityState == .quarantined)
}

/// A quarantine's record describes that quarantine only. Once the machine left
/// it, a later quarantine of another lease, here for cleanup reported
/// unproven, never recovers from the earlier record. Two defences each keep it
/// out: leaving a quarantine forgets its record, and recovery requires that
/// record to be the latest. Every path that leaves a quarantine does both, so
/// this test guards them together.
@Test func aQuarantineRecordDoesNotOutliveItsQuarantine() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  let exactOff = GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true, secretBufferCleared: true,
    ownerEndpointCleared: true,
    cleanup: .reconciledBoth(
      proxyListenerClosed: true, systemConfigurationRestored: true,
      providerLibboxStopped: true, packetPumpClosed: true),
    managedTunnel: .disconnected)
  #expect(try subject.core.resolveOff(exactOff) == .off(revision: subject.core.currentRevision))
  let secondPID: pid_t = 5_151
  _ = try bindOwner(
    core: subject.core, processes: subject.processes, mode: .systemProxy, ownerUID: 501,
    pid: secondPID, generation: 10)
  #expect(try subject.supervisor.forceStop(.connectionLoss) == .forcedStop(.connectionLoss))
  let unproven = GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true, secretBufferCleared: true,
    ownerEndpointCleared: true,
    cleanup: .systemProxy(listenerClosed: true, systemConfigurationRestored: false),
    managedTunnel: .disconnected)
  _ = try subject.core.resolveOff(unproven)
  #expect(subject.core.authorityState == .quarantined)
  subject.processes.end(ownerPID)
  subject.processes.end(secondPID)
  #expect(try subject.supervisor.evaluate() == .none)
  #expect(subject.core.authorityState == .quarantined)
}

/// The quarantine keeps the owner bound; recovery releases its binding with
/// its lease, so nothing under its connection counts as the owner's any more.
@Test func recoveredOwnerCannotActAgain() throws {
  let subject = try quarantinedOwner(mode: .tunnel)
  #expect(subject.core.ownerPeerID() == subject.ownerPeerID)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  #expect(subject.core.ownerPeerID() == nil)
  #expect(
    authorityCode {
      try subject.core.recordOwnerHeartbeat(
        peer: owner(role: .provider, uid: 501), peerID: subject.ownerPeerID)
    } == .staleOperation)
}

private func authorityJournalDirectory() throws -> URL {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "cfw-authority-ended-owner-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  guard chmod(root.path, 0o700) == 0, let canonical = realpath(root.path, nil) else {
    throw CocoaError(.fileWriteUnknown)
  }
  defer { free(canonical) }
  return URL(fileURLWithPath: String(cString: canonical), isDirectory: true)
}

/// The journal store, which validates its file each time it reads it, reads
/// back the Recovering state the Authority recovered into in memory, as a
/// restart would. The Off a Host then proves on the recovered Authority is what
/// the store reads next. Only the System Proxy user requirement is the
/// in-memory Authority's own (onlyTheOwnersHostReconcilesARecoveredSystemProxy).
@Test func theJournalStoreReadsBackTheRecoveryAsARestartWould() throws {
  let root = try authorityJournalDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let store = try DescriptorRelativeAuthorityJournalStore(
    testingRootPath: root.path, expectedOwnerUID: getuid(),
    anchorStore: InMemoryAuthorityJournalAnchorStore())
  let processes = FakeProcessTable()
  let clock = ManualClock()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: store, randomness: FixedRandomness(),
    clock: clock, processTable: processes)
  let supervisor = AuthorityLivenessSupervisor(
    core: core, consoleResolver: FixedConsole(uid: 501))
  _ = try bindOwner(
    core: core, processes: processes, mode: .systemProxy, ownerUID: 501, pid: ownerPID,
    generation: 9)
  #expect(try supervisor.forceStop(.connectionLoss) == .forcedStop(.connectionLoss))
  clock.advance(by: AuthorityV1Limits.stopAttestationTimeoutMilliseconds)
  #expect(try supervisor.evaluate() == .quarantinedForUnprovenCleanup)
  processes.end(ownerPID)
  #expect(try supervisor.evaluate() == .recoveredFromEndedOwner)
  let recovered = try core.snapshot(peer: host(uid: 501))

  let restart = store.recover()
  #expect(restart.posture == .recovering(.stopOwner))
  let restarted = GlobalAuthorityServiceCore(
    reducer: try .reconciled(from: restart), journal: RecordingJournal(),
    processTable: EmptyAuthorityProcessTable())
  #expect(try restarted.snapshot(peer: host(uid: 501)) == recovered)

  let receipt = try reconcile(core, as: host(uid: 501))
  #expect(receipt.revision == recovered.revision + 1)
  #expect(receipt.replayCursor == recovered.replayCursor)
  let afterOff = store.recover()
  #expect(afterOff.posture == .recovering(.verifyOff))
  #expect(afterOff.committedState?.state == .off)
  #expect(afterOff.committedState?.revision == receipt.revision)
}

/// System Proxy settings that the ended owner applied can be restored only by
/// that user's ProxyAgent, so only that user's Host proves them restored. A
/// tunnel or local proxy leaves nothing a Host of another user cannot see.
@Test(arguments: [AuthorityMode.systemProxy, .localProxy, .tunnel])
func onlyTheOwnersHostReconcilesARecoveredSystemProxy(mode: AuthorityMode) throws {
  let subject = try quarantinedOwner(mode: mode, ownerUID: 501)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  if mode == .systemProxy {
    #expect(
      authorityCode { _ = try reconcile(subject, as: host(uid: 502)) } == .cleanupUnproven)
    #expect(subject.core.authorityState == .recovering)
    _ = try reconcile(subject, as: host(uid: 501))
  } else {
    _ = try reconcile(subject, as: host(uid: 502))
  }
  #expect(subject.core.authorityState == .off)
}

@Test func restartPostureFollowsTheLastRecord() throws {
  func record(
    _ state: AuthorityState, _ transition: AuthorityJournalTransition
  ) throws -> AuthorityCommittedState {
    try AuthorityCommittedState(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1, revision: 5,
      transition: transition, state: state, operationID: nil, mode: nil,
      configSHA256: nil, leaseID: nil, ownerUID: nil)
  }
  let table: [(AuthorityState, AuthorityJournalTransition, AuthorityRecoveryPosture)] = [
    (.active, .ready, .recovering(.reattestOwner)),
    (.preparing, .prepare, .recovering(.stopOwner)),
    (.starting, .bindOwner, .recovering(.stopOwner)),
    (.stopping, .beginStop, .recovering(.stopOwner)),
    (.off, .globalOff, .recovering(.verifyOff)),
    (.quarantined, .reconcileOff, .recovering(.stopOwner)),
    (.quarantined, .checkpoint, .recovering(.stopOwner)),
    (.quarantined, .revokeForTimeout, .quarantined(.invalidState)),
    (.recovering, .reconcileOff, .quarantined(.invalidState)),
  ]
  for (state, transition, posture) in table {
    #expect(
      AuthorityJournalRecoveryReducer.restartPosture(for: try record(state, transition))
        == posture, "\(state) after \(transition)")
  }
}
