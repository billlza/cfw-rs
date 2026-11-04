import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing

@testable import CFWGlobalAuthority
@testable import CFWSharedProtocol

// Recovering from an ended owner: a quarantine that recovers as a restart
// would, only while the owner has ended, read back from the journal store, and
// the restart posture that follows the last record.
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
    thrownAuthorityCode { _ = try reconcile(subject, as: host(uid: 501)) } == .quarantined)
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
    thrownAuthorityCode {
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
      thrownAuthorityCode { _ = try reconcile(subject, as: host(uid: 502)) } == .cleanupUnproven)
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
