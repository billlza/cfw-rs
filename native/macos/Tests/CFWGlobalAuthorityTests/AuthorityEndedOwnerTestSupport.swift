import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing

@testable import CFWGlobalAuthority
@testable import CFWSharedProtocol

// Shared by the ended owner and lease status tests: a recording journal, a
// fake process table, fixed randomness, clock and console, the owner and its
// host, and the binds and quarantines built from them.
func ownerRecoveryDigest(_ text: String) -> CFWSharedProtocol.SHA256Digest {
  try! CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined())
}

/// Keeps every committed record with the head it returned.
final class RecordingJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private var commits: [AuthorityJournalCommit] = []

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      let sequence = UInt64(commits.count + 1)
      let head = try AuthorityJournalHead(
        sequence: sequence, committedLength: sequence * 128,
        recordSHA256: ownerRecoveryDigest("record-\(sequence)"))
      commits.append(AuthorityJournalCommit(state: state, head: head))
      return head
    }
  }

  var count: Int { lock.withLock { commits.count } }
  var last: AuthorityJournalCommit? { lock.withLock { commits.last } }
}

/// The processes a test says the kernel holds, by pid.
final class FakeProcessTable: AuthorityProcessTable, @unchecked Sendable {
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

struct FixedRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

final class ManualClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64 = 1_000
  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func advance(by milliseconds: UInt64) { lock.withLock { value += milliseconds } }
}

struct FixedConsole: LiveConsoleUserResolving {
  let uid: uid_t?
  func liveConsoleUID() -> uid_t? { uid }
}

let ownerPID: pid_t = 4_242
let ownerStart: UInt64 = 1_760_000_000

func host(uid: UInt32) -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: ownerRecoveryDigest("host-\(uid)"), pid: 300, euid: uid,
    auditSessionID: 17, role: .host, consoleUID: uid)
}

func owner(role: AuthorityRole, uid: UInt32, pid: pid_t = ownerPID) -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: ownerRecoveryDigest("owner-\(role.rawValue)"), pid: pid,
    euid: role == .provider ? 0 : uid, auditSessionID: role == .provider ? 0 : 17, role: role,
    consoleUID: uid)
}

/// An Authority whose owner bound a lease of `mode` and then lost its
/// connection without attesting Stopped, past the stop deadline.
struct QuarantinedOwner {
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
func bindOwner(
  core: GlobalAuthorityServiceCore, processes: FakeProcessTable, mode: AuthorityMode,
  ownerUID: UInt32, pid: pid_t, generation: UInt64, knownAtBind: Bool = true,
  uidAtBind: uid_t? = nil, readableAtBind: Bool = true, peerID: UUID = UUID()
) throws -> OperationContext {
  let configuration = Data("{\"inbounds\":[]}".utf8)
  let configurationDigest = ownerRecoveryDigest("{\"inbounds\":[]}")
  let identity = ownerRecoveryDigest("identity-\(mode.rawValue)")
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

let installationID = AuthorityIdentifier(UUID())

func quarantinedOwner(
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

func reconcile(
  _ subject: QuarantinedOwner, as peer: PeerIdentity
) throws -> ReconcileOffReceipt {
  try reconcile(subject.core, as: peer)
}

func reconcile(
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

func thrownAuthorityCode(_ body: () throws -> Void) -> AuthorityErrorCode? {
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
