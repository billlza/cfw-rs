import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing

@testable import CFWGlobalAuthority
@testable import CFWSharedProtocol

// The lease status: what an owner, its agent, another user's host and an agent
// without a lease may learn, and its crossing of the authenticated service.
private func leaseStatus(
  _ core: GlobalAuthorityServiceCore, of leaseID: AuthorityIdentifier, asking peer: PeerIdentity
) throws -> OwnerLeaseStatus {
  try core.ownerLeaseStatus(OwnerLeaseStatusRequest(leaseID: leaseID), peer: peer)
}

private func heldLeaseID(_ core: GlobalAuthorityServiceCore) throws -> AuthorityIdentifier {
  try #require(try core.snapshot(peer: host(uid: 501)).leaseView?.leaseID)
}

/// An owner learns that the Authority still holds the lease it bound, and that
/// a quarantine holds it until the owner's process ended.
@Test func anOwnerLearnsWhetherItsLeaseIsHeldOrQuarantined() throws {
  let journal = RecordingJournal()
  let processes = FakeProcessTable()
  let clock = ManualClock()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: journal, randomness: FixedRandomness(),
    clock: clock, processTable: processes)
  let supervisor = AuthorityLivenessSupervisor(
    core: core, consoleResolver: FixedConsole(uid: 501))
  _ = try bindOwner(
    core: core, processes: processes, mode: .systemProxy, ownerUID: 501, pid: ownerPID,
    generation: 9)
  let leaseID = try heldLeaseID(core)
  let agent = owner(role: .proxyAgent, uid: 501)
  #expect(try leaseStatus(core, of: leaseID, asking: agent) == .held)

  #expect(try supervisor.forceStop(.connectionLoss) == .forcedStop(.connectionLoss))
  #expect(try leaseStatus(core, of: leaseID, asking: agent) == .held)
  clock.advance(by: AuthorityV1Limits.stopAttestationTimeoutMilliseconds)
  #expect(try supervisor.evaluate() == .quarantinedForUnprovenCleanup)
  #expect(try leaseStatus(core, of: leaseID, asking: agent) == .quarantined)
}

/// Once the Authority released the lease, in memory or by restarting from its
/// journal, or reached Off, the owner learns that the lease is gone.
@Test func anOwnerLearnsItsLeaseIsAbsentOnceTheAuthorityReleasedIt() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  let quarantine = try #require(subject.journal.last)
  let leaseID = try #require(quarantine.state.leaseID)
  let agent = owner(role: .proxyAgent, uid: 501)

  let restarted = GlobalAuthorityServiceCore(
    reducer: try GlobalAuthorityReducer.reconciled(
      from: AuthorityJournalRecovery(
        committedState: quarantine.state, head: quarantine.head,
        posture: AuthorityJournalRecoveryReducer.restartPosture(for: quarantine.state))),
    journal: RecordingJournal(), processTable: EmptyAuthorityProcessTable())
  #expect(try leaseStatus(restarted, of: leaseID, asking: agent) == .absent)

  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  #expect(try leaseStatus(subject.core, of: leaseID, asking: agent) == .absent)
  _ = try reconcile(subject, as: host(uid: 501))
  #expect(subject.core.authorityState == .off)
  #expect(try leaseStatus(subject.core, of: leaseID, asking: agent) == .absent)
  #expect(try leaseStatus(subject.core, of: AuthorityIdentifier(UUID()), asking: agent) == .absent)
}

/// An Authority that has not read its journal, or quarantined the journal it
/// read, cannot tell whether a lease existed, so it never claims one absent.
@Test func anAuthorityThatCannotReadItsJournalIsNotReady() throws {
  let agent = owner(role: .proxyAgent, uid: 501)
  let leaseID = AuthorityIdentifier(UUID())
  for reducer in [
    try GlobalAuthorityReducer.reconciled(
      from: AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .recovering(.restoreAnchorAccess))),
    try GlobalAuthorityReducer.reconciled(
      from: AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .quarantined(.malformedFrame))),
  ] {
    let core = GlobalAuthorityServiceCore(
      reducer: reducer, journal: RecordingJournal(), processTable: EmptyAuthorityProcessTable())
    #expect(try leaseStatus(core, of: leaseID, asking: agent) == .notReady, "\(reducer.state)")
  }
}

/// The Authority answers only for the caller's own lease, as the authenticated
/// connection identifies the caller: another user's agent, a Host or the
/// provider learns nothing of it.
@Test func onlyTheLeasesOwnAgentLearnsOfIt() throws {
  let journal = RecordingJournal()
  let processes = FakeProcessTable()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: journal, randomness: FixedRandomness(),
    clock: ManualClock(), processTable: processes)
  _ = try bindOwner(
    core: core, processes: processes, mode: .systemProxy, ownerUID: 501, pid: ownerPID,
    generation: 9)
  let leaseID = try heldLeaseID(core)
  for peer in [
    owner(role: .proxyAgent, uid: 502), host(uid: 501), owner(role: .provider, uid: 501),
  ] {
    #expect(
      thrownAuthorityCode { _ = try leaseStatus(core, of: leaseID, asking: peer) }
        == .globalAuthorityIdentityRejected, "\(peer.role) \(peer.euid)")
  }
}

/// Each call an agent can make asks the peer policy for what it needs of the
/// lease: only the question after its own lease does without one. The core
/// refuses a lease-less agent's other calls too, but the policy keeps such an
/// agent from reaching it.
@Test func onlyTheLeaseStatusAsksForNoLease() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  let leaseID = try #require(subject.journal.last?.state.leaseID)
  let agent = owner(role: .proxyAgent, uid: 501)
  let asked = Mutex<[ProxyAgentLeaseRequirement]>([])
  let service = AuthenticatedAuthorityPeerService(
    peerID: subject.ownerPeerID, peer: agent,
    reauthorize: { agentLease in
      asked.withLock { $0.append(agentLease) }
      return agent
    }, core: subject.core, concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
  func envelope(_ command: AuthorityCommand) throws -> Data {
    try AuthorityV1Codec.encode(
      AuthorityRequestEnvelope(requestID: AuthorityIdentifier(UUID()), command: command))
  }
  service.snapshot(try envelope(.snapshot(SnapshotRequest()))) { _, _ in }
  service.attestStopped(
    try envelope(
      .attestStopped(
        try StoppedAttestation(
          operation: subject.operation, leaseID: leaseID, libboxStopped: true,
          transportClosed: true, osRestored: true, monotonicTimestamp: 1)))
  ) { _, _ in }
  service.ownerHeartbeat { _ in }
  service.ownerLeaseStatus(
    try envelope(.ownerLeaseStatus(OwnerLeaseStatusRequest(leaseID: leaseID)))
  ) { _, _ in }
  #expect(
    asked.withLock { $0 } == [.ownedLease, .ownedLease, .ownedLease, .ownedLeaseOrNone])
}

/// A Tunnel lease is its provider's, so the agent of the same user learns
/// nothing of it either.
@Test func anAgentLearnsNothingOfATunnelLease() throws {
  let processes = FakeProcessTable()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: RecordingJournal(), randomness: FixedRandomness(),
    clock: ManualClock(), processTable: processes)
  _ = try bindOwner(
    core: core, processes: processes, mode: .tunnel, ownerUID: 501, pid: ownerPID,
    generation: 9)
  let leaseID = try heldLeaseID(core)
  #expect(
    thrownAuthorityCode {
      _ = try leaseStatus(core, of: leaseID, asking: owner(role: .proxyAgent, uid: 501))
    } == .globalAuthorityIdentityRejected)
}

/// Another user's Host learns only that a lease it does not hold exists, a
/// conflict it can wait out; the owner's user in another login session is not
/// the lease's Host.
@Test func anotherUsersHostLearnsOnlyOfAConflictingLease() throws {
  let processes = FakeProcessTable()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: RecordingJournal(), randomness: FixedRandomness(),
    clock: ManualClock(), processTable: processes)
  _ = try bindOwner(
    core: core, processes: processes, mode: .systemProxy, ownerUID: 501, pid: ownerPID,
    generation: 9)
  #expect(
    thrownAuthorityCode { _ = try core.snapshot(peer: host(uid: 502)) } == .globalLeaseConflict)
  let otherSession = PeerIdentity(
    connectionIdentityDigest: ownerRecoveryDigest("host-501"), pid: 300, euid: 501,
    auditSessionID: 18, role: .host, consoleUID: 501)
  #expect(
    thrownAuthorityCode { _ = try core.snapshot(peer: otherSession) }
      == .globalAuthorityIdentityRejected)
  #expect(try core.snapshot(peer: host(uid: 501)).leaseView != nil)
}

/// A ProxyAgent service whose calls the peer policy admits, as production's
/// listener does, against the lease the core holds at each call.
private func policyAdmittedAgentService(
  _ core: GlobalAuthorityServiceCore, peerID: UUID = UUID()
) -> AuthenticatedAuthorityPeerService {
  let agent = owner(role: .proxyAgent, uid: 501)
  return AuthenticatedAuthorityPeerService(
    peerID: peerID, peer: agent,
    reauthorize: { agentLease in
      try GlobalAuthorityPeerPolicy().authorizeRoleScopedConnection(
        role: .proxyAgent, pid: agent.pid, euid: agent.euid,
        auditSessionID: agent.auditSessionID, liveConsoleUID: 501,
        leaseOwnerUID: core.leaseOwnerUID, agentLease: agentLease)
    }, core: core, concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
}

private func serviceCode(
  _ call: (@escaping (Data?, NSError?) -> Void) -> Void
) -> AuthorityErrorCode? {
  var code: AuthorityErrorCode?
  var replied = false
  call { _, error in
    replied = true
    code = error.map { AuthorityXPCErrorContract.domainError($0).code }
  }
  #expect(replied)
  return code
}

/// Each call names what it needs of the lease, and the peer policy admits the
/// agent for that alone. Once its lease ended, a ProxyAgent may still ask
/// after it, but it gets no snapshot, heartbeat or attestation: they need a
/// lease its user owns, as the same agent's snapshot shows while it held one.
@Test func anAgentWithoutALeaseMayOnlyAskAfterItsLease() throws {
  let processes = FakeProcessTable()
  let held = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: RecordingJournal(), randomness: FixedRandomness(),
    clock: ManualClock(), processTable: processes)
  let peerID = UUID()
  _ = try bindOwner(
    core: held, processes: processes, mode: .systemProxy, ownerUID: 501, pid: ownerPID,
    generation: 9, peerID: peerID)
  let snapshot = try AuthorityV1Codec.encode(
    AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .snapshot(SnapshotRequest())))
  #expect(
    serviceCode { policyAdmittedAgentService(held, peerID: peerID).snapshot(snapshot, reply: $0) }
      == nil)

  let subject = try quarantinedOwner(mode: .systemProxy)
  let leaseID = try #require(subject.journal.last?.state.leaseID)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  let service = policyAdmittedAgentService(subject.core, peerID: subject.ownerPeerID)
  let status = try AuthorityV1Codec.encode(
    AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()),
      command: .ownerLeaseStatus(OwnerLeaseStatusRequest(leaseID: leaseID))))
  #expect(serviceCode { service.ownerLeaseStatus(status, reply: $0) } == nil)
  let attestation = try AuthorityV1Codec.encode(
    AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()),
      command: .attestStopped(
        try StoppedAttestation(
          operation: subject.operation, leaseID: leaseID, libboxStopped: true,
          transportClosed: true, osRestored: true, monotonicTimestamp: 1))))
  #expect(
    serviceCode { service.snapshot(snapshot, reply: $0) } == .globalAuthorityIdentityRejected)
  #expect(
    serviceCode { service.attestStopped(attestation, reply: $0) }
      == .globalAuthorityIdentityRejected)
  var heartbeat: AuthorityErrorCode?
  service.ownerHeartbeat { error in
    heartbeat = error.map { AuthorityXPCErrorContract.domainError($0).code }
  }
  #expect(heartbeat == .globalAuthorityIdentityRejected)
}

/// The status travels in the versioned envelope over the authenticated peer
/// service, and the answer is the caller's.
@Test func theLeaseStatusCrossesTheAuthenticatedService() throws {
  let subject = try quarantinedOwner(mode: .systemProxy)
  let leaseID = try #require(subject.journal.last?.state.leaseID)
  subject.processes.end(ownerPID)
  #expect(try subject.supervisor.evaluate() == .recoveredFromEndedOwner)
  let agent = owner(role: .proxyAgent, uid: 501)
  let service = AuthenticatedAuthorityPeerService(
    peerID: UUID(), peer: agent, reauthorize: { _ in agent }, core: subject.core,
    concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
  let requestID = AuthorityIdentifier(UUID())
  let request = try AuthorityV1Codec.encode(
    AuthorityRequestEnvelope(
      requestID: requestID,
      command: .ownerLeaseStatus(OwnerLeaseStatusRequest(leaseID: leaseID))))
  var replied: (Data?, NSError?) = (nil, nil)
  service.ownerLeaseStatus(request) { replied = ($0, $1) }
  #expect(replied.1 == nil)
  let response = try AuthorityV1Codec.decodeResponse(
    OwnerLeaseStatusResponse.self, from: try #require(replied.0))
  #expect(response.requestID == requestID)
  #expect(response.result.status == .absent)

  // The service answers a caller the core refuses with that refusal.
  let hostPeer = host(uid: 501)
  let hostService = AuthenticatedAuthorityPeerService(
    peerID: UUID(), peer: hostPeer, reauthorize: { _ in hostPeer }, core: subject.core,
    concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
  #expect(
    serviceCode { hostService.ownerLeaseStatus(request, reply: $0) }
      == .globalAuthorityIdentityRejected)
}
