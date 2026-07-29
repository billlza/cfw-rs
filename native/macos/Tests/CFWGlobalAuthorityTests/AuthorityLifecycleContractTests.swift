import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

private enum LifecycleContractJournalFailure: Error {
  case injected
}

private final class LifecycleContractJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private var records: [AuthorityCommittedState] = []
  private var failingAppendNumber: Int?

  init(failingAppendNumber: Int? = nil) {
    self.failingAppendNumber = failingAppendNumber
  }

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      if records.count + 1 == failingAppendNumber {
        throw LifecycleContractJournalFailure.injected
      }
      records.append(state)
      return try AuthorityJournalHead(
        sequence: UInt64(records.count),
        committedLength: UInt64(records.count),
        recordSHA256: lifecycleDigest(Data("record-\(records.count)".utf8)))
    }
  }

  var count: Int { lock.withLock { records.count } }
  var transitions: [AuthorityJournalTransition] {
    lock.withLock { records.map(\.transition) }
  }

  func disableFailure() {
    lock.withLock { failingAppendNumber = nil }
  }
}

private struct LifecycleContractRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data {
    Data(repeating: 0x5a, count: count)
  }
}

private final class LifecycleContractClock: AuthorityMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64

  init(_ value: UInt64 = 1_000) { self.value = value }

  func nowMilliseconds() -> UInt64 { lock.withLock { value } }
  func set(_ value: UInt64) { lock.withLock { self.value = value } }
}

private struct LifecycleActiveStart {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
  let providerPeerID: UUID
}

private func lifecycleDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

private func lifecyclePeer(
  role: AuthorityRole,
  ownerUID: UInt32 = 501,
  auditSessionID: UInt32 = 17
) throws -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: try lifecycleDigest(Data("audit-\(role.rawValue)".utf8)),
    pid: role == .provider ? 900 : 800,
    euid: role == .provider ? 0 : ownerUID,
    auditSessionID: role == .provider ? 0 : auditSessionID,
    role: role,
    consoleUID: ownerUID)
}

private func lifecycleCore(
  clock: LifecycleContractClock = LifecycleContractClock()
) throws -> GlobalAuthorityServiceCore {
  GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(),
    journal: LifecycleContractJournal(),
    randomness: LifecycleContractRandomness(),
    clock: clock)
}

private func tunnelPrepareRequest(
  installationID: AuthorityIdentifier,
  generation: UInt64,
  revision: UInt64
) throws -> (request: PrepareStartRequest, configuration: Data) {
  let configuration = Data("{\"inbounds\":[]}".utf8)
  let configurationDigest = try lifecycleDigest(configuration)
  let identityDigest = try lifecycleDigest(Data("identity-\(generation)".utf8))
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: installationID,
      epoch: 1,
      generation: generation),
    mode: .tunnel,
    configSHA256: configurationDigest,
    identitySHA256: identityDigest,
    ownerUID: 501,
    authorityRevision: revision)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count),
    configSHA256: configurationDigest,
    identitySHA256: identityDigest,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identityDigest),
    credentialSlots: [],
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500))
  return (
    try PrepareStartRequest(
      operation: operation,
      expectedRevision: revision,
      configuration: descriptor),
    configuration
  )
}

private func activateTunnel(
  core: GlobalAuthorityServiceCore,
  installationID: AuthorityIdentifier,
  generation: UInt64
) throws -> LifecycleActiveStart {
  let host = try lifecyclePeer(role: .host)
  let preparedInput = try tunnelPrepareRequest(
    installationID: installationID,
    generation: generation,
    revision: core.currentRevision)
  let prepared = try core.prepare(
    preparedInput.request,
    configuration: preparedInput.configuration,
    secretPayload: nil,
    peer: host)
  let ticket = try #require(prepared.ticket)
  let providerPeerID = UUID()
  let redeemed = try core.redeemTunnelTicket(
    RedeemTunnelTicketRequest(ticket: ticket),
    peer: lifecyclePeer(role: .provider),
    peerID: providerPeerID)
  redeemed.transport.erase()

  _ = try core.attestReady(
    ReadyAttestation(
      operation: prepared.operation,
      leaseID: prepared.leaseID,
      runtimeDigest: prepared.operation.identitySHA256,
      ownerRole: .provider,
      readyFlags: .all,
      packetPumpLimits: PacketPumpLimits(
        maximumQueuedPackets: 32,
        maximumQueuedBytes: 131_072,
        maximumPacketBytes: 1_500,
        maximumReadBatch: 16),
      monotonicTimestamp: 2_000),
    peer: lifecyclePeer(role: .provider),
    peerID: providerPeerID)
  return LifecycleActiveStart(
    operation: prepared.operation,
    leaseID: prepared.leaseID,
    providerPeerID: providerPeerID)
}

private func lifecycleAuthorityError(
  _ body: () throws -> Void
) -> AuthorityErrorCode? {
  do {
    try body()
    return nil
  } catch let error as AuthorityDomainError {
    return error.code
  } catch {
    Issue.record("Unexpected error type: \(error)")
    return nil
  }
}

private func attestLifecycleStopped(
  _ active: LifecycleActiveStart,
  core: GlobalAuthorityServiceCore
) throws {
  _ = try core.attestStopped(
    StoppedAttestation(
      operation: active.operation,
      leaseID: active.leaseID,
      libboxStopped: true,
      transportClosed: true,
      osRestored: true,
      monotonicTimestamp: 3_000),
    peer: lifecyclePeer(role: .provider),
    peerID: active.providerPeerID)
}

@Suite(.serialized)
struct AuthorityLifecycleContractTests {
  @Test func repeatedReadyAttestationReturnsOneDurableAcknowledgement() throws {
    let journal = LifecycleContractJournal()
    let core = GlobalAuthorityServiceCore(
      reducer: try .unEnrolledOff(),
      journal: journal,
      randomness: LifecycleContractRandomness(),
      clock: LifecycleContractClock())
    let active = try activateTunnel(
      core: core,
      installationID: AuthorityIdentifier(UUID()),
      generation: 1)
    let journalCount = journal.count
    let revision = core.currentRevision
    let acknowledgement = try core.attestReady(
      ReadyAttestation(
        operation: active.operation,
        leaseID: active.leaseID,
        runtimeDigest: active.operation.identitySHA256,
        ownerRole: .provider,
        readyFlags: .all,
        packetPumpLimits: PacketPumpLimits(
          maximumQueuedPackets: 32,
          maximumQueuedBytes: 131_072,
          maximumPacketBytes: 1_500,
          maximumReadBatch: 16),
        monotonicTimestamp: 2_000),
      peer: lifecyclePeer(role: .provider),
      peerID: active.providerPeerID)

    #expect(acknowledgement.operationID == active.operation.operationID)
    #expect(acknowledgement.revision == revision)
    #expect(core.authorityState == .active)
    #expect(journal.count == journalCount)
    #expect(journal.transitions.last == .ready)

    #expect(
      lifecycleAuthorityError {
        _ = try core.attestReady(
          ReadyAttestation(
            operation: active.operation,
            leaseID: active.leaseID,
            runtimeDigest: active.operation.identitySHA256,
            ownerRole: .provider,
            readyFlags: .all,
            packetPumpLimits: PacketPumpLimits(
              maximumQueuedPackets: 32,
              maximumQueuedBytes: 131_072,
              maximumPacketBytes: 1_500,
              maximumReadBatch: 16),
            monotonicTimestamp: 2_001),
          peer: lifecyclePeer(role: .provider),
          peerID: active.providerPeerID)
      } == .staleOperation)
    #expect(journal.count == journalCount)
  }

  @Test func repeatedBeginStopIsOneDurableClaimWithStableDeadline() throws {
    let journal = LifecycleContractJournal()
    let clock = LifecycleContractClock()
    let core = GlobalAuthorityServiceCore(
      reducer: try .unEnrolledOff(),
      journal: journal,
      randomness: LifecycleContractRandomness(),
      clock: clock)
    let active = try activateTunnel(
      core: core,
      installationID: AuthorityIdentifier(UUID()),
      generation: 1)
    let host = try lifecyclePeer(role: .host)
    let request = try BeginStopRequest(
      operation: active.operation,
      leaseID: active.leaseID,
      expectedRevision: core.currentRevision)
    let first = try core.beginStop(request, peer: host)
    let firstJournalCount = journal.count

    clock.set(4_000)
    let retry = try core.beginStop(request, peer: host)

    #expect(retry.revision == first.revision)
    #expect(retry.deadlineMonotonic == first.deadlineMonotonic)
    #expect(journal.count == firstJournalCount)
    #expect(journal.transitions.last == .beginStop)
  }

  @Test func cancelOffPersistFailureRetainsDurableStoppingHighWaterForRetry() throws {
    // Enrollment, prepare, and abort succeed. The fourth append (exact Off)
    // fails after the abort is durable.
    let journal = LifecycleContractJournal(failingAppendNumber: 4)
    let core = GlobalAuthorityServiceCore(
      reducer: try .unEnrolledOff(),
      journal: journal,
      randomness: LifecycleContractRandomness(),
      clock: LifecycleContractClock())
    let host = try lifecyclePeer(role: .host)
    let preparedInput = try tunnelPrepareRequest(
      installationID: AuthorityIdentifier(UUID()),
      generation: 1,
      revision: core.currentRevision)
    let prepared = try core.prepare(
      preparedInput.request,
      configuration: preparedInput.configuration,
      secretPayload: nil,
      peer: host)
    defer { prepared.erase() }

    #expect(
      lifecycleAuthorityError {
        _ = try core.cancelPrepared(
          CancelPreparedRequest(
            operation: prepared.operation,
            expectedRevision: core.currentRevision),
          peer: host)
      } == .journalCorrupt)
    #expect(core.authorityState == .stopping)
    #expect(core.currentRevision == 3)
    #expect(core.ownerHasAttestedStopped)
    #expect(journal.count == 3)
    #expect(journal.transitions == [.enrollOff, .prepare, .abortPrepared])

    journal.disableFailure()
    let completion = try core.completeStop(
      CompleteStopRequest(
        operation: prepared.operation,
        leaseID: prepared.leaseID,
        expectedRevision: core.currentRevision),
      peer: host)
    #expect(completion.operationID == prepared.operation.operationID)
    #expect(completion.revision == 4)
    #expect(core.authorityState == .off)
    #expect(journal.transitions == [.enrollOff, .prepare, .abortPrepared, .globalOff])
  }

  @Test func startingOwnerStoppedAttestationPersistsOnceAcrossExactRetry() throws {
    let journal = LifecycleContractJournal()
    let core = GlobalAuthorityServiceCore(
      reducer: try .unEnrolledOff(),
      journal: journal,
      randomness: LifecycleContractRandomness(),
      clock: LifecycleContractClock())
    let installationID = AuthorityIdentifier(UUID())
    let host = try lifecyclePeer(role: .host)
    let preparedInput = try tunnelPrepareRequest(
      installationID: installationID,
      generation: 1,
      revision: core.currentRevision)
    let prepared = try core.prepare(
      preparedInput.request,
      configuration: preparedInput.configuration,
      secretPayload: nil,
      peer: host)
    let ticket = try #require(prepared.ticket)
    let providerPeerID = UUID()
    let provider = try lifecyclePeer(role: .provider)
    let redeemed = try core.redeemTunnelTicket(
      RedeemTunnelTicketRequest(ticket: ticket),
      peer: provider,
      peerID: providerPeerID)
    redeemed.transport.erase()
    #expect(core.authorityState == .starting)
    #expect(journal.count == 3)

    let stopped = try StoppedAttestation(
      operation: prepared.operation,
      leaseID: prepared.leaseID,
      libboxStopped: true,
      transportClosed: true,
      osRestored: true,
      monotonicTimestamp: 3_000)
    let first = try core.attestStopped(
      stopped, peer: provider, peerID: providerPeerID)
    #expect(core.authorityState == .stopping)
    #expect(core.ownerHasAttestedStopped)
    #expect(journal.count == 4)

    let retry = try core.attestStopped(
      stopped, peer: provider, peerID: providerPeerID)
    #expect(retry.revision == first.revision)
    #expect(core.currentRevision == first.revision)
    #expect(journal.count == 4)
  }

  @Test func hostCompleteStopRequiresExactStoppedOwnerProofThenAllowsSecondStart() throws {
    let core = try lifecycleCore()
    let installationID = AuthorityIdentifier(UUID())
    let host = try lifecyclePeer(role: .host)
    let first = try activateTunnel(
      core: core,
      installationID: installationID,
      generation: 1)
    #expect(core.authorityState == .active)

    _ = try core.beginStop(
      BeginStopRequest(
        operation: first.operation,
        leaseID: first.leaseID,
        expectedRevision: core.currentRevision),
      peer: host)
    #expect(core.authorityState == .stopping)

    #expect(
      lifecycleAuthorityError {
        _ = try core.completeStop(
          CompleteStopRequest(
            operation: first.operation,
            leaseID: first.leaseID,
            expectedRevision: core.currentRevision),
          peer: host)
      } == .cleanupUnproven)
    #expect(core.authorityState == .stopping)

    try attestLifecycleStopped(first, core: core)
    let exactRevision = core.currentRevision

    let wrongOperation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: first.operation.root,
      mode: first.operation.mode,
      configSHA256: first.operation.configSHA256,
      identitySHA256: first.operation.identitySHA256,
      ownerUID: first.operation.ownerUID,
      authorityRevision: first.operation.authorityRevision)
    #expect(
      lifecycleAuthorityError {
        _ = try core.completeStop(
          CompleteStopRequest(
            operation: wrongOperation,
            leaseID: first.leaseID,
            expectedRevision: exactRevision),
          peer: host)
      } == .cleanupUnproven)
    #expect(
      lifecycleAuthorityError {
        _ = try core.completeStop(
          CompleteStopRequest(
            operation: first.operation,
            leaseID: AuthorityIdentifier(UUID()),
            expectedRevision: exactRevision),
          peer: host)
      } == .cleanupUnproven)
    #expect(
      lifecycleAuthorityError {
        _ = try core.completeStop(
          CompleteStopRequest(
            operation: first.operation,
            leaseID: first.leaseID,
            expectedRevision: exactRevision - 1),
          peer: host)
      } == .staleOperation)
    #expect(core.authorityState == .stopping)

    let acknowledgement = try core.completeStop(
      CompleteStopRequest(
        operation: first.operation,
        leaseID: first.leaseID,
        expectedRevision: exactRevision),
      peer: host)
    #expect(acknowledgement.revision == exactRevision + 1)
    #expect(core.authorityState == .off)
    #expect(core.leaseOwnerUID == nil)

    let second = try activateTunnel(
      core: core,
      installationID: installationID,
      generation: 2)
    #expect(core.authorityState == .active)
    #expect(second.operation.operationID != first.operation.operationID)
    #expect(second.leaseID != first.leaseID)
  }

  @Test func unboundPreparationSessionLossReturnsDirectlyToExactOff() throws {
    let installationID = AuthorityIdentifier(UUID())

    let fastUserSwitchCore = try lifecycleCore()
    let fastUserSwitchRequest = try tunnelPrepareRequest(
      installationID: installationID,
      generation: 1,
      revision: fastUserSwitchCore.currentRevision)
    let fastUserSwitchPrepared = try fastUserSwitchCore.prepare(
      fastUserSwitchRequest.request,
      configuration: fastUserSwitchRequest.configuration,
      secretPayload: nil,
      peer: lifecyclePeer(role: .host))
    _ = try fastUserSwitchCore.observeLiveConsoleUser(502)
    fastUserSwitchPrepared.erase()
    #expect(fastUserSwitchCore.authorityState == .off)
    #expect(fastUserSwitchCore.leaseOwnerUID == nil)

    let logoutCore = try lifecycleCore()
    let logoutRequest = try tunnelPrepareRequest(
      installationID: AuthorityIdentifier(UUID()),
      generation: 1,
      revision: logoutCore.currentRevision)
    let logoutPrepared = try logoutCore.prepare(
      logoutRequest.request,
      configuration: logoutRequest.configuration,
      secretPayload: nil,
      peer: lifecyclePeer(role: .host))
    let logoutSupervisor = AuthorityLivenessSupervisor(core: logoutCore)
    #expect(try logoutSupervisor.forceStop(.logout) == .forcedStop(.logout))
    logoutPrepared.erase()
    #expect(logoutCore.authorityState == .off)
    #expect(logoutCore.leaseOwnerUID == nil)

    let sessionChangeCore = try lifecycleCore()
    let sessionChangeRequest = try tunnelPrepareRequest(
      installationID: AuthorityIdentifier(UUID()),
      generation: 1,
      revision: sessionChangeCore.currentRevision)
    let sessionChangePrepared = try sessionChangeCore.prepare(
      sessionChangeRequest.request,
      configuration: sessionChangeRequest.configuration,
      secretPayload: nil,
      peer: lifecyclePeer(role: .host))
    let sessionChangeSupervisor = AuthorityLivenessSupervisor(core: sessionChangeCore)
    #expect(
      try sessionChangeSupervisor.observeConsoleSessionChange()
        == .forcedStop(.consoleUserChange))
    sessionChangePrepared.erase()
    #expect(sessionChangeCore.authorityState == .off)
    #expect(sessionChangeCore.leaseOwnerUID == nil)

    let lateClock = LifecycleContractClock(50_000)
    let lateSupervisor = AuthorityLivenessSupervisor(
      core: sessionChangeCore,
      clock: lateClock)
    #expect(try lateSupervisor.evaluate() == .none)
    #expect(sessionChangeCore.authorityState != .stopping)
    #expect(sessionChangeCore.authorityState != .quarantined)
  }
}
