import Foundation
import Testing

@testable import CFWNativeBridge
@testable import CFWSharedProtocol

private actor SequencedAuthorityClient: AuthorityClient {
  private var snapshots: [AuthoritySnapshot]
  private let stopDirective: StopDirective?
  private let reconcileReceipt: ReconcileOffReceipt?
  private let cancelError: AuthorityDomainError?
  private(set) var cancelRequests: [(OperationContext, UInt64)] = []
  private(set) var beginRequests: [BeginStopRequest] = []
  private(set) var completeRequests: [CompleteStopRequest] = []
  private(set) var reconcileRequests: [ReconcileOffRequest] = []

  init(
    snapshots: [AuthoritySnapshot],
    stopDirective: StopDirective? = nil,
    reconcileReceipt: ReconcileOffReceipt? = nil,
    cancelError: AuthorityDomainError? = nil
  ) {
    self.snapshots = snapshots
    self.stopDirective = stopDirective
    self.reconcileReceipt = reconcileReceipt
    self.cancelError = cancelError
  }

  func prepare(
    _ request: PrepareStartRequest,
    configuration: SensitiveBytes,
    secrets: SensitiveBytes?
  ) throws -> PreparedStart {
    throw AuthorityDomainError(code: .invalidMessage)
  }

  func cancelPrepared(_ context: OperationContext, revision: UInt64) throws {
    cancelRequests.append((context, revision))
    if let cancelError { throw cancelError }
  }

  func beginStop(_ request: BeginStopRequest) throws -> StopDirective {
    beginRequests.append(request)
    guard let stopDirective else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    return stopDirective
  }

  func completeStop(_ request: CompleteStopRequest) {
    completeRequests.append(request)
  }

  func reconcileOff(_ request: ReconcileOffRequest) throws -> ReconcileOffReceipt {
    reconcileRequests.append(request)
    guard let reconcileReceipt else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    return reconcileReceipt
  }

  func snapshot() throws -> AuthoritySnapshot {
    guard !snapshots.isEmpty else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    if snapshots.count == 1 {
      return snapshots[0]
    }
    return snapshots.removeFirst()
  }

  func counts() -> (cancel: Int, begin: Int, complete: Int, reconcile: Int) {
    (
      cancelRequests.count, beginRequests.count,
      completeRequests.count, reconcileRequests.count
    )
  }

  func lastReconcileRequest() -> ReconcileOffRequest? {
    reconcileRequests.last
  }
}

private struct AuthorityLeaseFixture {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
  let cursor: ReplayCursor
  let descriptor: ConfigurationDescriptor

  init() throws {
    let installationID = try #require(
      UUID(uuidString: "11111111-1111-4111-8111-111111111111"))
    let config = try SHA256Digest(hex: String(repeating: "11", count: 32))
    let identity = try SHA256Digest(hex: String(repeating: "22", count: 32))
    operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: AuthorityIdentifier(installationID),
        epoch: 2,
        generation: 7),
      mode: .systemProxy,
      configSHA256: config,
      identitySHA256: identity,
      ownerUID: 501,
      authorityRevision: 10)
    leaseID = AuthorityIdentifier(UUID())
    cursor = try ReplayCursor(
      installationID: AuthorityIdentifier(installationID),
      acceptedEpoch: 2,
      acceptedGeneration: 7,
      revision: 14,
      previousRecordSHA256: SHA256Digest(hex: String(repeating: "33", count: 32)))
    descriptor = try ConfigurationDescriptor(
      slot: .systemProxy,
      tunnelOptions: nil,
      credentialAudience: CredentialAudience(
        profileID: installationID,
        profileDigest: SHA256Digest(hex: String(repeating: "ab", count: 32))),
      installationID: installationID,
      epoch: 2,
      generation: 7,
      byteCount: 2,
      sha256: config,
      identitySHA256: identity)
  }

  func snapshot(
    state: AuthorityState,
    revision: UInt64,
    leaseState: AuthorityLeaseState? = nil,
    cursor: ReplayCursor? = nil
  ) throws -> AuthoritySnapshot {
    let lease = try leaseState.map {
      try LeaseView(
        leaseID: leaseID,
        operation: operation,
        state: $0,
        expiryMonotonic: 20_000)
    }
    return try AuthoritySnapshot(
      protocolVersion: AuthorityProtocolVersion(),
      state: state,
      revision: revision,
      replayCursor: cursor,
      leaseView: lease,
      lastFailure: nil,
      consoleUID: 501)
  }

  func cursor(revision: UInt64) throws -> ReplayCursor {
    try ReplayCursor(
      installationID: operation.root.installationID,
      acceptedEpoch: operation.root.epoch,
      acceptedGeneration: operation.root.generation,
      revision: revision,
      previousRecordSHA256: cursor.previousRecordSHA256)
  }
}

@Suite(.serialized)
struct GlobalAuthorityEngineLeaseInspectorTests {
  @Test func exactPreparedCancellationCommitsOffBeforeReportingCleanup() async throws {
    let fixture = try AuthorityLeaseFixture()
    let preparing = try fixture.snapshot(
      state: .preparing,
      revision: 11,
      leaseState: .prepared,
      cursor: try fixture.cursor(revision: 11))
    let off = try fixture.snapshot(
      state: .off,
      revision: 13,
      cursor: try fixture.cursor(revision: 13))
    let authority = SequencedAuthorityClient(snapshots: [preparing, off])
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    #expect(try await inspector.cancelPreparedStart(for: fixture.descriptor))
    #expect(await authority.counts().cancel == 1)
    let request = try #require(await authority.cancelRequests.last)
    #expect(request.0 == fixture.operation)
    #expect(request.1 == 11)
  }

  @Test func lostCancellationReplyIsSuccessOnlyAfterFreshExactOffProof() async throws {
    let fixture = try AuthorityLeaseFixture()
    let preparing = try fixture.snapshot(
      state: .preparing,
      revision: 11,
      leaseState: .prepared,
      cursor: try fixture.cursor(revision: 11))
    let off = try fixture.snapshot(
      state: .off,
      revision: 13,
      cursor: try fixture.cursor(revision: 13))
    let authority = SequencedAuthorityClient(
      snapshots: [preparing, off],
      cancelError: AuthorityDomainError(code: .globalAuthorityInterrupted))
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    #expect(try await inspector.cancelPreparedStart(for: fixture.descriptor))
    #expect(await authority.counts().cancel == 1)
  }

  @Test func redeemWinningCancellationRaceRequiresTheExactStopPath() async throws {
    let fixture = try AuthorityLeaseFixture()
    let preparing = try fixture.snapshot(
      state: .preparing,
      revision: 11,
      leaseState: .prepared,
      cursor: try fixture.cursor(revision: 11))
    let starting = try fixture.snapshot(
      state: .starting,
      revision: 12,
      leaseState: .starting,
      cursor: try fixture.cursor(revision: 12))
    let authority = SequencedAuthorityClient(
      snapshots: [preparing, starting],
      cancelError: AuthorityDomainError(code: .staleOperation))
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    #expect(try await !inspector.cancelPreparedStart(for: fixture.descriptor))
    #expect(await authority.counts().cancel == 1)
  }

  @Test func cancellationRejectsAnOffCursorNewerThanTheFailedStart() async throws {
    let fixture = try AuthorityLeaseFixture()
    let newerCursor = try ReplayCursor(
      installationID: fixture.cursor.installationID,
      acceptedEpoch: fixture.descriptor.epoch,
      acceptedGeneration: fixture.descriptor.generation + 1,
      revision: fixture.cursor.revision + 1,
      previousRecordSHA256: fixture.cursor.previousRecordSHA256)
    let newerOff = try fixture.snapshot(
      state: .off,
      revision: newerCursor.revision,
      cursor: newerCursor)
    let authority = SequencedAuthorityClient(snapshots: [newerOff])
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    await #expect(throws: AuthorityDomainError(code: .replayRejected)) {
      try await inspector.cancelPreparedStart(for: fixture.descriptor)
    }
    #expect(await authority.counts().cancel == 0)
  }

  @Test func recoversExactStoppingLeaseContextWithoutProjectingOwnerProof()
    async throws
  {
    let fixture = try AuthorityLeaseFixture()
    let snapshot = try fixture.snapshot(
      state: .stopping,
      revision: 14,
      leaseState: .stopping,
      cursor: fixture.cursor)
    let authority = SequencedAuthorityClient(snapshots: [snapshot])
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    let recovered = try #require(try await inspector.recoverStoppingLease())
    #expect(recovered.owner == .systemProxy)
    #expect(recovered.commandContext.installationID == fixture.descriptor.installationID)
    #expect(recovered.commandContext.configEpoch == fixture.descriptor.epoch)
    #expect(recovered.commandContext.generation == fixture.descriptor.generation)
    #expect(recovered.authorityContext.operation == fixture.operation)
    #expect(recovered.authorityContext.leaseID == fixture.leaseID)
    #expect(await authority.counts().complete == 0)
  }

  @Test func repeatedBeginStopAcceptsTheExistingStoppingRevision() async throws {
    let fixture = try AuthorityLeaseFixture()
    let snapshot = try fixture.snapshot(
      state: .stopping,
      revision: 14,
      leaseState: .stopping,
      cursor: fixture.cursor)
    let directive = try StopDirective(
      operation: fixture.operation,
      leaseID: fixture.leaseID,
      deadlineMonotonic: 30_000,
      revision: 14)
    let authority = SequencedAuthorityClient(
      snapshots: [snapshot],
      stopDirective: directive)
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    let context = try await inspector.beginStop(for: fixture.descriptor)
    #expect(context.operation == fixture.operation)
    #expect(context.leaseID == fixture.leaseID)
    #expect(await authority.counts().begin == 1)
  }

  @Test func freshBeginStopRejectsAnUnadvancedAcknowledgement() async throws {
    let fixture = try AuthorityLeaseFixture()
    let snapshot = try fixture.snapshot(
      state: .active,
      revision: 14,
      leaseState: .active,
      cursor: fixture.cursor)
    let directive = try StopDirective(
      operation: fixture.operation,
      leaseID: fixture.leaseID,
      deadlineMonotonic: 30_000,
      revision: 14)
    let authority = SequencedAuthorityClient(
      snapshots: [snapshot],
      stopDirective: directive)
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      _ = try await inspector.beginStop(for: fixture.descriptor)
    }
    #expect(await authority.counts().begin == 1)
  }

  @Test func lostCompleteReplyIsIdempotentOnlyForTheExactOffReplayGeneration()
    async throws
  {
    let fixture = try AuthorityLeaseFixture()
    let off = try fixture.snapshot(
      state: .off,
      revision: 15,
      cursor: fixture.cursor)
    let authority = SequencedAuthorityClient(snapshots: [off])
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    try await inspector.completeStop(
      NativeAuthorityStopContext(
        operation: fixture.operation,
        leaseID: fixture.leaseID))
    #expect(await authority.counts().complete == 0)
  }

  @Test func restartReconciliationBindsExactCursorAndOwnerOffEvidence() async throws {
    let fixture = try AuthorityLeaseFixture()
    let recovering = try fixture.snapshot(
      state: .recovering,
      revision: 14,
      cursor: fixture.cursor)
    let reconciled = try fixture.snapshot(
      state: .off,
      revision: 15,
      cursor: fixture.cursor)
    let receipt = try ReconcileOffReceipt(
      revision: 15,
      replayCursor: fixture.cursor)
    let authority = SequencedAuthorityClient(
      snapshots: [recovering, reconciled],
      reconcileReceipt: receipt)
    let inspector = GlobalAuthorityEngineLeaseInspector(authority: authority)

    let observation = try await inspector.reconcileOff(managedTunnel: .disconnected)
    #expect(observation == AuthorityOwnershipObservation(state: .off, lease: nil))
    let request = try #require(await authority.lastReconcileRequest())
    #expect(request.expectedRevision == 14)
    #expect(request.replayCursor == fixture.cursor)
    #expect(request.proxy.ownershipCleared)
    #expect(request.proxy.listenerClosed)
    #expect(request.proxy.effectiveSystemConfigurationRestored)
    #expect(request.provider.ownershipCleared)
    #expect(request.provider.libboxStopped)
    #expect(request.provider.packetPumpClosed)
    #expect(request.managedTunnel == .disconnected)
  }
}
