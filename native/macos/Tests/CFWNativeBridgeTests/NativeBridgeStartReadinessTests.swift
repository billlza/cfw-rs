import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Readiness and mutation ownership: readiness deadlines, stale mutation
// completions, external status during an operation, installation receipts, and
// approval waits.
extension NativeBridgeStartCommandIntegrationTests {
  /// The Host's own readiness deadline ends the length it is armed with after
  /// the moment it was armed, on the clock that stops while the Mac sleeps.
  @Test func defaultTunnelReadinessDeadlineEndsAfterItsLength() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))
    let arm = await coordinator.armTunnelReadinessDeadline
    let before = SuspendingClock.now
    let deadline = arm(EngineStartBudget.tunnelReadiness)
    let after = SuspendingClock.now
    #expect(deadline.end >= before.advanced(by: EngineStartBudget.tunnelReadiness))
    #expect(deadline.end <= after.advanced(by: EngineStartBudget.tunnelReadiness))
    #expect(!deadline.hasPassed())
  }

  @Test func readinessDeadlinePassesExactlyAtItsEnd() {
    let start = SuspendingClock.now
    let clock = ManualSuspendingClock(start)
    let deadline = NativeReadinessDeadline.awake(after: .seconds(20)) { clock.now }
    #expect(deadline.end == start.advanced(by: .seconds(20)))
    #expect(!deadline.hasPassed())
    clock.now = start.advanced(by: .seconds(20) - .nanoseconds(1))
    #expect(!deadline.hasPassed())
    clock.now = start.advanced(by: .seconds(20))
    #expect(deadline.hasPassed())
  }

  /// The Host waits for Packet Tunnel readiness for exactly the readiness budget,
  /// which outlasts the provider's own libbox deadline, and then rolls the start
  /// back as a timeout.
  @Test func tunnelReadinessWaitsTheReadinessBudgetThenRollsBack() async throws {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startPendingPreferenceDescriptor: descriptor,
      staysStarting: true)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .preparing,
        lease: agreement(for: descriptor, mode: .tunnel, leaseState: .prepared)),
      cancelPreparedResult: true)
    let deadlines = RecordedReadinessDeadlines(checksBeforePassing: 2)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease,
      armTunnelReadinessDeadline: deadlines.arm)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .timeout)
    #expect(deadlines.lengths == [EngineStartBudget.tunnelReadiness])
    #expect(deadlines.checkCount == 3, "the readiness wait did not end on its own deadline")
    let compensation = await tunnel.compensationCounts()
    #expect(compensation.compensate == 1)
    #expect(compensation.finish == 1)
    #expect(await tunnel.counters().start == 1)
    #expect(try await tunnel.snapshot() == .off)
  }

  @Test func staleMutationCompletionCannotReleaseANewerMutation() async throws {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    let firstMutation = try await coordinator.beginMutation()
    await coordinator.endMutation(firstMutation)
    let secondMutation = try await coordinator.beginMutation()
    await coordinator.endMutation(firstMutation)
    #expect(await coordinator.activeOperation == secondMutation)
    await coordinator.endMutation(secondMutation)
    #expect(await coordinator.activeOperation == nil)
  }

  @Test func installationTimeoutReleasesMutationAndAllowsExactConcurrentRetry()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = BlockingRetryableInstallationTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: ServiceUpgradeFixture())

    // While the exact OS callback wait is unresolved, a reentrant mutation fails
    // Busy instead of starting a parallel System Extension request or projecting
    // a status through an incomplete mutation boundary.
    let first = try await whileNativeFixtureBlocked(
      at: tunnel.installationHandshake,
      operation: { await failureCode(coordinator, .installTunnel(request.context)) },
      body: {
        #expect(await failureCode(coordinator, .queryStatus) == .busy)
        #expect(await failureCode(coordinator, .installTunnel(request.context)) == .busy)
      })
    #expect(first == .timeout)

    let differentContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(
      await failureCode(coordinator, .installTunnel(differentContext)) == .busy)

    guard
      case .tunnelInstall(.ready) = try await coordinator.execute(
        .installTunnel(request.context))
    else {
      Issue.record("exact-generation installation retry did not complete")
      return
    }
    #expect(await tunnel.installCalls == 2)
  }

  @Test func externalStatusRetainsOperationOwnershipAcrossReentrantOwnerQueries()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      blocksSnapshot: true)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: ServiceUpgradeFixture())

    let result = try await whileNativeFixtureBlocked(
      at: proxy.snapshotHandshake,
      operation: { try await coordinator.execute(.queryStatus) },
      body: {
        #expect(await failureCode(coordinator, .installTunnel(request.context)) == .busy)
      })
    guard case .status(.off) = result else {
      Issue.record("external status did not return Off after its snapshot was released")
      return
    }
  }

  @Test func earlySnapshotReleaseDoesNotStrandExternalStatus() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor, blocksSnapshot: true)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: ServiceUpgradeFixture())
    // Force the ordering that polling cannot exclude: release precedes entry.
    await proxy.releaseSnapshot()
    let completion = NativeFixturePromise<NativeBridgeResult>()
    let status = Task {
      do {
        completion.finish(.success(try await coordinator.execute(.queryStatus)))
      } catch {
        completion.finish(.failure(error))
      }
    }
    do {
      let result = try await completion.wait(deadline: .init(timeout: .seconds(2)))
      guard case .status(.off) = result else {
        Issue.record("early snapshot release did not preserve global Off")
        await status.value
        return
      }
    } catch {
      status.cancel()
      await proxy.releaseSnapshot()
      await status.value
      throw error
    }
    await status.value
    #expect(await coordinator.activeOperation == nil)
  }

  @Test(arguments: NativeFixtureReadinessFailure.allCases)
  fileprivate func preSnapshotReadinessFailureCancelsAndDrainsOwnedQuery(
    failure: NativeFixtureReadinessFailure
  ) async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let admission = NativeFixtureHandshake()
    let proxy = StartableProxyAgent(
      descriptor: descriptor, blocksSnapshot: true, snapshotAdmission: admission)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: ServiceUpgradeFixture())
    let scheduledDeadline = NativeFixturePromise<@Sendable () -> Void>()
    let deadline = CallbackDeadlineScheduler { expire in
      scheduledDeadline.finish(.success(expire))
      // This deadline fires only when the test expires it.
      return {}
    }
    let waiting = Task {
      try await whileNativeFixtureBlocked(
        at: proxy.snapshotHandshake, readinessDeadline: deadline,
        operation: { try await coordinator.execute(.queryStatus) },
        body: {
          Issue.record("failed readiness must not execute the reentrant command path")
        })
    }
    do {
      // Force the query to own the operation but not yet install its snapshot
      // continuation. Unlike a scheduler delay this ordering is deterministic.
      try await admission.waitUntilEntered()
      #expect(await coordinator.activeOperation != nil)
      let expire = try await scheduledDeadline.wait()
      switch failure {
      case .deadline:
        expire()
        expire()  // A duplicate terminal callback must not resume twice.
      case .cancellation:
        waiting.cancel()
      }
      switch await waiting.result {
      case .success:
        Issue.record("failed readiness incorrectly completed the external query")
      case .failure(let error):
        if failure == .deadline {
          #expect(error as? NativeFixtureWaitError == .deadlineExceeded)
        } else {
          #expect(error is CancellationError)
        }
      }
      // These deliberately late signals cannot revive the canceled operation.
      admission.release()
      proxy.snapshotHandshake.release()
      expire()
    } catch {
      waiting.cancel()
      admission.cancel()
      proxy.snapshotHandshake.cancel()
      _ = await waiting.result
      throw error
    }
    #expect(await coordinator.activeOperation == nil)
    #expect(await proxy.counters().snapshot == 1)
    #expect(await tunnel.counters().install == 0)
    let retry = try await coordinator.beginMutation()
    await coordinator.endMutation(retry)
  }

  @Test(arguments: NativeFixtureBlockPoint.allCases)
  fileprivate func failedBlockedAssertionDrainsTheExactCoordinatorOperation(
    point: NativeFixtureBlockPoint
  ) async throws {
    let request = try startRequest(
      tunnelOptions: point == .snapshot ? nil : TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: point == .snapshot ? .systemProxy : .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor, blocksSnapshot: point == .snapshot)
    let tunnel: any TunnelHostBridging
    let handshake: NativeFixtureHandshake
    let command: NativeBridgeCommand
    switch point {
    case .snapshot:
      tunnel = StartableTunnelHost(descriptor: descriptor)
      handshake = proxy.snapshotHandshake
      command = .queryStatus
    case .authorization:
      let host = StartableTunnelHost(descriptor: descriptor, blocksAuthorization: true)
      tunnel = host
      handshake = host.authorizationHandshake
      command = .authorizeTunnelConfiguration(request)
    case .installation:
      let host = BlockingRetryableInstallationTunnelHost(descriptor: descriptor)
      tunnel = host
      handshake = host.installationHandshake
      command = .installTunnel(request.context)
    }
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: ServiceUpgradeFixture())
    await #expect(throws: NativeFixtureWaitError.injectedFailure) {
      _ = try await whileNativeFixtureBlocked(
        at: handshake, operation: { try await coordinator.execute(command) },
        body: {
          #expect(await coordinator.activeOperation != nil)
          #expect(await failureCode(coordinator, .installTunnel(request.context)) == .busy)
          // Model a throwing readiness/body assertion, then require real cleanup.
          throw NativeFixtureWaitError.injectedFailure
        })
    }
    #expect(await coordinator.activeOperation == nil)
    handshake.release()
    handshake.cancel()
    let retry = try await coordinator.beginMutation()
    await coordinator.endMutation(retry)
  }

  @Test func terminalTunnelInstallationFailureRetainsAnExactCancelableReceipt()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      installResult: .requiresRestart)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    #expect(await failureCode(coordinator, .installTunnel(request.context)) == .unavailable)
    let wrongContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(
      await failureCode(coordinator, .cancelTunnelInstall(wrongContext))
        == .identityRejected)
    guard
      case .acknowledged = try await coordinator.execute(
        .cancelTunnelInstall(request.context))
    else {
      Issue.record("exact terminal installation receipt was not acknowledged")
      return
    }
    #expect(await tunnel.cancelInstallCount() == 1)
    #expect(
      await failureCode(coordinator, .cancelTunnelInstall(request.context))
        == .identityRejected)
  }

  @Test func approvalWaitAnswersOnlyTheExactPendingInstallationAndHoldsNoMutation()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let wrongContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)

    let answering = StartableTunnelHost(descriptor: descriptor, installResult: .awaitingApproval)
    let answeringCoordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: answering,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))
    #expect(
      try await answeringCoordinator.execute(.awaitTunnelApproval(request.context))
        == .tunnelApproval(.noPendingRequest))
    #expect(
      try await answeringCoordinator.execute(.installTunnel(request.context))
        == .tunnelInstall(.awaitingApproval))
    #expect(
      try await answeringCoordinator.execute(.awaitTunnelApproval(wrongContext))
        == .tunnelApproval(.noPendingRequest))
    #expect(await answering.approvalWaitCalls == 0)
    for (wait, expected) in [
      (SystemExtensionApprovalWait.resolved, NativeTunnelApprovalWait.resolved),
      (.stillAwaiting, .stillAwaiting),
      (.noPendingRequest, .noPendingRequest),
    ] {
      await answering.answerApprovalWaits(with: wait)
      #expect(
        try await answeringCoordinator.execute(.awaitTunnelApproval(request.context))
          == .tunnelApproval(expected))
    }
    #expect(await answering.approvalWaitCalls == 3)

    let blocking = StartableTunnelHost(
      descriptor: descriptor, installResult: .awaitingApproval, blocksApprovalWait: true)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: blocking,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))
    #expect(
      try await coordinator.execute(.installTunnel(request.context))
        == .tunnelInstall(.awaitingApproval))
    let answer = try await whileNativeFixtureBlocked(
      at: blocking.approvalHandshake,
      operation: { try await coordinator.execute(.awaitTunnelApproval(request.context)) },
      body: {
        // The open wait holds no mutation: the stop of that installation runs.
        #expect(await coordinator.activeOperation == nil)
        let stopped = try await coordinator.execute(.cancelTunnelInstall(request.context))
        #expect(stopped == .acknowledged)
      })
    #expect(answer == .tunnelApproval(.resolved))
    #expect(await blocking.cancelInstallCount() == 1)
    #expect(
      try await coordinator.execute(.awaitTunnelApproval(request.context))
        == .tunnelApproval(.noPendingRequest))
    #expect(await blocking.approvalWaitCalls == 1)
  }

  @Test func failedTunnelPreparationCancelsExactlyAndTheRustStopReceiptIsOneUse()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startError: .preferenceSaveFailed(
        NetworkExtensionOperationFailure(
          domain: NEVPNErrorDomain,
          code: NEVPNError.configurationReadWriteFailed.rawValue,
          diagnostic: "injected"
        )
      ))
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .preparing,
        lease: agreement(
          for: descriptor,
          mode: .tunnel,
          leaseState: .prepared)),
      cancelPreparedResult: true)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .unavailable)
    #expect(await lease.cancelPreparedCount() == 1)
    #expect((await tunnel.counters()).stop == 0)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven)
    let wrongContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(await failureCode(coordinator, .stopTunnel(wrongContext)) == .identityRejected)

    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("exact compensated Tunnel stop was not acknowledged")
      return
    }
    try await expectRepeatedStopProvesOffAgain(
      coordinator, .stopTunnel(request.context), lease: lease)
  }
}
