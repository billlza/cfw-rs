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

// Failed starts: the Off transaction that survives every proof failure,
// timeouts reported only after the exact owner stop, unclosable engines, and
// rollbacks.
extension NativeBridgeStartCommandIntegrationTests {
  @Test func failedStartOffTransactionSurvivesEveryProofBoundaryFailure() async throws {
    for fault in FailedStartRetryFault.allCases {
      let request = try startRequest(tunnelOptions: nil)
      let descriptor = try request.descriptor(slot: .systemProxy)
      let proxy = FailedStartProxyAgent(descriptor: descriptor, fault: fault)
      let lease = RecordingEngineLease(
        observation: AuthorityOwnershipObservation(state: .off, lease: nil),
        ownershipFailures: fault == .globalOffObservation ? 1 : 0)
      let coordinator = makeCoordinator(
        proxy: proxy,
        tunnel: StartableTunnelHost(descriptor: descriptor),
        observation: AuthorityOwnershipObservation(state: .off, lease: nil),
        systemProxyPreparer: RecordingSystemProxyStartPreparer(),
        engineLease: lease)

      #expect(
        await failureCode(coordinator, .startSystemProxy(request)) == .cleanupUnproven,
        "fault \(fault) must retain the exact failed-start transaction")
      #expect(
        await failureCode(coordinator, .startSystemProxy(request)) == .cleanupUnproven,
        "a retained cleanup transaction must block a newer start")

      let wrongContext = try EngineCommandContext(
        installationID: request.context.installationID,
        configEpoch: request.context.configEpoch,
        generation: request.context.generation + 1)
      #expect(
        await failureCode(coordinator, .stopSystemProxy(wrongContext)) == .identityRejected)
      guard
        case .acknowledged =
          try await coordinator.execute(.stopSystemProxy(request.context))
      else {
        Issue.record("exact failed-start cleanup retry was not acknowledged for \(fault)")
        continue
      }
      let counts = await proxy.counters()
      #expect(counts.start == 1)
      #expect(counts.stop == (fault == .ownerStop ? 2 : 1))
      try await expectRepeatedStopProvesOffAgain(
        coordinator, .stopSystemProxy(request.context), lease: lease)
    }
  }

  @Test func failedTunnelStartOffTransactionSurvivesEveryProofBoundaryFailure() async throws {
    let endpointFailure = EngineFailure(
      code: "controller-endpoint-in-use",
      message: "The controller endpoint is already in use.",
      isRetryable: false)
    // Once the Host compensates the failed start's preferences, HostBridge no
    // longer reports that provider, so the Host never stops it and an owner
    // stop cannot fail here; the System Proxy variant covers that fault.
    for fault in FailedStartRetryFault.allCases where fault != .ownerStop {
      let request = try startRequest(
        tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
      let descriptor = try request.descriptor(slot: .tunnel)
      let tunnel = StartableTunnelHost(
        descriptor: descriptor,
        startError: .providerFailure(endpointFailure),
        startPendingPreferenceDescriptor: descriptor,
        failedStartSnapshot: endpointFailure,
        snapshotFailures: fault == .ownerObservation ? 1 : 0)
      let lease = RecordingEngineLease(
        observation: AuthorityOwnershipObservation(
          state: .preparing,
          lease: agreement(
            for: descriptor,
            mode: .tunnel,
            leaseState: .prepared)),
        ownershipFailures: fault == .globalOffObservation ? 1 : 0,
        cancelPreparedResult: true)
      let coordinator = makeCoordinator(
        proxy: StartableProxyAgent(descriptor: descriptor),
        tunnel: tunnel,
        observation: AuthorityOwnershipObservation(state: .off, lease: nil),
        engineLease: lease)

      #expect(
        await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven,
        "fault \(fault) must retain the exact Tunnel failed-start transaction")
      #expect(
        await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven,
        "a retained Tunnel cleanup transaction must block a newer start")
      guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
        Issue.record("exact Tunnel cleanup retry was not acknowledged for \(fault)")
        continue
      }
      let counts = await tunnel.counters()
      #expect(counts.start == 1)
      #expect(counts.stop == 0)
      let cancelPreparedCount = await lease.cancelPreparedCount()
      #expect(cancelPreparedCount == 2)
      try await expectRepeatedStopProvesOffAgain(
        coordinator, .stopTunnel(request.context), lease: lease)
    }
  }

  @Test func asynchronousTicketExpiryIsReportedOnlyAfterExactCleanupAndOff() async throws {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startPendingPreferenceDescriptor: descriptor,
      failedStartSnapshot: TunnelStartupFailure.ticketExpired,
      reportsAsynchronousStartFailure: true)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .preparing,
        lease: agreement(for: descriptor, mode: .tunnel, leaseState: .prepared)),
      cancelPreparedResult: true)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .ticketExpired)
    let counts = await tunnel.counters()
    #expect(counts.start == 1)
    // The provider stopped itself. Compensation found it disconnected and
    // restored the preferences, and HostBridge forgot the started
    // configuration, so the snapshot is Off and the Host sends no stop.
    #expect(counts.stop == 0)
    let compensation = await tunnel.compensationCounts()
    #expect(compensation.compensate == 1)
    #expect(compensation.finish == 1)
    #expect(try await tunnel.snapshot() == .off)
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("exact failed-start cleanup receipt was not acknowledged")
      return
    }
    try await expectRepeatedStopProvesOffAgain(
      coordinator, .stopTunnel(request.context), lease: lease)
  }

  /// A provider whose libbox start timed out had redeemed its ticket, so the
  /// Authority will not cancel the start as a preparation. The Host reports the
  /// timeout only after stopping that exact owner at the Authority and proving
  /// Off.
  @Test func asynchronousEngineStartTimeoutIsReportedOnlyAfterExactOwnerStopAndOff()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startPendingPreferenceDescriptor: descriptor,
      failedStartSnapshot: TunnelStartupFailure.engineStartTimedOut,
      reportsAsynchronousStartFailure: true)
    // The provider attests Stopped before it reports the timeout, so the
    // Authority is already stopping that exact owner.
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(for: descriptor, mode: .tunnel, leaseState: .stopping)))
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .engineStartTimedOut)
    #expect(await lease.cancelPreparedCount() == 1)
    // The preference compensation begins the same stop again to confirm that
    // its identity did not change, and the stop completes once.
    let authority = await lease.counters()
    #expect(authority.begin == 2)
    #expect(authority.complete == 1)
    #expect(await lease.currentState() == .off)
    let compensation = await tunnel.compensationCounts()
    #expect(compensation.compensate == 1)
    #expect(compensation.finish == 1)
    let counts = await tunnel.counters()
    #expect(counts.start == 1)
    // The provider stopped itself. Compensation found it disconnected and
    // restored the preferences, and HostBridge forgot the started
    // configuration, so the snapshot is Off and the Host sends no stop.
    #expect(counts.stop == 0)
    #expect(try await tunnel.snapshot() == .off)
    #expect(
      await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven,
      "the failed-start cleanup receipt blocks a new start until a stop acknowledges it")
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("exact failed-start cleanup receipt was not acknowledged")
      return
    }
  }

  /// A provider whose libbox runtime could not be closed reports that with the
  /// start's lineage before it ends its process, so the Host stops waiting at
  /// once instead of after the readiness window. The provider never attested
  /// Stopped, so the Authority refuses to complete the rollback: the start
  /// reports cleanup it cannot prove whatever its own failure was, and later
  /// starts stay refused.
  @Test func unclosableTunnelEngineEndsTheReadinessWaitWithUnprovenCleanup() async throws {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startPendingPreferenceDescriptor: descriptor,
      failedStartSnapshot: TunnelStartupFailure.engineUnclosable,
      reportsAsynchronousStartFailure: true)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(for: descriptor, mode: .tunnel, leaseState: .stopping)),
      completeError: AuthorityDomainError(code: .cleanupUnproven))
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    let started = ContinuousClock.now
    #expect(await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven)
    #expect(started.duration(to: .now) < EngineStartBudget.tunnelReadiness)
    #expect(await lease.counters().complete == 1)
    #expect(await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven)
    #expect(await tunnel.counters().start == 1)
  }

  /// The failed start's preferences were not restored before the Authority
  /// recovered. Restoring them later needs no Authority order, whether the
  /// stop had been ordered or not: the Authority holds no lease and admits no
  /// start until the Host proves Off.
  @Test(arguments: [false, true])
  func tunnelCleanupRestoresPreferencesOnceTheAuthorityRecovered(stopOrdered: Bool)
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startPendingPreferenceDescriptor: descriptor,
      failedStartSnapshot: TunnelStartupFailure.engineUnclosable,
      reportsAsynchronousStartFailure: true,
      compensationFailures: stopOrdered ? 1 : 0)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(for: descriptor, mode: .tunnel, leaseState: .stopping)),
      beginFailures: stopOrdered ? 0 : 1)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)
    #expect(await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven)
    #expect(await tunnel.compensationCounts().compensate == 0)

    await lease.recoverFromEndedOwner(of: request.context)
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("the failed start's preferences were not restored once the Authority recovered")
      return
    }
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await lease.reconcileCount() == 1)
    #expect(await lease.counters().complete == (stopOrdered ? 1 : 0))
  }

  /// The provider that could not close its runtime ends its process, and the
  /// Authority recovers once it provably ended. The failed start's cleanup then
  /// finishes with the Host's Off proof, and a new start is admitted.
  @Test func unclosableTunnelCleanupFinishesOnceTheAuthorityRecovered() async throws {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startPendingPreferenceDescriptor: descriptor,
      failedStartSnapshot: TunnelStartupFailure.engineUnclosable,
      reportsAsynchronousStartFailure: true)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(for: descriptor, mode: .tunnel, leaseState: .stopping)),
      completeError: AuthorityDomainError(code: .cleanupUnproven))
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)
    #expect(await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven)

    await lease.recoverFromEndedOwner(of: request.context)
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("the failed start's cleanup did not finish once the Authority recovered")
      return
    }
    #expect(await lease.reconcileCount() == 1)
    #expect(await tunnel.compensationCounts().finish == 1)
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("the recovered tunnel cleanup did not leave proven Off")
      return
    }
  }

  /// The ProxyAgent replies to a timed-out libbox start only after it stopped
  /// and attested Stopped, so the Authority is stopping and refuses to cancel
  /// the start as a preparation. The Host then stops that exact owner at the
  /// Authority and proves Off before it reports the timeout as its own cause.
  @Test func proxyAgentStartTimeoutIsReportedOnlyAfterExactOwnerStopAndOff() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = FailedStartProxyAgent(
      descriptor: descriptor, fault: nil,
      failure: EngineFailure(
        .agent(.engineStartTimedOut),
        message: "System Proxy runtime startup did not finish in time and was interrupted."))
    let preparer = RecordingSystemProxyStartPreparer(
      cancelError: AuthorityDomainError(code: .compensationConflict))
    // The Authority is already stopping that exact owner when the Host reads
    // the reply, which is why it refuses to cancel the start.
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(
          for: descriptor, mode: descriptor.slot.authorityMode, leaseState: .stopping)))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      systemProxyPreparer: preparer,
      engineLease: lease)

    #expect(await failureCode(coordinator, .startSystemProxy(request)) == .engineStartTimedOut)
    #expect(await preparer.cancelCalls == 1)
    let authority = await lease.counters()
    #expect(authority.begin == 1)
    #expect(authority.complete == 1)
    #expect(await lease.currentState() == .off)
    let counts = await proxy.counters()
    #expect(counts.start == 1)
    #expect(counts.stop == 1)
    #expect(try await proxy.snapshot() == .off)
    #expect(
      await failureCode(coordinator, .startSystemProxy(request)) == .cleanupUnproven,
      "the failed-start cleanup receipt blocks a new start until a stop acknowledges it")
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("exact failed-start cleanup receipt was not acknowledged")
      return
    }
  }

  /// A rollback whose Authority stop could not be ordered still asks the
  /// ProxyAgent to stop. A reply that it has no record of the stop proves
  /// nothing yet, since the lease could still be bound, so the retry asks the
  /// ProxyAgent again once the Authority stops the lease.
  @Test func staleReplyBeforeAuthorityOrderingLeavesTheOwnerToBeAskedAgain() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = FailedStartProxyAgent(
      descriptor: descriptor, fault: nil,
      failure: EngineFailure(
        .agent(.engineStartTimedOut),
        message: "System Proxy runtime startup did not finish in time and was interrupted."),
      sessionlessStops: 1)
    let preparer = RecordingSystemProxyStartPreparer(
      cancelError: AuthorityDomainError(code: .compensationConflict))
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(
          for: descriptor, mode: descriptor.slot.authorityMode, leaseState: .stopping)),
      beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      systemProxyPreparer: preparer,
      engineLease: lease)

    #expect(await failureCode(coordinator, .startSystemProxy(request)) == .cleanupUnproven)
    #expect(await proxy.counters().stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 0))

    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the retried stop did not complete once the Authority stopped the lease")
      return
    }
    #expect(await proxy.counters().stop == 2)
    #expect(await lease.counters() == (begin: 2, complete: 1))
  }

  /// A rollback whose Authority stop could not be ordered stops its owner
  /// locally, with no restore first: the owner's own stop restores its
  /// settings. The stop the user asks for next finds the owner stopped, so it
  /// restores nothing before the Authority orders the stop either.
  @Test func aRollbackThatStoppedItsOwnerLocallyRestoresNothingOnItsRetry() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = FailedStartProxyAgent(
      descriptor: descriptor, fault: nil,
      failure: EngineFailure(
        .agent(.engineStartTimedOut),
        message: "System Proxy runtime startup did not finish in time and was interrupted."))
    let preparer = RecordingSystemProxyStartPreparer(
      cancelError: AuthorityDomainError(code: .compensationConflict))
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .stopping,
        lease: agreement(
          for: descriptor, mode: descriptor.slot.authorityMode, leaseState: .stopping)),
      beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      systemProxyPreparer: preparer,
      engineLease: lease)

    #expect(await failureCode(coordinator, .startSystemProxy(request)) == .cleanupUnproven)
    #expect(await proxy.counters().stop == 1)
    #expect(await proxy.restoresBeforeStop == 0)

    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the retried rollback did not complete")
      return
    }
    #expect(await proxy.restoresBeforeStop == 0)
    #expect(await proxy.counters().stop == 1)
    #expect(await lease.counters() == (begin: 2, complete: 1))
  }
}
