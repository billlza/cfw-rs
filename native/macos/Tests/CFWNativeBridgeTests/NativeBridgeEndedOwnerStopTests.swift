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

// Stops of ended and recovered owners: later starts, quarantine, the
// Authority's cause, Off cursors, and other generations.
extension NativeBridgeStartCommandIntegrationTests {
  /// An explicit stop reaches an owner that already ended while a later start
  /// is stopping at the Authority. That start's lease is not this stop's, so
  /// the stop ends with its own owner Off before it looks at that lease.
  @Test func anExplicitStopOfAnEndedOwnerEndsWhileALaterStartIsStopping() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let later = try startRequest(tunnelOptions: nil, generation: 8).descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(
      observation: ownership, recoveredStop: try recoveredStop(for: later))
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))

    await proxy.simulateEnded()
    await lease.passGeneration(
      to: try context(request, generation: 8), state: .stopping,
      lease: agreement(for: later, mode: .systemProxy, leaseState: .stopping))
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the stop of an ended owner did not end")
      return
    }
    #expect((await proxy.counters()).stop == 0)
    #expect(await lease.recoverCount() == 0)
    #expect(await lease.counters() == (begin: 0, complete: 0))
  }

  /// The Authority quarantines a stop whose owner never attested it once the
  /// stop deadline passes, while a ProxyAgent that could not close its engine
  /// runs at least 11 seconds. A retry in between reaches the successor, which
  /// holds no session, and fails at the quarantined Authority. The stop keeps
  /// its ordering and its stopped owner, so the retry after the Authority
  /// recovered asks neither of them again and reconciles Off once.
  @Test func stopRetriedWhileTheAuthorityQuarantinesKeepsItsProgress() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: [
        .agentFailure(
          EngineFailure(
            .agent(.engineUnclosable), message: "System Proxy could not close its runtime.")),
        .agentFailure(
          EngineFailure(
            .agent(.stopWithoutSession),
            message: "System Proxy holds no session for the stopped generation.")),
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .cleanupUnproven)
    #expect(await lease.counters() == (begin: 1, complete: 0))

    await lease.quarantine()
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .cleanupUnproven)
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.counters() == (begin: 1, complete: 1))

    await lease.recoverFromEndedOwner(of: request.context)
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the stop did not reach Off once the Authority recovered")
      return
    }
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.counters() == (begin: 1, complete: 2))
    #expect(await lease.reconcileCount() == 1)
  }

  /// An Authority that fails the check of this stop's Off reports its own
  /// cause, as every other Authority call of the stop does.
  @Test func aFailedCompletedStopCheckReportsTheAuthoritysCause() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership, beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .unavailable)

    await lease.recoverFromEndedOwner(of: request.context)
    await lease.failNextStopResolution(
      with: AuthorityDomainError(code: .globalAuthorityUnavailable))
    #expect(
      await failureCode(coordinator, .stopSystemProxy(request.context))
        == .globalAuthorityUnavailable)
  }

  /// A restarted Authority whose cursor passed this stop's generation needs
  /// no reconciliation for this stop: its lease ended, and the stop ends with
  /// its own owner Off.
  @Test func recoveredStopTheAuthorityPassedEndsWithItsOwnersOff() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: [
        .agentFailure(
          EngineFailure(
            .agent(.engineUnclosable), message: "System Proxy could not close its runtime."))
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .cleanupUnproven)

    await lease.recoverFromEndedOwner(of: try context(request, generation: 8))
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("a recovered stop whose generation the Authority passed did not end")
      return
    }
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.reconcileCount() == 0)
  }

  /// An Authority never reports Off at an earlier generation than one it
  /// prepared. Should a recovered one reconcile to such an Off anyway, that
  /// Off does not prove this stop.
  @Test func recoveredStopRequiresAnOffCursorAtOrPastItsGeneration() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: [
        .agentFailure(
          EngineFailure(
            .agent(.engineUnclosable), message: "System Proxy could not close its runtime."))
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .cleanupUnproven)

    await lease.recoverFromEndedOwner(of: try context(request, generation: 6))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .cleanupUnproven)
    #expect(await lease.reconcileCount() == 1)
  }

  /// A ProxyAgent answers a stop as stale when it holds a session of another
  /// generation. That owner has not ended, so the stop fails without asking the
  /// Authority to complete it. A ProxyAgent of an earlier build answers a stop
  /// without a session the same way, and fails the same, as every released
  /// Host failed it.
  @Test func staleStopForAnotherGenerationIsNotTakenForAnEndedOwner() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: [
        .agentFailure(
          EngineFailure(
            .agent(.staleStopRequest),
            message: "System Proxy stop does not match the active generation."))
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))

    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .identityRejected)
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 0))
  }

  /// A ProxyAgent that attested Stopped can still end before its reply arrives.
  /// The retry's successor has no record of the stop, and the Authority, which
  /// holds that attestation, completes it, so the Host still proves Off.
  @Test func stopRetriedAfterTheAgentEndedCompletesWhenItHadAttestedStopped() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: [
        .transportUnavailable("The ProxyAgent connection was interrupted."),
        .agentFailure(
          EngineFailure(
            .agent(.stopWithoutSession),
            message: "System Proxy holds no session for the stopped generation.")),
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))

    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .unavailable)
    guard case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("a stop retried after its attested owner ended was not acknowledged")
      return
    }
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("a stop retried after its attested owner ended did not reach proven Off")
      return
    }
  }

  @Test func tunnelStopRetriesOnlyIncompleteAuthorityCompletion() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      engineLease: lease)

    _ = try await coordinator.execute(.startTunnel(request))
    let first = await failureCode(coordinator, .stopTunnel(request.context))
    #expect(first == .unavailable)
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))

    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("exact Tunnel stop retry was not acknowledged")
      return
    }
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 2))
  }
}
