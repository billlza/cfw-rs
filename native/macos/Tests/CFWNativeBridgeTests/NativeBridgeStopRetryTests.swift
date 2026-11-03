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

// Stop retries: incomplete Authority completions, ended agents, and stops the
// Authority did or did not order.
extension NativeBridgeStartCommandIntegrationTests {
  @Test func systemProxyStopRetriesOnlyIncompleteAuthorityCompletion() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .systemProxy)),
      completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .systemProxy)),
      systemProxyPreparer: preparer,
      engineLease: lease)

    _ = try await coordinator.execute(.startSystemProxy(request))
    let first = await failureCode(coordinator, .stopSystemProxy(request.context))
    #expect(first == .unavailable)
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))

    guard case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("exact System Proxy stop retry was not acknowledged")
      return
    }
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 2))
  }

  /// A ProxyAgent whose engine could not be closed reports it and ends, so the
  /// stop's retry reaches a successor with no record of it. The Authority, which
  /// refuses to complete a stop its owner never attested, decides the retry: it
  /// reports the same unproven cleanup as the first stop, not a rejected
  /// configuration, and later retries ask only the Authority.
  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func stopRetriedAfterAnUnclosableAgentEndedReportsUnprovenCleanup(mode: NativeStartMode)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
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
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(
      observation: ownership, completeError: AuthorityDomainError(code: .cleanupUnproven))
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    let stop: NativeBridgeCommand =
      mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context)

    #expect(await failureCode(coordinator, stop) == .cleanupUnproven)
    #expect(await lease.counters() == (begin: 1, complete: 0))
    #expect(await failureCode(coordinator, stop) == .cleanupUnproven)
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    #expect(await failureCode(coordinator, stop) == .cleanupUnproven)
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.counters() == (begin: 1, complete: 2))
  }

  /// The Authority quarantines the stop of a ProxyAgent that ended without
  /// attesting it, and recovers once that process provably ended. The stop's
  /// retry then proves Off through the reconciliation a restart needs, instead
  /// of asking the Authority to complete a stop whose lease it released.
  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func stopRetriedAfterTheAuthorityRecoveredFromTheEndedAgentReachesOff(
    mode: NativeStartMode
  ) async throws {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
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
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(
      observation: ownership, completeError: AuthorityDomainError(code: .cleanupUnproven))
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    let stop: NativeBridgeCommand =
      mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context)
    #expect(await failureCode(coordinator, stop) == .cleanupUnproven)

    await lease.recoverFromEndedOwner(of: request.context)
    guard case .acknowledged = try await coordinator.execute(stop) else {
      Issue.record("the stop's retry did not reach Off once the Authority recovered")
      return
    }
    #expect((await proxy.counters()).stop == 2)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    #expect(await lease.reconcileCount() == 1)
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("the recovered stop did not leave proven Off")
      return
    }
  }

  /// A stop the Authority could not order before it recovered has no lease to
  /// order any more: the owner is still stopped and the Host proves Off itself.
  /// A System Proxy owner already stopped once its settings were restored and
  /// the ordering failed, so the retry does not ask it again.
  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func stopUnorderedWhenTheAuthorityRecoveredEndsWithTheHostsOffProof(
    mode: NativeStartMode
  ) async throws {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(observation: ownership, beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    let stop: NativeBridgeCommand =
      mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context)
    #expect(await failureCode(coordinator, stop) == .unavailable)
    #expect((await proxy.counters()).stop == (mode == .systemProxy ? 1 : 0))

    await lease.recoverFromEndedOwner(of: request.context)
    guard case .acknowledged = try await coordinator.execute(stop) else {
      Issue.record("an unordered stop did not reach Off once the Authority recovered")
      return
    }
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 2, complete: 0))
    #expect(await lease.reconcileCount() == 1)
  }

  /// The Authority quarantined the lease before the stop could order it, so the
  /// stop is left unordered. The owner then ended, the Authority recovered, and
  /// the app's next status query proved Off at this stop's generation. The
  /// stop's retry finds no lease to order and ends with that Off, instead of
  /// failing, and holding back every start, until the app is relaunched. A
  /// System Proxy stop restored the settings first, so it asked the owner to
  /// stop at once; that owner held no session, so the retry asks it again.
  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func stopUnorderedBeforeTheAuthorityReachedOffEndsWithItsGenerationsOff(
    mode: NativeStartMode
  ) async throws {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: [
        .agentFailure(
          EngineFailure(
            .agent(.stopWithoutSession),
            message: "System Proxy holds no session for the stopped generation."))
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    let stop: NativeBridgeCommand =
      mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context)
    await lease.quarantine()
    #expect(await failureCode(coordinator, stop) == .staleOperation)
    #expect((await proxy.counters()).stop == (mode == .systemProxy ? 1 : 0))

    await proxy.simulateEnded()
    await lease.recoverFromEndedOwner(of: request.context)
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("the status query did not reconcile the recovered Authority")
      return
    }
    #expect(await lease.reconcileCount() == 1)

    guard case .acknowledged = try await coordinator.execute(stop) else {
      Issue.record("the unordered stop did not end with its generation's Off")
      return
    }
    #expect((await proxy.counters()).stop == (mode == .systemProxy ? 2 : 1))
    #expect(await lease.counters() == (begin: 2, complete: 0))
    #expect(await lease.reconcileCount() == 1)
    // No stop transaction is left: the same stop is acknowledged from Off.
    guard case .acknowledged = try await coordinator.execute(stop) else {
      Issue.record("a stop transaction outlived its proven Off")
      return
    }
    #expect(await lease.counters() == (begin: 2, complete: 0))
  }

  /// A later start passed this stop's generation while the stop waited, so the
  /// stop's lease ended through a proven Off. The unordered stop stops its own
  /// owner and ends once that owner is Off, instead of failing, and holding
  /// back every start, until the app is relaunched.
  @Test func stopUnorderedEndsOnceTheAuthorityPassedItsGeneration() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    await lease.quarantine()
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .staleOperation)

    await proxy.simulateEnded()
    await lease.recoverFromEndedOwner(of: try context(request, generation: 8))
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("the status query did not reconcile the recovered Authority")
      return
    }
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("a stop whose generation the Authority passed did not end")
      return
    }
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 2, complete: 0))
    #expect(await lease.reconcileCount() == 1)
  }

  /// The stop could not be ordered, and a later start passed its generation
  /// before the retry. Its owner is Off, so the stop ends without reconciling
  /// or completing anything at the Authority, and the next start is admitted.
  /// A System Proxy owner already stopped once its settings were restored and
  /// the ordering failed.
  @Test(arguments: [NativeStartMode.localProxy, .systemProxy])
  func anUnorderedStopTheAuthorityPassedEndsAndAdmitsTheNextStart(
    mode: NativeStartMode
  ) async throws {
    let request = try startRequest(tunnelOptions: nil, mode: mode)
    let descriptor = try request.descriptor(slot: mode.slot)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: mode.slot.authorityMode))
    let lease = RecordingEngineLease(observation: ownership, beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: preparer, engineLease: lease)
    _ = try await coordinator.execute(
      mode == .localProxy ? .startLocalProxy(request) : .startSystemProxy(request))
    let stop: NativeBridgeCommand =
      mode == .localProxy ? .stopLocalProxy(request.context) : .stopSystemProxy(request.context)
    #expect(await failureCode(coordinator, stop) == .unavailable)
    #expect((await proxy.counters()).stop == (mode == .systemProxy ? 1 : 0))

    await lease.passGeneration(to: try context(request, generation: 8), state: .off)
    guard case .acknowledged = try await coordinator.execute(stop) else {
      Issue.record("a stop whose generation the Authority passed did not end")
      return
    }
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 2, complete: 0))
    #expect(await lease.reconcileCount() == 0)
    let next = try startRequest(tunnelOptions: nil, mode: mode, generation: 9)
    _ = await failureCode(
      coordinator, mode == .localProxy ? .startLocalProxy(next) : .startSystemProxy(next))
    #expect(await preparer.prepareCalls == 2)
  }

  /// The stop was ordered, and the owner stopped, but a later start passed the
  /// generation before the Authority completed the stop. The stop ends with
  /// its own owner Off, whatever later lease the Authority holds, and the
  /// status then reports that lease as busy.
  @Test func anOrderedStopTheAuthorityPassedEndsWhileALaterLeaseIsActive() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let later = try startRequest(tunnelOptions: nil, generation: 8).descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership, completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .unavailable)
    #expect(await lease.counters() == (begin: 1, complete: 1))

    await lease.passGeneration(
      to: try context(request, generation: 8), state: .active,
      lease: agreement(for: later, mode: .systemProxy))
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("an ordered stop whose generation the Authority passed did not end")
      return
    }
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 2))
    #expect(await lease.reconcileCount() == 0)
    #expect(await failureCode(coordinator, .queryStatus) == .busy)
  }

  /// The Authority passed the stop's generation, but the stop's own owner is
  /// not Off: it failed at the stop's generation, which leaves cleanup
  /// unproven, or a later start holds it, which is busy. Either way the stop
  /// stays pending and holds back starts, and it ends once the owner is Off.
  @Test(arguments: [false, true])
  func aStopTheAuthorityPassedWaitsForItsOwnOwner(laterStartHoldsIt: Bool) async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let later = try startRequest(tunnelOptions: nil, generation: 8).descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership, completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: preparer, engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .unavailable)

    await lease.passGeneration(to: try context(request, generation: 8), state: .off)
    await proxy.report(
      laterStartHoldsIt
        ? .proxyActive(configuration: later, sequence: 3)
        : try EngineSnapshot(
          mode: .systemProxy,
          state: .failed(
            EngineFailure(
              code: "runtime-failed", message: "Runtime stopped unexpectedly.",
              isRetryable: false)),
          configuration: descriptor, sequence: 3))
    #expect(
      await failureCode(coordinator, .stopSystemProxy(request.context))
        == (laterStartHoldsIt ? .busy : .cleanupUnproven))
    #expect(
      await failureCode(
        coordinator, .startSystemProxy(try startRequest(tunnelOptions: nil, generation: 9)))
        == .cleanupUnproven)
    #expect(await preparer.prepareCalls == 1)

    await proxy.report(nil)
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the stop did not end once its own owner was Off")
      return
    }
    #expect((await proxy.counters()).stop == 1)
  }

  /// An unordered stop ends only once the Authority settled its lease: Off at
  /// the stop's generation, or a cursor past it. A quarantined Authority, or
  /// one that lost its store and holds no record of any generation, settled
  /// nothing, so the retry fails without asking the owner, and starts stay
  /// held back. A Local Proxy stop changes nothing before it is ordered, so its
  /// owner still runs.
  @Test(arguments: [false, true])
  func anUnorderedStopTheAuthorityDidNotSettleFails(storeLost: Bool) async throws {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let descriptor = try request.descriptor(slot: .localProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .localProxy))
    let lease = RecordingEngineLease(observation: ownership, beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startLocalProxy(request))
    #expect(await failureCode(coordinator, .stopLocalProxy(request.context)) == .unavailable)

    if storeLost {
      await lease.loseStore()
    } else {
      await lease.quarantine()
    }
    #expect(await failureCode(coordinator, .stopLocalProxy(request.context)) == .staleOperation)
    #expect((await proxy.counters()).stop == 0)
    let next = try startRequest(tunnelOptions: nil, mode: .localProxy, generation: 9)
    #expect(await failureCode(coordinator, .startLocalProxy(next)) == .cleanupUnproven)
  }
}
