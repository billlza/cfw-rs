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

// Tunnel stops against other managers, and the settings a stop restores:
// restores before the Authority orders a stop, rollbacks, earlier builds, and
// another user's lease.
extension NativeBridgeStartCommandIntegrationTests {
  /// A later start passed this Tunnel stop's generation and wrote its own
  /// manager, so Network Extension answers the stop as stale. The Authority
  /// holds no lease of the stop, so nothing of it is left to stop: the stop
  /// ends once the tunnel is Off.
  @Test func aReleasedTunnelStopEndsWhenALaterManagerReplacedItsOwn() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .tunnel))
    let lease = RecordingEngineLease(observation: ownership, beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: ownership, engineLease: lease)
    _ = try await coordinator.execute(.startTunnel(request))
    #expect(await failureCode(coordinator, .stopTunnel(request.context)) == .unavailable)
    #expect((await tunnel.counters()).stop == 0)

    await tunnel.replaceManager(sessionRuns: false)
    await lease.passGeneration(to: try context(request, generation: 8), state: .off)
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("a Tunnel stop whose manager a later start replaced did not end")
      return
    }
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 2, complete: 0))
  }

  /// While the Authority stops this Tunnel stop's lease, a manager of another
  /// configuration is no answer for it: the stop fails as stale.
  @Test func anOrderedTunnelStopFailsWhenAnotherManagerAnswersIt() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .tunnel))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: ownership, engineLease: lease)
    _ = try await coordinator.execute(.startTunnel(request))

    await tunnel.replaceManager(sessionRuns: true)
    #expect(await failureCode(coordinator, .stopTunnel(request.context)) == .identityRejected)
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 0))
  }

  /// An explicit Tunnel stop whose generation the Authority passed skips the
  /// status barrier, so it keeps that barrier's rule itself: it ends only once
  /// no Tunnel preference write awaits reconciliation.
  @Test func anExplicitTunnelStopTheAuthorityPassedWaitsForThePreferenceJournal()
    async throws
  {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let later = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true), generation: 8
    ).descriptor(slot: .tunnel)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .tunnel))
    let lease = RecordingEngineLease(observation: ownership, beginFailures: 1)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor), tunnel: tunnel,
      observation: ownership, engineLease: lease)
    _ = try await coordinator.execute(.startTunnel(request))
    #expect(await failureCode(coordinator, .stopTunnel(request.context)) == .unavailable)

    await tunnel.replaceManager(sessionRuns: false)
    await tunnel.injectPendingPreferenceMutation(later)
    await lease.passGeneration(to: try context(request, generation: 8), state: .off)
    #expect(await failureCode(coordinator, .stopTunnel(request.context)) == .cleanupUnproven)
    #expect((await tunnel.counters()).stop == 1)

    try await tunnel.finishPreferenceCompensation(expectedConfiguration: later)
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("the Tunnel stop did not end once the preference journal settled")
      return
    }
    #expect((await tunnel.counters()).stop == 1)
  }

  /// The failed start's preferences were not restored before a later start
  /// passed its generation, whether its stop had been ordered or not. The
  /// cleanup restores them once, asks the Authority for nothing that later
  /// start holds, and ends with the tunnel Off.
  @Test(arguments: [false, true])
  func tunnelCleanupFinishesOnceTheAuthorityPassedItsGeneration(stopOrdered: Bool)
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

    await lease.passGeneration(to: try context(request, generation: 8), state: .off)
    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("the failed start's cleanup did not finish once the Authority passed it")
      return
    }
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await lease.reconcileCount() == 0)
    #expect(await lease.counters().complete == (stopOrdered ? 1 : 0))
    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("the cleanup did not leave proven Off")
      return
    }
  }

  /// A System Proxy stop has the ProxyAgent give the OS back its settings
  /// before the Authority orders the stop, and only then. A retry of a stop
  /// the Authority already ordered does not ask again, whether the owner
  /// stopped or its stop failed: the owner's own stop restores what is left.
  @Test(arguments: [false, true])
  func aSystemProxyStopRestoresItsSettingsBeforeTheAuthorityOrdersIt(ownerStopFails: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let events = NativeCleanupEventLog()
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: ownerStopFails
        ? [.transportUnavailable("The ProxyAgent connection was interrupted.")] : [],
      events: events)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(
      observation: ownership, completeFailures: ownerStopFails ? 0 : 1, cleanupEvents: events)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .unavailable)
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the System Proxy stop did not end")
      return
    }
    #expect(await proxy.restoresBeforeStop == [descriptor])
    #expect(
      events.events
        == (ownerStopFails
          ? ["restore-before-stop", "begin-stop", "proxy-stop", "proxy-stop", "complete-stop"]
          : [
            "restore-before-stop", "begin-stop", "proxy-stop", "complete-stop", "complete-stop",
          ]))
  }

  /// A start whose readiness the Host could not confirm is rolled back. The
  /// user did not ask for Off, so the rollback restores nothing first: the
  /// Authority orders the stop, and the owner's own stop restores its
  /// settings.
  @Test func aRollbackRestoresNoSettingsBeforeItsStop() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let events = NativeCleanupEventLog()
    let proxy = StartableProxyAgent(descriptor: descriptor, events: events)
    // The owner's readiness has not reached the Authority yet, so the Host
    // cannot confirm the start.
    let ownership = AuthorityOwnershipObservation(
      state: .starting,
      lease: agreement(for: descriptor, mode: .systemProxy, leaseState: .starting))
    let lease = RecordingEngineLease(observation: ownership, cleanupEvents: events)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    #expect(await failureCode(coordinator, .startSystemProxy(request)) == .busy)
    #expect(await proxy.restoresBeforeStop.isEmpty)
    #expect(events.events == ["begin-stop", "proxy-stop", "complete-stop"])
  }

  /// Ordering a stop the user asked for can fail once the ProxyAgent restored
  /// its settings. The settings then select no listener, so the owner stops
  /// at once, and the status no longer reports System Proxy running; the
  /// retry has the Authority order and complete the stop. A local stop that
  /// fails too is reported with the ordering failure, and the retry restores
  /// and stops again.
  @Test(arguments: [false, true])
  func aStopWhoseOrderingFailsAfterItsRestoreStopsTheOwnerLocally(localStopFails: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let events = NativeCleanupEventLog()
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      stopFailures: localStopFails
        ? [.transportUnavailable("The ProxyAgent connection was interrupted.")] : [],
      events: events)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(
      observation: ownership, beginFailures: 1, cleanupEvents: events)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))

    let stopFailure = await failure(coordinator, .stopSystemProxy(request.context))
    #expect(stopFailure?.code == .unavailable)
    #expect(stopFailure?.message.contains("Local stop also failed") == localStopFails)
    #expect(events.events == ["restore-before-stop", "begin-stop", "proxy-stop"])
    if !localStopFails,
      case .status(.systemProxy) = try? await coordinator.execute(.queryStatus)
    {
      Issue.record("System Proxy was still reported running after its owner stopped")
    }

    events.removeAll()
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the retried stop did not end")
      return
    }
    #expect(
      events.events
        == (localStopFails
          ? ["restore-before-stop", "begin-stop", "proxy-stop", "complete-stop"]
          : ["begin-stop", "complete-stop"]))
  }

  /// A restore before the stop that fails asks the Authority for nothing:
  /// System Proxy keeps running, the status still reports it, and the stop
  /// can be asked again.
  @Test func aStopWhoseSettingsCannotBeRestoredKeepsSystemProxyRunning() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      restoreBeforeStopFailures: [
        .agentFailure(
          EngineFailure(
            .agent(.preferencesFailed), message: "System Proxy settings were not restored."))
      ])
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startSystemProxy(request))
    #expect(
      await failureCode(coordinator, .stopSystemProxy(request.context))
        == .systemProxyPreferencesFailed)
    #expect(await lease.counters() == (begin: 0, complete: 0))
    #expect((await proxy.counters()).stop == 0)
    guard case .status(.systemProxy(let runtime)) = try await coordinator.execute(.queryStatus)
    else {
      Issue.record("System Proxy was not reported running after its restore failed")
      return
    }
    #expect(runtime.context == request.context)

    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the retried stop did not end")
      return
    }
    #expect(await proxy.restoresBeforeStop == [descriptor, descriptor])
    #expect(await lease.counters() == (begin: 1, complete: 1))
  }

  /// A ProxyAgent of an earlier build cannot restore before its stop, and
  /// one whose build cannot be told may be one, as a running agent whose
  /// bundle an install replaced is. Neither is asked: its session stops as
  /// that build stops it.
  @Test(arguments: [false, true])
  func aStopOfAnEarlierProxyAgentBuildNeedsNoRestoreBeforeIt(inspectionFails: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let events = NativeCleanupEventLog()
    let proxy = StartableProxyAgent(descriptor: descriptor, events: events)
    await proxy.simulateExistingActiveSession()
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(observation: ownership, cleanupEvents: events)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      engineLease: lease,
      serviceBuildObserver: EarlierProxyBuildObserver(fails: inspectionFails))
    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the earlier build's session did not stop")
      return
    }
    #expect(events.events == ["begin-stop", "proxy-stop", "complete-stop"])
    #expect(await proxy.restoresBeforeStop.isEmpty)
  }

  /// A stop that restored nothing first changed nothing before its ordering
  /// failed, so it stops no owner locally either: System Proxy keeps running
  /// with its settings until the retry. The retry orders the stop and stops
  /// the owner.
  @Test func aStopThatRestoredNothingFirstStopsNoOwnerWhenItsOrderingFails() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let events = NativeCleanupEventLog()
    let proxy = StartableProxyAgent(descriptor: descriptor, events: events)
    await proxy.simulateExistingActiveSession()
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let lease = RecordingEngineLease(
      observation: ownership, beginFailures: 1, cleanupEvents: events)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      engineLease: lease, serviceBuildObserver: EarlierProxyBuildObserver(fails: false))
    #expect(await failureCode(coordinator, .stopSystemProxy(request.context)) == .unavailable)
    #expect(events.events == ["begin-stop"])

    guard
      case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("the retried stop did not end")
      return
    }
    #expect(events.events == ["begin-stop", "begin-stop", "proxy-stop", "complete-stop"])
  }

  /// A Local Proxy session applied no System Proxy settings, so its stop
  /// restores nothing before the Authority orders it.
  @Test func aLocalProxyStopRestoresNothingBeforeIt() async throws {
    let request = try startRequest(tunnelOptions: nil, mode: .localProxy)
    let descriptor = try request.descriptor(slot: .localProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let ownership = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .localProxy))
    let lease = RecordingEngineLease(observation: ownership)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor), observation: ownership,
      systemProxyPreparer: RecordingSystemProxyStartPreparer(), engineLease: lease)
    _ = try await coordinator.execute(.startLocalProxy(request))
    guard case .acknowledged = try await coordinator.execute(.stopLocalProxy(request.context))
    else {
      Issue.record("the Local Proxy stop did not end")
      return
    }
    #expect(await proxy.restoresBeforeStop.isEmpty)
    #expect((await proxy.counters()).stop == 1)
  }

  /// Another user's lease is no state this Host can observe. The status is
  /// busy, which a later read settles, not a rejected identity, which no read
  /// settles.
  @Test func aStatusQueryWaitsOutAnotherUsersLease() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: ConflictingEngineLease())
    #expect(await failureCode(coordinator, .queryStatus) == .busy)
  }
}
