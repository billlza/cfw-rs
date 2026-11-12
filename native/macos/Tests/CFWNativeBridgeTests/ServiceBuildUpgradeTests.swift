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

// Ordered upgrades of the app's services: an old owner stays observable and
// stops first, an orphaned proxy's Off resumes the upgrade, and cancellations
// and identity changes keep the registration pair.
@Suite struct ServiceBuildUpgradeTests {
  @Test func oldActiveRemainsObservableAndStopsBeforeOrderedUpgrade() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let active = AuthorityOwnershipObservation(
      state: .active, lease: agreement(for: descriptor, mode: .systemProxy))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    await proxy.simulateExistingActiveSession()
    let lease = RecordingEngineLease(observation: active)
    let services = ServiceUpgradeFixture()
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: active, engineLease: lease,
      serviceBuildObserver: services, serviceMaintainer: services)

    guard case .status(.systemProxy(let runtime)) = try await subject.execute(.queryStatus) else {
      Issue.record("Old active owner was hidden by the version gate")
      return
    }
    #expect(runtime == (try NativeBridgeCoordinator.runtime(descriptor: descriptor, proxy: true)))
    #expect(await subject.serviceBuildUpgradePending)
    #expect(services.mutations.isEmpty)
    #expect(await proxy.counters().stop == 0)
    let initialInspections = services.inspectionCount
    _ = try await subject.execute(.queryStatus)
    #expect(services.inspectionCount == initialInspections)
    #expect(await failureCode(subject, .startSystemProxy(request)) == .busy)
    #expect(await proxy.counters().start == 1)
    #expect(services.mutations.isEmpty)

    #expect(try await subject.execute(.stopSystemProxy(request.context)) == .acknowledged)
    #expect(await proxy.counters().stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    #expect(services.mutations.isEmpty)
    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(
      services.mutations == [
        "unregister:proxyAgent", "unregister:globalAuthority",
        "register:globalAuthority", "register:proxyAgent",
      ])
    #expect(try services.inspect().isCurrent)
    #expect(!(await subject.serviceBuildUpgradePending))
    let completedInspections = services.inspectionCount
    for _ in 0..<12 { #expect(try await subject.execute(.queryStatus) == .status(.off)) }
    #expect(services.inspectionCount == completedInspections)
  }

  @Test func transientIdentityFailureCanRecoverWithUnchangedRegistrationPair() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(inspectionFailures: 1)
    services.markCurrent()
    let subject = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(await failureCode(subject, .queryStatus) == .identityRejected)
    #expect(services.inspectionCount == 1)
    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(services.inspectionCount == 2)
    #expect(services.mutations.isEmpty)
    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(services.inspectionCount == 2)
  }

  @Test func cachedStatusNeverAuthorizesNewOperationsAfterServiceChange() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture()
    services.markCurrent()
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(services.inspectionCount == 1)
    services.markOld()
    #expect(await failureCode(subject, .authorizeSystemProxy) == .busy)
    #expect(services.inspectionCount == 2)
    #expect(await proxy.authorizationCalls == 0)
    #expect(services.mutations.isEmpty)
    #expect(try await subject.execute(.authorizeSystemProxyRestoration) == .acknowledged)
    #expect(await proxy.authorizationCalls == 1)
    #expect(services.inspectionCount == 2)
  }

  @Test func partialHandoffFailureDoesNotFallThroughToAutoRegisteringQuery() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(failAfterProxyUnregister: true)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    _ = await failureCode(subject, .queryStatus)
    #expect(services.mutations == ["unregister:proxyAgent"])
    #expect(services.status(of: .proxyAgent) == .notRegistered)
    // Only the pre-handoff Off query may run. A fallback would call ensureRegistered again.
    #expect(await proxy.counters().ensure == 1)
    #expect(services.inspectionCount == 2)
    #expect(await subject.serviceBuildUpgradePending)
  }

  @Test func authorityRegistrationRefusalAfterUnregisterRetriesTheSameHandoff() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityRegistrationRefusals: 1)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)

    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(
      services.mutations == [
        "unregister:proxyAgent", "unregister:globalAuthority",
        "register:globalAuthority", "register:globalAuthority", "register:proxyAgent",
      ])
    #expect(try services.inspect().isCurrent)
    #expect(await proxy.counters().start == 0)
  }

  @Test(arguments: [false, true])
  func authorityRegistrationRefusalDoesNotRetryOutsideHandoffOrBeyondOnce(handoff: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let status: CurrentAppServiceStatus = handoff ? .enabled : .notRegistered
    let services = ServiceUpgradeFixture(
      proxyStatus: status, authorityStatus: status, authorityRegistrationRefusals: 2)
    let subject = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)

    #expect(await failureCode(subject, .queryStatus) == .cleanupUnproven)
    let expected =
      handoff
      ? [
        "unregister:proxyAgent", "unregister:globalAuthority", "register:globalAuthority",
        "register:globalAuthority",
      ]
      : ["register:globalAuthority"]
    #expect(services.mutations == expected)
    #expect(services.status(of: .globalAuthority) == .notRegistered)
    #expect(services.status(of: .proxyAgent) == .notRegistered)
  }
}

extension ServiceBuildUpgradeTests {
  @Test func orphanedProxyOffResumesOrderedUpgradeWithoutStartingAnEngine() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    do {
      #expect(try await subject.execute(.queryStatus) == .status(.off))
    } catch {
      let counters = await proxy.counters()
      Issue.record(
        "Stable-Off mixed pair failed: \(error); ordinary query ensure=\(counters.ensure), snapshot=\(counters.snapshot)"
      )
    }
    #expect(
      services.mutations == [
        "unregister:proxyAgent", "register:globalAuthority", "register:proxyAgent",
      ])
    #expect(try services.inspect().isCurrent)
    #expect(!(await subject.serviceBuildUpgradePending))
    #expect(await proxy.counters().start == 0)
    #expect(await proxy.counters().stop == 0)
  }

  private enum OrphanedProxyFailure: CaseIterable, Sendable {
    case active, failed, unknown
  }

  @Test(arguments: OrphanedProxyFailure.allCases, [false, true])
  private func orphanedProxyMustRemainStrictlyOffUntilRetirement(
    failure: OrphanedProxyFailure, changesAfterFirstProof: Bool
  ) async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let unsafe: EngineSnapshot
    switch failure {
    case .active:
      unsafe = .proxyActive(configuration: descriptor, sequence: 1)
    case .failed:
      unsafe = try EngineSnapshot(
        mode: .systemProxy,
        state: .failed(
          EngineFailure(code: "fixture-failed", message: "Fixture failure", isRetryable: false)),
        configuration: descriptor, sequence: 1)
    case .unknown:
      unsafe = .off  // The transport throws before returning this snapshot.
    }
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      snapshotSequence: changesAfterFirstProof ? [.off, unsafe] : [unsafe],
      snapshotErrorAt: failure == .unknown ? (changesAfterFirstProof ? 2 : 1) : nil)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(
      await failureCode(subject, .queryStatus) == (failure == .unknown ? .unavailable : .busy))
    #expect(services.mutations.isEmpty)
    #expect(await proxy.counters().snapshot == (changesAfterFirstProof ? 2 : 1))
    #expect(await proxy.counters().ensure == 0)
    #expect(await proxy.counters().start == 0)
    #expect(await proxy.counters().stop == 0)
    #expect(await subject.serviceBuildUpgradePending)
  }

  @Test(arguments: [1, 2, 3])
  func orphanedUpgradeRejectsConflictingIdentityBeforeRetirementAndBeforeStart(
    conflictingInspection: Int
  ) async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(
      authorityStatus: .notRegistered, conflictingInspection: conflictingInspection)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    let command: NativeBridgeCommand =
      conflictingInspection < 3 ? .queryStatus : .startSystemProxy(request)
    #expect(await failureCode(subject, command) == .identityRejected)
    if conflictingInspection < 3 {
      #expect(services.mutations.isEmpty)
      #expect(await proxy.counters().ensure == 0)
    } else {
      #expect(
        services.mutations == [
          "unregister:proxyAgent", "register:globalAuthority", "register:proxyAgent",
        ])
    }
    #expect(await proxy.counters().start == 0)
    #expect(await proxy.counters().stop == 0)
    #expect(await subject.serviceBuildUpgradePending)
  }

  @Test(arguments: ["unregister:proxyAgent", "register:globalAuthority", "register:proxyAgent"])
  func orphanedUpgradeMutationFailurePreservesPartialPairWithoutFallback(failedMutation: String)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(
      authorityStatus: .notRegistered, failedMutation: failedMutation)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(await failureCode(subject, .queryStatus) == .cleanupUnproven)
    let sequence = ["unregister:proxyAgent", "register:globalAuthority", "register:proxyAgent"]
    let failedIndex = try #require(sequence.firstIndex(of: failedMutation))
    #expect(services.mutations == Array(sequence.prefix(failedIndex + 1)))
    #expect(services.status(of: .proxyAgent) == (failedIndex == 0 ? .enabled : .notRegistered))
    #expect(services.status(of: .globalAuthority) == (failedIndex == 2 ? .enabled : .notRegistered))
    #expect(await proxy.counters().ensure == 0)
    #expect(await proxy.counters().start == 0)
    #expect(await subject.serviceBuildUpgradePending)
  }

  @Test func orphanedUpgradeCancellationPreservesAbsenceAndResumesOnANewCall() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(
      cancelAfterProxyUnregister: true, authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    let cancelled = Task { await failureCode(subject, .queryStatus) }
    #expect(await cancelled.value == .timeout)
    #expect(services.mutations == ["unregister:proxyAgent"])
    #expect(services.status(of: .proxyAgent) == .notRegistered)
    #expect(services.status(of: .globalAuthority) == .notRegistered)
    #expect(await proxy.counters().ensure == 0)
    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(
      services.mutations == [
        "unregister:proxyAgent", "register:globalAuthority", "register:proxyAgent",
      ])
    #expect(try services.inspect().isCurrent)
    #expect(await proxy.counters().start == 0)
  }

  @Test func orphanedUpgradeRechecksOffAfterRegistrationBeforeStarting() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      snapshotSequence: [.off, .off, .proxyActive(configuration: descriptor, sequence: 1)])
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(await failureCode(subject, .startSystemProxy(request)) == .quarantined)
    #expect(
      services.mutations == [
        "unregister:proxyAgent", "register:globalAuthority", "register:proxyAgent",
      ])
    #expect(await proxy.counters().start == 0)
    #expect(await subject.serviceBuildUpgradePending)
  }

  @Test(arguments: [CurrentAppServiceRuntimeStatus.present, .unobservable])
  func orphanedUpgradeRequiresActualAuthorityAbsence(authority: CurrentAppServiceRuntimeStatus)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services,
      serviceRuntimeObserver: ServiceUpgradeRuntimeState(authority: authority))
    #expect(
      await failureCode(subject, .queryStatus) == (authority == .present ? .busy : .cleanupUnproven)
    )
    #expect(services.mutations.isEmpty)
    #expect(await proxy.counters().ensure == 0)
    #expect(await proxy.counters().start == 0)
  }

  @Test(arguments: [false, true])
  func orphanedUpgradeRejectsRegistrationChangesAcrossRetirementAwaits(
    authorityAppearsAfterProxyRetirement: Bool
  ) async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      snapshotHook: { call in
        if authorityAppearsAfterProxyRetirement, call == 3 {
          // The new Authority is registered but has not launched yet. Process
          // absence must not grant automatic permission to unregister it.
          services.setStatus(.enabled, of: .globalAuthority)
        } else if !authorityAppearsAfterProxyRetirement, call == 1 {
          // The initial mixed pair vanished during the first awaited boundary.
          // Do not skip the strict checks and silently continue registration.
          services.setStatus(.notRegistered, of: .proxyAgent)
        }
      })
    let subject = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(await failureCode(subject, .queryStatus) == .cleanupUnproven)
    #expect(
      services.mutations == (authorityAppearsAfterProxyRetirement ? ["unregister:proxyAgent"] : []))
    #expect(!services.mutations.contains("unregister:globalAuthority"))
    #expect(await proxy.counters().ensure == 0)
    #expect(await proxy.counters().start == 0)
    #expect(await subject.serviceBuildUpgradePending)
  }

  @Test(arguments: [CurrentSystemProxySwitchStatus.enabled, .unobservable])
  func orphanedUpgradeRequiresObservableDisabledSystemProxy(status: CurrentSystemProxySwitchStatus)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services,
      systemProxySwitchObserver: ServiceUpgradeSystemProxyState(observed: status))
    #expect(
      await failureCode(subject, .queryStatus) == (status == .enabled ? .busy : .cleanupUnproven))
    #expect(services.mutations.isEmpty)
    #expect(await proxy.counters().ensure == 0)
    #expect(await proxy.counters().start == 0)
  }

  @Test(arguments: [false, true])
  func orphanedUpgradeRequiresObservableTunnelAndSettledPreferences(pendingPreference: Bool)
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(authorityStatus: .notRegistered)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor, pendingPreferenceDescriptor: pendingPreference ? descriptor : nil,
      snapshotFailures: pendingPreference ? 0 : 1)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    #expect(
      await failureCode(subject, .queryStatus)
        == (pendingPreference ? .cleanupUnproven : .unavailable))
    #expect(services.mutations.isEmpty)
    #expect(await proxy.counters().ensure == 0)
    #expect(await proxy.counters().start == 0)
    #expect(await tunnel.startCalls == 0)
  }

  @Test func cancellationAfterUnregisterRetainsPairAndNextCallResumesFromFreshOff() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture(cancelAfterProxyUnregister: true)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    let cancelledCall = Task { await failureCode(subject, .queryStatus) }
    #expect(await cancelledCall.value == .timeout)
    #expect(services.status(of: .proxyAgent) == .notRegistered)
    #expect(services.status(of: .globalAuthority) == .enabled)
    #expect(services.mutations == ["unregister:proxyAgent"])
    #expect(await proxy.counters().ensure == 1)
    #expect(try await subject.execute(.queryStatus) == .status(.off))
    #expect(
      services.mutations == [
        "unregister:proxyAgent", "unregister:globalAuthority",
        "register:globalAuthority", "register:proxyAgent",
      ])
    #expect(try services.inspect().isCurrent)
  }

  @Test func cancellationBeforeHandoffDoesNotFallThroughToQuery() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let services = ServiceUpgradeFixture()
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let subject = makeCoordinator(
      proxy: proxy, tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceBuildObserver: services, serviceMaintainer: services)
    let cancelledCall = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      do {
        _ = try await subject.queryStatusWithServiceBuildReconciliation()
        Issue.record("Cancelled build reconciliation unexpectedly succeeded")
      } catch let error as NativeBridgeExecutionError {
        #expect(error.responseFailure.code == .timeout)
      } catch {
        Issue.record("Cancellation lost its typed failure: \(error)")
      }
    }
    await cancelledCall.value
    #expect(services.inspectionCount == 0)
    #expect(services.mutations.isEmpty)
    #expect(await proxy.counters().ensure == 0)
  }
}
