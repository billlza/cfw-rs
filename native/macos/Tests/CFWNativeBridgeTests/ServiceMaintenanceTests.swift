import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Service maintenance and its leases: authorization takes no mutation lease,
// Off and mutation share the host lease, the fixed sequence, and a status that
// claims nothing and never repairs.
@Test func systemProxyAuthorizationAcquiresNoEngineOrHostMutationLease() async throws {
  let proxy = StubProxyAgent(.off)
  let subject = NativeBridgeCoordinator(
    proxy: proxy,
    systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: StubTunnelHost(.off),
    engineLease: StubLease(
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil)),
    credentialVault: StubCredentialVault(),
    hostOperationLease: BusyNativeHostOperationLease(),
    serviceBuildObserver: FixedCurrentServiceBuildObserver())
  #expect(try await subject.execute(.authorizeSystemProxy) == .acknowledged)
  #expect(try await subject.execute(.authorizeSystemProxyRestoration) == .acknowledged)
  #expect(await proxy.authorizationCount == 2)
  #expect(await proxy.authorizationRestorationOnly == [false, true])
}

@Test func maintenanceOffAndMutationShareTheHostOperationLease() async throws {
  let sentinel = LeaseSentinel()
  let maintainer = StubServiceMaintainer { _, _ in
    #expect(sentinel.isHeld)
  }
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    onAuthorityObservation: {
      #expect(sentinel.isHeld)
    },
    serviceMaintainer: maintainer,
    hostOperationLease: SentinelLeaseAcquirer(sentinel: sentinel)
  )

  guard
    case .serviceMaintenance(let result) = try await coordinator.execute(
      .maintainCurrentServices(.unregisterProxyAgent))
  else {
    Issue.record("maintenance returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == .off)
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.globalAuthority == .enabled)
  #expect(maintainer.unregisterCalls == 1)
  #expect(maintainer.registerCalls == 0)
  #expect(!sentinel.isHeld)
}

@Test func fixedMaintenanceSequencePreservesOrderingAndEndsEnabledOff() async throws {
  let maintainer = StubServiceMaintainer()
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )

  let actions: [NativeServiceMaintenanceAction] = [
    .unregisterProxyAgent,
    .unregisterGlobalAuthority,
    .registerGlobalAuthority,
    .registerProxyAgent,
    .proveOff,
  ]
  for action in actions {
    guard
      case .serviceMaintenance(let result) = try await coordinator.execute(
        .maintainCurrentServices(action))
    else {
      Issue.record("maintenance returned the wrong result kind")
      return
    }
    #expect(result.action == action)
    #expect(result.engineStatus == (action == .registerGlobalAuthority ? nil : .off))
    #expect(
      result.offProofProfile
        == (action == .registerGlobalAuthority ? nil : .currentEngineV6AuthorityV11))
  }
  #expect(maintainer.unregisterCalls == 2)
  #expect(maintainer.registerCalls == 2)
  #expect(maintainer.status(of: .proxyAgent) == .enabled)
  #expect(maintainer.status(of: .globalAuthority) == .enabled)
}

@Test func maintenanceStatusIsPureAndDoesNotClaimEngineOff() async throws {
  let maintainer = StubServiceMaintainer(proxy: .notFound, authority: .unknown)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .active, lease: nil),
    serviceMaintainer: maintainer
  )

  guard
    case .serviceMaintenance(let result) = try await coordinator.execute(
      .maintainCurrentServices(.status))
  else {
    Issue.record("maintenance status returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == nil)
  #expect(result.proxyAgent == .notFound)
  #expect(result.globalAuthority == .unknown)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.registerCalls == 0)
}

@Test func maintenanceRegistrationStatusRemainsReadableWhileAnotherHostOwnsTheLease() async throws {
  let maintainer = StubServiceMaintainer(proxy: .requiresApproval, authority: .notRegistered)
  let runtimeObserver = StubServiceRuntimeObserver(onObservation: { _ in
    Issue.record("registration status must not inspect native runtime ownership")
  })
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .active, lease: nil),
    onAuthorityObservation: { Issue.record("registration status must not call Authority") },
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: runtimeObserver,
    hostOperationLease: BusyNativeHostOperationLease()
  )
  guard
    case .serviceMaintenance(let result) = try await subject.execute(
      .maintainCurrentServices(.status))
  else {
    Issue.record("registration status returned the wrong result")
    return
  }
  #expect(result.proxyAgent == .requiresApproval)
  #expect(result.globalAuthority == .notRegistered)
  #expect(result.engineStatus == nil)
  #expect(result.offProofProfile == nil)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
  #expect(runtimeObserver.observations.isEmpty)
}

@Test func maintenanceStatusExemptionNeverAdmitsProofMutationOrEngineQuery() async {
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    onAuthorityObservation: { Issue.record("contended operation must stop before Authority") },
    serviceMaintainer: maintainer,
    hostOperationLease: BusyNativeHostOperationLease()
  )
  let actions: [NativeServiceMaintenanceAction] = [
    .retireOrphanedServices, .proveOff, .proveInstalled40019Off,
    .unregisterProxyAgent, .unregisterInstalled40019ProxyAgent,
    .unregisterGlobalAuthority, .unregisterInstalled40019GlobalAuthority,
    .recoverInstalled40019GlobalAuthority, .registerGlobalAuthority, .registerProxyAgent,
  ]
  for action in actions {
    #expect(await maintenanceErrorCode(subject, action: action) == .busy)
  }
  #expect(await statusErrorCode(subject) == .busy)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
}

@Test func everyUnprovenAuthorityStateBlocksBeforeServiceMutation() async {
  for state in [
    AuthorityState.preparing, .starting, .active, .stopping, .recovering, .quarantined,
  ] {
    let maintainer = StubServiceMaintainer()
    let coordinator = coordinator(
      proxy: .off,
      tunnel: .off,
      observation: AuthorityOwnershipObservation(state: state, lease: nil),
      serviceMaintainer: maintainer
    )
    #expect(
      await maintenanceErrorCode(
        coordinator, action: .unregisterProxyAgent) != nil)
    #expect(maintainer.unregisterCalls == 0)
    #expect(maintainer.registerCalls == 0)
  }
}

@Test func maintenanceLeaseContentionBlocksBeforeObservationOrMutation() async {
  let maintainer = StubServiceMaintainer()
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    hostOperationLease: BusyNativeHostOperationLease()
  )
  #expect(
    await maintenanceErrorCode(coordinator, action: .unregisterProxyAgent) == .busy)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.registerCalls == 0)
}

@Test func pureMaintenanceProofNeverRepairsAnAbsentProxyAgent() async {
  let maintainer = StubServiceMaintainer(proxy: .notRegistered, authority: .enabled)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )
  #expect(await maintenanceErrorCode(coordinator, action: .proveOff) != nil)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
}
