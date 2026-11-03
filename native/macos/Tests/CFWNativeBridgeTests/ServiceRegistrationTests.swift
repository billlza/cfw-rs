import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Service registration: a restarted Authority reconciled once its observer
// exists, and an existing engine lease never passed.
private actor RegistrationRecoveryLease: NativeEngineLeaseInspecting {
  let maintainer: StubServiceMaintainer
  var observation = AuthorityOwnershipObservation(state: .recovering, lease: nil)
  var reconciliationCount = 0
  init(_ maintainer: StubServiceMaintainer) { self.maintainer = maintainer }
  func isAvailable() -> Bool { observation.state == .off }
  func authorityOwnership() -> AuthorityOwnershipObservation { observation }
  func reconcileOff(managedTunnel: RecoveryManagedTunnelStatus) throws
    -> AuthorityOwnershipObservation
  {
    guard observation.state == .recovering, managedTunnel == .invalid,
      maintainer.status(of: .globalAuthority) == .enabled,
      maintainer.status(of: .proxyAgent) == .enabled
    else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    reconciliationCount += 1
    observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    return observation
  }
  func beginStop(for descriptor: ConfigurationDescriptor) throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unexpected stop")
  }
  func completeStop(_ context: NativeAuthorityStopContext) throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unexpected stop")
  }
}

@Test func serviceRegistrationReconcilesRestartedAuthorityAfterItsObserverExists() async throws {
  let maintainer = StubServiceMaintainer(proxy: .notRegistered, authority: .notRegistered)
  let lease = RegistrationRecoveryLease(maintainer)
  let subject = NativeBridgeCoordinator(
    proxy: StubProxyAgent(.off), systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: StubTunnelHost(.off, recoveryStatus: .invalid), engineLease: lease,
    credentialVault: StubCredentialVault(), hostOperationLease: AvailableNativeHostOperationLease(),
    serviceMaintainer: maintainer, serviceRuntimeObserver: StubServiceRuntimeObserver(),
    serviceBuildObserver: FixedCurrentServiceBuildObserver())
  guard
    case .serviceMaintenance(let registration) = try await subject.execute(
      .maintainCurrentServices(.registerGlobalAuthority))
  else {
    Issue.record("missing registration receipt")
    return
  }
  #expect(registration.globalAuthority == .enabled)
  #expect(registration.proxyAgent == .notRegistered)
  #expect(registration.engineStatus == nil)
  #expect(registration.offProofProfile == nil)
  #expect(await lease.reconciliationCount == 0)
  #expect(await !lease.isAvailable())
  guard
    case .serviceMaintenance(let ready) = try await subject.execute(
      .maintainCurrentServices(.registerProxyAgent))
  else {
    Issue.record("missing recovery receipt")
    return
  }
  #expect(ready.engineStatus == .off)
  #expect(ready.offProofProfile == .currentEngineV6AuthorityV11)
  #expect(ready.proxyAgent == .enabled)
  #expect(ready.globalAuthority == .enabled)
  #expect(await lease.reconciliationCount == 1)
  #expect(await lease.isAvailable())
  #expect(maintainer.registerCalls == 2)
}

@Test func serviceRegistrationCannotPassAnExistingEngineLease() async throws {
  let owned = try descriptor(slot: .systemProxy)
  let maintainer = StubServiceMaintainer(proxy: .notRegistered, authority: .enabled)
  let subject = coordinator(
    proxy: .off, tunnel: .off,
    observation: AuthorityOwnershipObservation(
      state: .recovering, lease: agreement(for: owned, mode: .systemProxy)),
    serviceMaintainer: maintainer)
  #expect(await maintenanceErrorCode(subject, action: .registerProxyAgent) == .busy)
  #expect(maintainer.registerCalls == 0)
}
