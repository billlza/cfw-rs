import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Retiring an orphaned service: recovery state kept, unproven network state
// refused, a network change stopping it until it resumes, and an Authority
// process or active owners blocking it.
@Test(arguments: [ConfigurationSlot.localProxy, .systemProxy])
func orphanedServiceRetirementPreservesRecoveryStateAndDoesNotClaimOff(slot: ConfigurationSlot)
  async throws
{
  let events = EventLedger()
  let maintainer = StubServiceMaintainer(onPerform: { mutation, service in
    #expect(mutation == .unregister)
    events.append(String(describing: service))
  })
  let subject = coordinator(
    proxy: .proxyFailed(
      EngineFailure(
        code: "system-proxy-ownership-conflict", message: "Pending recovery", isRetryable: false),
      configuration: try descriptor(slot: slot), sequence: 3),
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil),
    onAuthorityObservation: {
      Issue.record("Retirement must not start or reconcile the dead Authority")
    },
    serviceMaintainer: maintainer)
  let expected = NativeBridgeResult.serviceMaintenance(
    NativeServiceMaintenanceResult(
      action: .retireOrphanedServices, engineStatus: nil,
      globalAuthority: .notRegistered, offProofProfile: nil, proxyAgent: .notRegistered))
  #expect(try await subject.execute(.maintainCurrentServices(.retireOrphanedServices)) == expected)
  #expect(events.snapshot == ["proxyAgent", "globalAuthority"])
  #expect(maintainer.registerCalls == 0)
  #expect(try await subject.execute(.maintainCurrentServices(.retireOrphanedServices)) == expected)
  #expect(maintainer.unregisterCalls == 2)
}

@Test(arguments: [CurrentSystemProxySwitchStatus.enabled, .unobservable])
func orphanedServiceRetirementRejectsUnprovenNetworkState(
  status: CurrentSystemProxySwitchStatus
) async throws {
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: .off, tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil),
    serviceMaintainer: maintainer,
    systemProxySwitchObserver: StubSystemProxySwitchObserver(observed: status))
  #expect(
    await maintenanceErrorCode(subject, action: .retireOrphanedServices)
      == (status == .enabled ? .busy : .cleanupUnproven))
  #expect(maintainer.unregisterCalls == 0)
}

@Test func orphanedServiceRetirementStopsOnNetworkChangeAndCanResume() async throws {
  let maintainer = StubServiceMaintainer()
  let interrupted = coordinator(
    proxy: .off, tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil),
    serviceMaintainer: maintainer,
    systemProxySwitchObserver: SequencedSystemProxySwitchObserver([.disabled, .disabled, .enabled]))
  #expect(await maintenanceErrorCode(interrupted, action: .retireOrphanedServices) == .busy)
  #expect(maintainer.status(of: .proxyAgent) == .notRegistered)
  #expect(maintainer.status(of: .globalAuthority) == .enabled)
  #expect(maintainer.unregisterCalls == 1)
  let resumed = coordinator(
    proxy: .off, tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil),
    serviceMaintainer: maintainer)
  #expect(await maintenanceErrorCode(resumed, action: .retireOrphanedServices) == nil)
  #expect(maintainer.status(of: .globalAuthority) == .notRegistered)
  #expect(maintainer.unregisterCalls == 2)
}

@Test(arguments: [CurrentAppServiceRuntimeStatus.present, .unobservable])
func orphanedServiceRetirementRequiresTheAuthorityProcessToBeAbsent(
  status: CurrentAppServiceRuntimeStatus
) async throws {
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: .off, tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: SequencedServiceRuntimeObserver(authorityStatuses: [status]))
  #expect(await maintenanceErrorCode(subject, action: .retireOrphanedServices) != nil)
  #expect(maintainer.unregisterCalls == 0)
}

@Test(arguments: [ConfigurationSlot.localProxy, .systemProxy, .tunnel])
func orphanedServiceRetirementRejectsActiveOwners(slot: ConfigurationSlot) async throws {
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: slot.isProxyAgent
      ? .proxyActive(configuration: try descriptor(slot: slot), sequence: 1) : .off,
    tunnel: slot.isProxyAgent
      ? .off : .tunnelActive(configuration: try descriptor(slot: slot), sequence: 1),
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil),
    serviceMaintainer: maintainer)
  #expect(await maintenanceErrorCode(subject, action: .retireOrphanedServices) != nil)
  #expect(maintainer.unregisterCalls == 0)
}
