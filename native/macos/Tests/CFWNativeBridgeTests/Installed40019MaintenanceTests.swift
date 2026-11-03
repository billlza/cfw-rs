import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Maintenance of an installed 40019: legacy Off reproved before each mutation,
// its real transport's classification, and recovery after interruptions.
@Test func installed40019MaintenanceSequenceReprovesLegacyOffBeforeEachMutation()
  async throws
{
  let ledger = EventLedger()
  let maintainer = StubServiceMaintainer { mutation, service in
    guard mutation == .unregister else { return }
    ledger.append(
      service == .proxyAgent ? "unregister_proxy" : "unregister_authority")
  }
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    onAuthorityObservation: { ledger.append("authority_off") },
    serviceMaintainer: maintainer
  )

  for action in [
    NativeServiceMaintenanceAction.proveInstalled40019Off,
    .unregisterInstalled40019ProxyAgent,
    .unregisterInstalled40019GlobalAuthority,
  ] {
    guard
      case .serviceMaintenance(let result) = try await subject.execute(
        .maintainCurrentServices(action))
    else {
      Issue.record("installed 40019 maintenance returned the wrong result")
      return
    }
    #expect(result.action == action)
    #expect(result.engineStatus == .off)
    #expect(
      result.offProofProfile == .installed40019EngineV5AuthorityV10)
  }

  #expect(
    ledger.snapshot == [
      "authority_off",
      "authority_off",
      "unregister_proxy",
      "authority_off",
      "authority_off",
      "unregister_authority",
    ])
  #expect(maintainer.unregisterCalls == 2)
  #expect(maintainer.registerCalls == 0)
}

@Test func installed40019NonOffProofNeverReachesServiceMutation() async throws {
  let descriptor = try descriptor(slot: .systemProxy)
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: .proxyActive(configuration: descriptor, sequence: 1),
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )

  #expect(
    await maintenanceErrorCode(
      subject, action: .unregisterInstalled40019ProxyAgent) == .busy)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.registerCalls == 0)
}

@Test func installed40019RealTransportClassifiesActiveAndFailedAsBusy() async throws {
  let active = EngineSnapshot.proxyActive(
    configuration: try descriptor(slot: .systemProxy),
    sequence: 1
  )
  let failed = try EngineSnapshot(
    mode: .off,
    state: .failed(
      EngineFailure(code: "test-failure", message: "test failure", isRetryable: false)
    ),
    configuration: nil,
    sequence: 1
  )

  for snapshot in [active, failed] {
    let maintainer = StubServiceMaintainer()
    let subject = coordinator(
      proxy: .off,
      tunnel: .off,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      installed40019Proxy: try realInstalled40019ProxyTransport(snapshot: snapshot),
      serviceMaintainer: maintainer
    )
    #expect(
      await maintenanceErrorCode(
        subject,
        action: .unregisterInstalled40019ProxyAgent
      ) == .busy
    )
    #expect(maintainer.unregisterCalls == 0)
    #expect(maintainer.registerCalls == 0)
  }
}

@Test func installed40019LostAuthorityReceiptUsesExplicitCurrentRecoveryProfile()
  async throws
{
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered,
    authority: .notRegistered)
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: StubServiceRuntimeObserver()
  )

  guard
    case .serviceMaintenance(let result) = try await subject.execute(
      .maintainCurrentServices(.recoverInstalled40019GlobalAuthority))
  else {
    Issue.record("installed 40019 recovery returned the wrong result")
    return
  }

  #expect(result.engineStatus == .off)
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.globalAuthority == .notRegistered)
  #expect(
    result.offProofProfile == .installed40019RecoveryCurrentAuthorityV11)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 1)
}

@Test func installed40019RecoveryConvergesAfterCurrentAuthorityRegisterInterruption()
  async throws
{
  let interruption = FailAfterFirstAuthorityRegister()
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered,
    authority: .notRegistered,
    onPerform: interruption.check)
  let first = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: StubServiceRuntimeObserver()
  )

  await #expect(throws: (any Error).self) {
    _ = try await first.execute(
      .maintainCurrentServices(.recoverInstalled40019GlobalAuthority))
  }
  #expect(maintainer.status(of: .globalAuthority) == .enabled)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 0)

  let retry = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: StubServiceRuntimeObserver()
  )
  guard
    case .serviceMaintenance(let result) = try await retry.execute(
      .maintainCurrentServices(.recoverInstalled40019GlobalAuthority))
  else {
    Issue.record("installed 40019 recovery retry returned the wrong result")
    return
  }
  #expect(result.offProofProfile == .installed40019RecoveryCurrentAuthorityV11)
  #expect(maintainer.status(of: .globalAuthority) == .notRegistered)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 1)
}

@Test func installed40019LegacyAuthorityActionDoesNotRepairAnAbsentService() async {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered,
    authority: .notRegistered)
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: StubServiceRuntimeObserver()
  )

  #expect(
    await maintenanceErrorCode(
      subject,
      action: .unregisterInstalled40019GlobalAuthority) == .cleanupUnproven)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
}
