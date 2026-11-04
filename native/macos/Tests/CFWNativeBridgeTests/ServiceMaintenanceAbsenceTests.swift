import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Maintenance preconditions: every non-Off owner and a pending tunnel preference
// block it, and a process absence is proven stable before the Authority changes.
@Test func maintenanceRejectsEveryNonOffNativeOwnerBeforeMutation() async throws {
  let proxyDescriptor = try descriptor(slot: .systemProxy)
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let failure = EngineFailure(
    code: "fixture_failed", message: "retained owner", isRetryable: false)
  let cases: [(proxy: EngineSnapshot, tunnel: EngineSnapshot)] = [
    (
      .proxyActive(configuration: proxyDescriptor, sequence: 1),
      .off
    ),
    (
      .proxyFailed(failure, configuration: proxyDescriptor, sequence: 2),
      .off
    ),
    (
      .off,
      .tunnelActive(configuration: tunnelDescriptor, sequence: 3)
    ),
    (
      .off,
      .tunnelFailed(failure, configuration: tunnelDescriptor, sequence: 4)
    ),
  ]

  for item in cases {
    let maintainer = StubServiceMaintainer()
    let subject = coordinator(
      proxy: item.proxy,
      tunnel: item.tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: maintainer
    )
    #expect(
      await maintenanceErrorCode(subject, action: .unregisterProxyAgent) == .busy)
    #expect(maintainer.registerCalls == 0)
    #expect(maintainer.unregisterCalls == 0)
  }
}

@Test func pendingTunnelPreferenceBlocksMaintenanceBeforeMutation() async throws {
  let maintainer = StubServiceMaintainer()
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    pendingPreference: try descriptor(slot: .tunnel),
    serviceMaintainer: maintainer
  )
  #expect(
    await maintenanceErrorCode(subject, action: .unregisterProxyAgent)
      == .cleanupUnproven)
  #expect(maintainer.registerCalls == 0)
  #expect(maintainer.unregisterCalls == 0)
}

@Test func unregisteredProxyRequiresStableProcessAbsenceBeforeAuthorityMutation() async {
  for status in [
    CurrentAppServiceRuntimeStatus.present,
    CurrentAppServiceRuntimeStatus.unobservable,
  ] {
    let maintainer = StubServiceMaintainer(
      proxy: .notRegistered, authority: .enabled)
    let subject = coordinator(
      proxy: .off,
      tunnel: .off,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      serviceMaintainer: maintainer,
      serviceRuntimeObserver: StubServiceRuntimeObserver(proxy: status)
    )
    #expect(
      await maintenanceErrorCode(subject, action: .unregisterGlobalAuthority)
        != nil)
    #expect(maintainer.registerCalls == 0)
    #expect(maintainer.unregisterCalls == 0)
  }
}

@Test func processAbsenceProofRejectsConcurrentRegistrationDrift() async {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered, authority: .enabled)
  let observer = StubServiceRuntimeObserver { service in
    if service == .proxyAgent {
      _ = try? maintainer.perform(.register, on: .proxyAgent)
    }
  }
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: observer
  )
  #expect(
    await maintenanceErrorCode(subject, action: .unregisterGlobalAuthority)
      == .cleanupUnproven)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 0)
}

@Test func absentAuthorityRetryExplicitlyReprovesOffAndReturnsToAbsent() async throws {
  let ledger = EventLedger()
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered,
    authority: .notRegistered,
    onPerform: { mutation, service in
      guard service == .globalAuthority else { return }
      ledger.append(
        mutation == .register ? "register_authority" : "unregister_authority")
    })
  let runtimeObserver = StubServiceRuntimeObserver { service in
    if service == .globalAuthority {
      ledger.append("authority_absence")
    }
  }
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    onAuthorityObservation: {
      ledger.append("authority_off")
    },
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: runtimeObserver
  )

  guard
    case .serviceMaintenance(let result) = try await subject.execute(
      .maintainCurrentServices(.unregisterGlobalAuthority))
  else {
    Issue.record("authority retry returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == .off)
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.globalAuthority == .notRegistered)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 1)
  #expect(
    ledger.snapshot == [
      "authority_absence",
      "register_authority",
      "authority_off",
      "unregister_authority",
      "authority_absence",
      "authority_absence",
    ])
}

@Test func absentAuthorityRetryDoesNotUnregisterWhenDurableStateIsActive() async {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered, authority: .notRegistered)
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .active, lease: nil),
    serviceMaintainer: maintainer
  )

  #expect(
    await maintenanceErrorCode(subject, action: .unregisterGlobalAuthority) == .busy)
  #expect(maintainer.registerCalls == 1)
  #expect(maintainer.unregisterCalls == 0)
  #expect(maintainer.status(of: .globalAuthority) == .enabled)
}

@Test func authorityAbsenceFailureEmitsNoReceiptAndRetryConvergesForward() async throws {
  let maintainer = StubServiceMaintainer(
    proxy: .notRegistered, authority: .notRegistered)
  let first = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: SequencedServiceRuntimeObserver(
      authorityStatuses: [.absent, .unobservable])
  )
  #expect(
    await maintenanceErrorCode(first, action: .unregisterGlobalAuthority)
      == .cleanupUnproven)
  #expect(maintainer.status(of: .globalAuthority) == .notRegistered)

  let retry = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer
  )
  guard
    case .serviceMaintenance(let result) = try await retry.execute(
      .maintainCurrentServices(.unregisterGlobalAuthority))
  else {
    Issue.record("authority absence retry returned the wrong result kind")
    return
  }
  #expect(result.engineStatus == .off)
  #expect(result.globalAuthority == .notRegistered)
  #expect(maintainer.registerCalls == 2)
  #expect(maintainer.unregisterCalls == 2)
}

@Test func unregisterWaitsForProxyProcessToReachStableAbsence() async throws {
  let maintainer = StubServiceMaintainer()
  let observer = SequencedServiceRuntimeObserver(
    proxyStatuses: [.present, .absent])
  let subject = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil),
    serviceMaintainer: maintainer,
    serviceRuntimeObserver: observer
  )
  guard
    case .serviceMaintenance(let result) = try await subject.execute(
      .maintainCurrentServices(.unregisterProxyAgent))
  else {
    Issue.record("proxy unregister returned the wrong result kind")
    return
  }
  #expect(result.proxyAgent == .notRegistered)
  #expect(result.engineStatus == .off)
}
