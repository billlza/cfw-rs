import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Deterministic coverage for task 5.2: an owner is classified Active only when the
// Global_Lease, Operation_Context, owner-ready attestation, configuration digest,
// and effective OS state agree exactly. Every single mismatch must fail closed as
// Failed, Recovering, or Quarantined — never Active and never Off from ambiguity.
// All OS/XPC/Authority side effects are behind in-memory fakes: no real
// NetworkExtension, SystemConfiguration, or launchd is exercised.

@Test func tunnelActiveOnlyOnExactFiveWayAgreement() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: tunnelDescriptor, mode: .tunnel)
    )
  )

  guard case .status(.tunnel(let runtime)) = try await coordinator.execute(.queryStatus) else {
    Issue.record("exact five-way agreement did not classify Tunnel Active")
    return
  }
  #expect(runtime.owner == .packetTunnelSystemExtension)
  #expect(runtime.configDigest == tunnelDescriptor.identitySHA256.hex)
  #expect(runtime.context.installationID == fixtureInstallationID)
  #expect(runtime.context.generation == generation)
  #expect(runtime.ready)
}

@Test func systemProxyActiveOnlyOnExactFiveWayAgreement() async throws {
  let proxyDescriptor = try descriptor(slot: .systemProxy)
  let coordinator = coordinator(
    proxy: .proxyActive(configuration: proxyDescriptor, sequence: 2),
    tunnel: .off,
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: proxyDescriptor, mode: .systemProxy)
    )
  )

  guard
    case .status(.systemProxy(let runtime)) =
      try await coordinator.execute(.queryStatus)
  else {
    Issue.record("exact five-way agreement did not classify System Proxy Active")
    return
  }
  #expect(runtime.owner == .proxyAgent)
  #expect(runtime.configDigest == proxyDescriptor.identitySHA256.hex)
}

@Test func leaseContextMismatchIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      // Authority lease is bound to a different generation than the OS descriptor.
      lease: agreement(for: tunnelDescriptor, mode: .tunnel, generation: generation + 1)
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

@Test func wrongConfigurationDigestIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(
        for: tunnelDescriptor,
        mode: .tunnel,
        configSHA256: try digest("ef")
      )
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

@Test func missingReadyAttestationIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      // The owner is bound but has not yet attested ready (lease not Active).
      lease: agreement(for: tunnelDescriptor, mode: .tunnel, leaseState: .bound)
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}

@Test func osStateNotConnectedIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let starting = try EngineSnapshot(
    mode: .tunnel,
    state: EngineState(kind: .tunnelStarting),
    configuration: tunnelDescriptor,
    sequence: 1
  )
  let coordinator = coordinator(
    proxy: .off,
    tunnel: starting,
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: tunnelDescriptor, mode: .tunnel)
    )
  )
  // Effective OS state is not connected: the machine is transitional, not Active.
  #expect(await statusErrorCode(coordinator) == .busy)
}

@Test func snapshotStateNotActiveIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let active = EngineSnapshot.tunnelActive(configuration: tunnelDescriptor, sequence: 3)

  let recovering = coordinator(
    proxy: .off,
    tunnel: active,
    observation: AuthorityOwnershipObservation(state: .recovering, lease: nil)
  )
  #expect(await statusErrorCode(recovering) == .globalAuthorityRecovering)

  let quarantined = coordinator(
    proxy: .off,
    tunnel: active,
    observation: AuthorityOwnershipObservation(state: .quarantined, lease: nil)
  )
  #expect(await statusErrorCode(quarantined) == .quarantined)

  // Authority proves global Off while the OS shows an active owner: ambiguity that
  // must fail closed as Quarantined, never Active and never Off.
  let ambiguousOff = coordinator(
    proxy: .off,
    tunnel: active,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil)
  )
  #expect(await statusErrorCode(ambiguousOff) == .quarantined)
}

@Test func offOnlyWhenAuthorityProvesGlobalOff() async throws {
  let allOff = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .off, lease: nil)
  )
  guard case .status(.off) = try await allOff.execute(.queryStatus) else {
    Issue.record("stable Off with proven Authority Off did not classify Off")
    return
  }

  // Owners are Off but the Authority still holds/prepares a lease: not Off.
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let leaseHeld = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(for: tunnelDescriptor, mode: .tunnel)
    )
  )
  #expect(await statusErrorCode(leaseHeld) == .busy)

  let recovering = coordinator(
    proxy: .off,
    tunnel: .off,
    observation: AuthorityOwnershipObservation(state: .recovering, lease: nil)
  )
  #expect(await statusErrorCode(recovering) == .globalAuthorityRecovering)
}

@Test func installationLineageMismatchIsNeverActive() async throws {
  let tunnelDescriptor = try descriptor(slot: .tunnel)
  let coordinator = coordinator(
    proxy: .off,
    tunnel: .tunnelActive(configuration: tunnelDescriptor, sequence: 3),
    observation: AuthorityOwnershipObservation(
      state: .active,
      lease: agreement(
        for: tunnelDescriptor,
        mode: .tunnel,
        installationID: otherInstallationID
      )
    )
  )
  #expect(await statusErrorCode(coordinator) == .identityRejected)
}
