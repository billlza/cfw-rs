import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import Foundation
import Testing

@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Deterministic coverage for task 5.2: an owner is classified Active only when the
// Global_Lease, Operation_Context, owner-ready attestation, configuration digest,
// and effective OS state agree exactly. Every single mismatch must fail closed as
// Failed, Recovering, or Quarantined — never Active and never Off from ambiguity.
// All OS/XPC/Authority side effects are behind in-memory fakes: no real
// NetworkExtension, SystemConfiguration, or launchd is exercised.

private let installationID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
private let otherInstallationID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
private let epoch: UInt64 = 4
private let generation: UInt64 = 9

private func digest(_ byte: String) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(hex: String(repeating: byte, count: 32))
}

private func descriptor(
  slot: ConfigurationSlot,
  epoch: UInt64 = epoch,
  generation: UInt64 = generation,
  installationID: UUID = installationID,
  config: String = "ab",
  identity: String = "cd"
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: slot == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil,
    credentialAudience: CredentialAudience(
      profileID: installationID,
      profileDigest: digest("ee")),
    installationID: installationID,
    epoch: epoch,
    generation: generation,
    byteCount: 42,
    sha256: digest(config),
    identitySHA256: digest(identity)
  )
}

private func agreement(
  for descriptor: ConfigurationDescriptor,
  mode: AuthorityMode,
  leaseState: AuthorityLeaseState = .active,
  epoch: UInt64? = nil,
  generation: UInt64? = nil,
  installationID: UUID? = nil,
  configSHA256: CFWSharedProtocol.SHA256Digest? = nil,
  identitySHA256: CFWSharedProtocol.SHA256Digest? = nil
) -> AuthorityLeaseAgreement {
  AuthorityLeaseAgreement(
    installationID: installationID ?? descriptor.installationID,
    epoch: epoch ?? descriptor.epoch,
    generation: generation ?? descriptor.generation,
    ownerUID: 501,
    mode: mode,
    configSHA256: configSHA256 ?? descriptor.sha256,
    identitySHA256: identitySHA256 ?? descriptor.identitySHA256,
    leaseState: leaseState
  )
}

private struct StubLease: NativeEngineLeaseInspecting {
  let observation: AuthorityOwnershipObservation
  func isAvailable() async throws -> Bool { observation.state == .off }
  func authorityOwnership() async throws -> AuthorityOwnershipObservation { observation }
  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
}

private actor StubProxyAgent: ProxyAgentTransporting {
  let observed: EngineSnapshot
  init(_ observed: EngineSnapshot) { self.observed = observed }
  func registrationStatus() -> ProxyAgentRegistrationStatus { .notRegistered }
  func ensureRegistered() throws {}
  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) throws {
    _ = configuration
    _ = descriptor
    authorization.erase()
    throw UnusedSystemProxyStartPreparerError.unexpectedInvocation
  }
  func stop(configuration: ConfigurationDescriptor) throws {}
  func snapshot() -> EngineSnapshot { observed }
  func validateConfiguration(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {}
}

private actor StubTunnelHost: TunnelHostBridging {
  let observed: EngineSnapshot
  init(_ observed: EngineSnapshot) { self.observed = observed }
  func installTunnel() throws -> SystemExtensionInstallResult { .completed }
  func cancelTunnelInstallationWait() {}
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {}
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {}
  func snapshot() -> EngineSnapshot { observed }
  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }
}

private final class StubCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CFWCredentialVault.CredentialVaultReceipt {
    throw CredentialVaultError.missingVault
  }
  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CFWCredentialVault.CredentialPresence] { [] }
  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial { .empty }
  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    throw CredentialVaultError.missingVault
  }
  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    throw CredentialVaultError.missingVault
  }
}

private func coordinator(
  proxy: EngineSnapshot,
  tunnel: EngineSnapshot,
  observation: AuthorityOwnershipObservation
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: StubProxyAgent(proxy),
    systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: StubTunnelHost(tunnel),
    engineLease: StubLease(observation: observation),
    credentialVault: StubCredentialVault()
  )
}

private func statusErrorCode(
  _ coordinator: NativeBridgeCoordinator
) async -> NativeBridgeErrorCode? {
  do {
    _ = try await coordinator.execute(.queryStatus)
    return nil
  } catch let error as NativeBridgeExecutionError {
    switch error {
    case .failure(let code, _): return code
    }
  } catch {
    return nil
  }
}

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
  #expect(runtime.context.installationID == installationID)
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
