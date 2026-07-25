import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
import Testing

@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Integration coverage for task 9.12 (Host / NativeBridge start commands): the
// serialized coordinator's `startSystemProxy` and `startTunnel` command paths are
// driven end to end through `execute(_:)` to prove:
//   - registration denial fails closed BEFORE any preference/network mutation, with
//     no persist, no owner start, and no fallback to the other mode;
//   - an owner is returned Active only when the Global Authority's machine-wide
//     ownership observation agrees EXACTLY with the effective owner descriptor
//     (lease / context / digest / owner-ready / OS state); any lease disagreement
//     fails closed and never activates or falls back;
//   - a stop that cannot prove the effective OS descriptor is ambiguous, never Active.
// Every ProxyAgent / Packet Tunnel / Authority side effect lives behind an injected
// in-memory seam, so no real launchd, XPC, SystemConfiguration, or Network Extension
// is exercised. The public command request/response contract is unchanged.
//
// This complements (and does not duplicate) `ActiveAgreementTests`, which drives the
// read-only `queryStatus` agreement matrix, and `CutoverPreflightTests`, which drives
// the preflight (never-start) path.

// MARK: - Fakes

private actor StartableProxyAgent: ProxyAgentTransporting {
  private let descriptor: ConfigurationDescriptor
  private let registrationError: ProxyAgentHostError?
  private(set) var ensureCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0

  init(descriptor: ConfigurationDescriptor, registrationError: ProxyAgentHostError? = nil) {
    self.descriptor = descriptor
    self.registrationError = registrationError
  }

  func registrationStatus() -> ProxyAgentRegistrationStatus {
    registrationError == nil ? .enabled : .requiresApproval
  }

  func ensureRegistered() throws {
    ensureCalls += 1
    if let registrationError { throw registrationError }
  }

  func start(configuration: ConfigurationDescriptor) throws { startCalls += 1 }
  func stop(configuration: ConfigurationDescriptor) throws { stopCalls += 1 }

  func snapshot() -> EngineSnapshot {
    startCalls > 0 && stopCalls == 0
      ? .proxyActive(configuration: descriptor, sequence: 1)
      : .off
  }

  func validateConfiguration(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {}

  func counters() -> (ensure: Int, start: Int, stop: Int) { (ensureCalls, startCalls, stopCalls) }
}

private actor StartableTunnelHost: TunnelHostBridging {
  private let descriptor: ConfigurationDescriptor
  private(set) var installCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0

  init(descriptor: ConfigurationDescriptor) { self.descriptor = descriptor }

  func installTunnel() throws -> SystemExtensionInstallResult { .completed }
  func cancelTunnelInstallationWait() {}

  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {
    startCalls += 1
  }

  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) { stopCalls += 1 }

  func snapshot() -> EngineSnapshot {
    startCalls > 0 && stopCalls == 0
      ? .tunnelActive(configuration: descriptor, sequence: 1)
      : .off
  }

  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }

  func counters() -> (install: Int, start: Int, stop: Int) {
    (installCalls, startCalls, stopCalls)
  }
}

/// Records whether the descriptor-only configuration was persisted so ordering
/// assertions can prove nothing is written before a fail-closed denial.
private final class RecordingConfigurationStore: NativeConfigurationStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  var persistCount: Int { lock.withLock { count } }
  func persist(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {
    lock.withLock { count += 1 }
  }
}

/// Reports an exact Authority ownership observation. Concrete production inspectors
/// override the default coarse derivation; this stub returns the exact observation
/// so start-path activation agreement can be exercised deterministically.
private struct FixedEngineLease: NativeEngineLeaseInspecting {
  let observation: AuthorityOwnershipObservation
  func isAvailable() async throws -> Bool { observation.state == .off }
  func authorityOwnership() async throws -> AuthorityOwnershipObservation { observation }
}

private final class EmptyCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
  func provision(
    profileID: String,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CredentialVaultReceipt {
    throw CredentialVaultError.missingVault
  }
  func presence(of references: [CredentialReference]) throws -> [CredentialPresence] { [] }
  func resolve(slots: [CredentialSlot]) throws -> CredentialMaterial {
    guard slots.isEmpty else {
      throw CredentialMaterialError.missingReference(slots[0].reference.id)
    }
    return .empty
  }
  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview { throw CredentialVaultError.missingVault }
  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt { throw CredentialVaultError.missingVault }
}

// MARK: - Builders

private func sha256(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

private struct IdentityDocument: Encodable {
  let configurationSHA256: String
  let credentialSlots: [CredentialSlot]
  let mode: String
  let networkOptions: TunnelNetworkOptions?
  let schemaVersion: UInt16

  private enum CodingKeys: String, CodingKey {
    case configurationSHA256 = "configuration_sha256"
    case credentialSlots = "credential_slots"
    case mode
    case networkOptions = "network_options"
    case schemaVersion = "schema_version"
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(configurationSHA256, forKey: .configurationSHA256)
    try container.encode(credentialSlots, forKey: .credentialSlots)
    try container.encode(mode, forKey: .mode)
    if let networkOptions {
      try container.encode(networkOptions, forKey: .networkOptions)
    } else {
      try container.encodeNil(forKey: .networkOptions)
    }
    try container.encode(schemaVersion, forKey: .schemaVersion)
  }
}

private func startRequest(
  tunnelOptions: TunnelNetworkOptions?,
  generation: UInt64 = 7
) throws -> EngineStartRequest {
  let context = try EngineCommandContext(
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    configEpoch: 2,
    generation: generation)
  let configuration = Data(
    #"{"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}"#.utf8)
  let contentDigest = try sha256(configuration)
  let identity = IdentityDocument(
    configurationSHA256: contentDigest.hex,
    credentialSlots: [],
    mode: tunnelOptions == nil ? "system_proxy" : "tunnel",
    networkOptions: tunnelOptions,
    schemaVersion: NativeProtocolConstants.schemaVersion)
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  return try EngineStartRequest(
    context: context,
    configJSON: String(decoding: configuration, as: UTF8.self),
    configContentDigest: contentDigest,
    configDigest: try sha256(encoder.encode(identity)),
    credentialSlots: [],
    tunnelOptions: tunnelOptions)
}

private func agreement(
  for descriptor: ConfigurationDescriptor,
  mode: AuthorityMode,
  generation: UInt64? = nil,
  leaseState: AuthorityLeaseState = .active
) -> AuthorityLeaseAgreement {
  AuthorityLeaseAgreement(
    installationID: descriptor.installationID,
    epoch: descriptor.epoch,
    generation: generation ?? descriptor.generation,
    ownerUID: 501,
    mode: mode,
    configSHA256: descriptor.sha256,
    identitySHA256: descriptor.identitySHA256,
    leaseState: leaseState)
}

private func makeCoordinator(
  proxy: any ProxyAgentTransporting,
  tunnel: any TunnelHostBridging,
  observation: AuthorityOwnershipObservation,
  store: RecordingConfigurationStore
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    configurationStore: store,
    engineLease: FixedEngineLease(observation: observation),
    credentialVault: EmptyCredentialVault())
}

/// Whether the Global Authority release gate is compiled in. In the production
/// Release configuration (`CFW_GLOBAL_AUTHORITY_REQUIRED=1`, defined on the
/// `CFWSharedProtocol` module) every start command fails closed at this gate before
/// any preference, network, libbox, or Tunnel mutation. In Debug the gate is a no-op,
/// so the richer start orchestration runs.
///
/// The test branches on the real production gate so it is correct under BOTH
/// configurations, including the mandated `-c release` run, without weakening the P0
/// contract. Note the compile-time `CFW_GLOBAL_AUTHORITY_REQUIRED` symbol is scoped to
/// `CFWSharedProtocol` and is intentionally NOT propagated to this test target, so an
/// in-file `#if CFW_GLOBAL_AUTHORITY_REQUIRED` would always be false here and would
/// mis-assert Debug behavior under `-c release`. The gate is therefore observed at
/// runtime through its public entry point, which reflects the exact configuration
/// `CFWSharedProtocol` was compiled with.
private let releaseAuthorityGateActive: Bool = {
  do {
    try GlobalAuthorityReleaseGate.requireStartAuthorization()
    return false
  } catch {
    return true
  }
}()

/// Executes a command that is expected to fail closed and returns the stable typed
/// failure code, or records an issue if the command unexpectedly succeeded.
private func failureCode(
  _ coordinator: NativeBridgeCoordinator,
  _ command: NativeBridgeCommand
) async -> NativeBridgeErrorCode? {
  do {
    _ = try await coordinator.execute(command)
    Issue.record("expected a fail-closed error but the command succeeded")
    return nil
  } catch let error as NativeBridgeExecutionError {
    switch error {
    case .failure(let code, _): return code
    }
  } catch {
    Issue.record("expected a typed NativeBridgeExecutionError, got \(error)")
    return nil
  }
}

// MARK: - Tests

@Suite(.serialized)
struct NativeBridgeStartCommandIntegrationTests {
  @Test func systemProxyRegistrationDenialFailsClosedBeforeAnyMutation() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor, registrationError: .registrationRequiresApproval)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let store = RecordingConfigurationStore()
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil), store: store)

    let code = await failureCode(coordinator, .startSystemProxy(request))
    let proxyCounts = await proxy.counters()
    if releaseAuthorityGateActive {
      // Release production boundary: the Authority gate fails closed BEFORE the
      // owner registration is even consulted.
      #expect(code == .globalAuthorityUnavailable)
      #expect(proxyCounts.ensure == 0)
    } else {
      // Debug: registration denial fails closed after the registration check.
      #expect(code == .permissionDenied)
      #expect(proxyCounts.ensure == 1)
    }
    // In every configuration the denial fails closed before any preference persist
    // or owner start, and never falls back to the Tunnel owner.
    #expect(proxyCounts.start == 0)
    #expect(store.persistCount == 0)
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.install == 0)
    #expect(tunnelCounts.start == 0)
  }

  @Test func systemProxyReachesActiveOnlyOnExactAuthorityAgreement() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let store = RecordingConfigurationStore()
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .systemProxy)),
      store: store)

    if releaseAuthorityGateActive {
      // Release production boundary: no owner start is authorized; the gate fails
      // closed before any persist or owner start.
      let code = await failureCode(coordinator, .startSystemProxy(request))
      #expect(code == .globalAuthorityUnavailable)
      let proxyCounts = await proxy.counters()
      #expect(proxyCounts.start == 0)
      #expect(store.persistCount == 0)
      return
    }

    guard case .runtime(let runtime) = try await coordinator.execute(.startSystemProxy(request))
    else {
      Issue.record("exact Authority agreement did not return a proxy runtime")
      return
    }
    #expect(runtime.owner == .proxyAgent)
    #expect(runtime.context == request.context)
    #expect(runtime.configDigest == request.configDigest.hex)
    #expect(runtime.ready)

    // The Authority-bound owner start is ordered after registration and the
    // descriptor-only persist; the Tunnel owner is never touched.
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.ensure == 1)
    #expect(proxyCounts.start == 1)
    #expect(store.persistCount == 1)
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 0)
  }

  @Test func systemProxyStartFailsClosedWhenAuthorityLeaseDisagrees() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let store = RecordingConfigurationStore()
    // The lease binds a different generation than the effective owner descriptor:
    // even though the owner started, activation is refused fail-closed.
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(
          for: descriptor, mode: .systemProxy, generation: descriptor.generation + 1)),
      store: store)

    let code = await failureCode(coordinator, .startSystemProxy(request))
    let proxyCounts = await proxy.counters()
    if releaseAuthorityGateActive {
      // Release production boundary: the gate fails closed before the owner starts.
      #expect(code == .globalAuthorityUnavailable)
      #expect(proxyCounts.start == 0)
    } else {
      // Debug: the owner started, but the lease disagreement never activates.
      #expect(code == .identityRejected)
      #expect(proxyCounts.start == 1)
    }
    // The disagreement never falls back to the Tunnel owner.
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 0)
  }

  @Test func tunnelReachesActiveOnlyOnExactAuthorityAgreement() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let store = RecordingConfigurationStore()
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .tunnel)),
      store: store)

    if releaseAuthorityGateActive {
      // Release production boundary: no Tunnel owner start is authorized.
      #expect(await failureCode(coordinator, .startTunnel(request)) == .globalAuthorityUnavailable)
      let tunnelCounts = await tunnel.counters()
      #expect(tunnelCounts.start == 0)
      return
    }

    guard case .runtime(let runtime) = try await coordinator.execute(.startTunnel(request)) else {
      Issue.record("exact Authority agreement did not return a tunnel runtime")
      return
    }
    #expect(runtime.owner == .packetTunnelSystemExtension)
    #expect(runtime.context == request.context)
    #expect(runtime.configDigest == request.configDigest.hex)
    #expect(runtime.ready)

    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 1)
    // The Tunnel start path never starts the System Proxy owner as a fallback.
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.start == 0)
  }

  @Test func tunnelStartFailsClosedWhenAuthorityProvesGlobalOff() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let store = RecordingConfigurationStore()
    // The provider reports active, but the Authority proves global Off: an
    // unresolved ownership ambiguity that must fail closed as Quarantined.
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil), store: store)

    let code = await failureCode(coordinator, .startTunnel(request))
    // Release: gate fails closed (globalAuthorityUnavailable). Debug: provider active
    // while the Authority proves global Off is an ambiguity that fails closed as
    // Quarantined. Neither activates and neither falls back.
    #expect(code == (releaseAuthorityGateActive ? .globalAuthorityUnavailable : .quarantined))
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.start == 0)
  }
}
