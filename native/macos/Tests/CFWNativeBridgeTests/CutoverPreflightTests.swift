import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
import Testing

@testable import CFWNativeBridge
@testable import CFWSharedProtocol

private actor RecordingProxyAgent: ProxyAgentTransporting {
  private let observedSnapshot: EngineSnapshot
  private let rejectsValidation: Bool
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private(set) var validationCalls = 0

  init(
    observedSnapshot: EngineSnapshot = .off,
    rejectsValidation: Bool = false
  ) {
    self.observedSnapshot = observedSnapshot
    self.rejectsValidation = rejectsValidation
  }

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

  func stop(configuration: ConfigurationDescriptor) throws {
    _ = configuration
    stopCalls += 1
  }

  func snapshot() -> EngineSnapshot { observedSnapshot }

  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws {
    _ = descriptor
    #expect(!configuration.isEmpty)
    validationCalls += 1
    if rejectsValidation {
      throw ProxyAgentHostError.agentFailure(
        EngineFailure(
          code: "configuration-rejected",
          message: "Source-built libbox rejected the configuration.",
          isRetryable: false
        )
      )
    }
  }

  func mutationCounts() -> (Int, Int) { (startCalls, stopCalls) }
  func validationCount() -> Int { validationCalls }
}

private actor RecordingTunnelHost: TunnelHostBridging {
  private var installResults: [SystemExtensionInstallResult]
  private let managedConfiguration: ConfigurationDescriptor?
  private(set) var installCalls = 0
  private(set) var cancelCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0

  init(
    installResult: SystemExtensionInstallResult = .completed,
    managedConfiguration: ConfigurationDescriptor? = nil
  ) {
    installResults = [installResult]
    self.managedConfiguration = managedConfiguration
  }

  init(installResults: [SystemExtensionInstallResult]) {
    self.installResults = installResults
    managedConfiguration = nil
  }

  func installTunnel() throws -> SystemExtensionInstallResult {
    installCalls += 1
    guard !installResults.isEmpty else {
      throw AppleNetworkError.unknownSystemExtensionResult(-1)
    }
    return installResults.removeFirst()
  }

  func cancelTunnelInstallationWait() { cancelCalls += 1 }

  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {
    _ = configuration
    _ = descriptor
    _ = credentialPayload
    startCalls += 1
  }

  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {
    _ = expectedConfiguration
    stopCalls += 1
  }

  func snapshot() -> EngineSnapshot { .off }
  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { managedConfiguration }

  func mutationCounts() -> (install: Int, cancel: Int, start: Int, stop: Int) {
    (installCalls, cancelCalls, startCalls, stopCalls)
  }
}

private struct AvailableEngineLease: NativeEngineLeaseInspecting {
  func isAvailable() async throws -> Bool { true }
  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
}

private final class RecordingGarbageCollectionVault:
  NativeCredentialVaulting, @unchecked Sendable
{
  private let lock = NSLock()
  private var previewReferences: [CredentialReference] = []

  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CFWCredentialVault.CredentialVaultReceipt {
    _ = requiredReferences
    _ = material
    return CFWCredentialVault.CredentialVaultReceipt(audience: audience)
  }

  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CFWCredentialVault.CredentialPresence] {
    references.map { CFWCredentialVault.CredentialPresence(reference: $0, present: true) }
  }

  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial {
    _ = slots
    return .empty
  }

  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    lock.withLock { previewReferences = request.catalog.flatMap(\.references) }
    return try CredentialGarbageCollectionPreview(
      snapshotDigest: request.snapshotDigest,
      vaultRevision: #require(
        UUID(uuidString: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
      ),
      orphanBindings: []
    )
  }

  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    _ = request
    throw CredentialVaultError.garbageCollectionConfirmationExpired
  }

  func capturedReferences() -> [CredentialReference] {
    lock.withLock { previewReferences }
  }
}

private final class EmptyCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CFWCredentialVault.CredentialVaultReceipt {
    _ = requiredReferences
    _ = material
    return CFWCredentialVault.CredentialVaultReceipt(audience: audience)
  }

  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CFWCredentialVault.CredentialPresence] {
    references.map {
      CFWCredentialVault.CredentialPresence(reference: $0, present: false)
    }
  }

  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial {
    guard slots.isEmpty else {
      throw CredentialMaterialError.missingReference(slots[0].reference.id)
    }
    return .empty
  }

  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    _ = request
    throw CredentialVaultError.missingVault
  }

  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    _ = request
    throw CredentialVaultError.missingVault
  }
}

private func makeCoordinator(
  proxy: any ProxyAgentTransporting,
  tunnel: any TunnelHostBridging,
  credentialVault: any NativeCredentialVaulting
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: proxy,
    systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: tunnel,
    engineLease: AvailableEngineLease(),
    credentialVault: credentialVault
  )
}

private struct PreflightIdentityDocument: Encodable {
  let configurationSHA256: String
  let credentialAudience: CredentialAudience
  let credentialSlots: [CredentialSlot]
  let mode: String
  let networkOptions: TunnelNetworkOptions?
  let schemaVersion: UInt16

  private enum CodingKeys: String, CodingKey {
    case configurationSHA256 = "configuration_sha256"
    case credentialAudience = "credential_audience"
    case credentialSlots = "credential_slots"
    case mode
    case networkOptions = "network_options"
    case schemaVersion = "schema_version"
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(configurationSHA256, forKey: .configurationSHA256)
    try container.encode(credentialAudience, forKey: .credentialAudience)
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

private func sha256(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  )
}

private func preflightRequest(target: EngineMode = .tunnel) throws -> CutoverPreflightRequest {
  let context = try EngineCommandContext(
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    configEpoch: 2,
    generation: 7
  )
  let audience = CredentialAudience(
    profileID: try #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
    profileDigest: try CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
  let configuration = Data(
    #"{"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}"#.utf8
  )
  let contentDigest = try sha256(configuration)
  let tunnelOptions = try TunnelNetworkOptions(ipv6Enabled: true)

  func request(options: TunnelNetworkOptions?) throws -> EngineStartRequest {
    let identity = PreflightIdentityDocument(
      configurationSHA256: contentDigest.hex,
      credentialAudience: audience,
      credentialSlots: [],
      mode: options == nil ? "system_proxy" : "tunnel",
      networkOptions: options,
      schemaVersion: NativeProtocolConstants.schemaVersion
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try EngineStartRequest(
      context: context,
      credentialAudience: audience,
      configJSON: String(decoding: configuration, as: UTF8.self),
      configContentDigest: contentDigest,
      configDigest: sha256(encoder.encode(identity)),
      credentialSlots: [],
      tunnelOptions: options
    )
  }

  return try CutoverPreflightRequest(
    target: target,
    systemProxyRequest: request(options: nil),
    tunnelRequest: request(options: tunnelOptions)
  )
}

@Test func cutoverPreflightChecksBothConfigsAndNeverStartsADataPlane() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost()
  let coordinator = makeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  let result = try await coordinator.execute(.preflightCutover(preflightRequest()))
  guard case .cutoverPreflight(.ready(let attestation)) = result else {
    Issue.record("preflight did not return a ready attestation")
    return
  }
  #expect(attestation.target == .tunnel)
  #expect(attestation.validForMillis == 300_000)
  #expect(await proxy.validationCount() == 2)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 1, cancel: 0, start: 0, stop: 0))
}

@Test func failedConfigPreflightLeavesInstallAndDataPlaneUntouched() async throws {
  let proxy = RecordingProxyAgent(rejectsValidation: true)
  let tunnel = RecordingTunnelHost()
  let coordinator = makeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  await #expect(throws: (any Error).self) {
    try await coordinator.execute(.preflightCutover(preflightRequest()))
  }
  #expect(await proxy.validationCount() == 1)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

@Test func systemProxyPreflightNeverRequestsSystemExtensionInstallation() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost()
  let coordinator = makeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  let result = try await coordinator.execute(
    .preflightCutover(preflightRequest(target: .systemProxy))
  )
  guard case .cutoverPreflight(.ready(let attestation)) = result else {
    Issue.record("System Proxy preflight did not return readiness")
    return
  }
  #expect(attestation.target == .systemProxy)
  #expect(await proxy.validationCount() == 2)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

@Test func approvalRetryReconcilesLateCompletionWithoutStartingTunnel() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost(installResults: [.awaitingApproval, .completed])
  let coordinator = makeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )
  let request = try preflightRequest()

  let first = try await coordinator.execute(.preflightCutover(request))
  guard case .cutoverPreflight(.awaitingApproval) = first else {
    Issue.record("first preflight did not surface approval")
    return
  }
  let second = try await coordinator.execute(.preflightCutover(request))
  guard case .cutoverPreflight(.ready) = second else {
    Issue.record("approved retry did not return readiness")
    return
  }
  #expect(await proxy.validationCount() == 4)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 2, cancel: 1, start: 0, stop: 0))
}

@Test func nonOffNativeStateBlocksPreflightBeforeValidationOrInstallation() async throws {
  let proxy = RecordingProxyAgent(
    observedSnapshot: .proxyFailed(
      EngineFailure(code: "owned", message: "retained", isRetryable: false),
      configuration: nil,
      sequence: 1
    )
  )
  let tunnel = RecordingTunnelHost()
  let coordinator = makeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: EmptyCredentialVault()
  )

  await #expect(throws: (any Error).self) {
    try await coordinator.execute(.preflightCutover(preflightRequest()))
  }
  #expect(await proxy.validationCount() == 0)
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

private func descriptor(
  slot: ConfigurationSlot,
  reference: CredentialReference
) throws -> ConfigurationDescriptor {
  let digest = try CFWSharedProtocol.SHA256Digest(hex: String(repeating: "12", count: 32))
  let target: CredentialTarget =
    reference.kind == .trojanPassword ? .trojanPassword : .shadowsocksPassword
  let credentialSlot = try CredentialSlot(
    reference: reference,
    target: target,
    outboundIndex: 0,
    jsonPointer: "/outbounds/0/password"
  )
  return try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: slot == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil,
    credentialAudience: CredentialAudience(
      profileID: #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
      profileDigest: CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32))),
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    epoch: 2,
    generation: 7,
    byteCount: 2,
    sha256: digest,
    identitySHA256: digest,
    credentialSlots: [credentialSlot]
  )
}

@Test func garbageCollectionProtectsActiveAndManagedTunnelCredentialReferences() async throws {
  let activeReference = CredentialReference(
    id: try #require(UUID(uuidString: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")),
    kind: .trojanPassword
  )
  let pendingReference = CredentialReference(
    id: try #require(UUID(uuidString: "cccccccc-cccc-4ccc-8ccc-cccccccccccc")),
    kind: .shadowsocksPassword
  )
  let activeDescriptor = try descriptor(slot: .systemProxy, reference: activeReference)
  let pendingDescriptor = try descriptor(slot: .tunnel, reference: pendingReference)
  let proxy = RecordingProxyAgent(
    observedSnapshot: .proxyActive(configuration: activeDescriptor, sequence: 1)
  )
  let tunnel = RecordingTunnelHost(
    managedConfiguration: pendingDescriptor
  )
  let vault = RecordingGarbageCollectionVault()
  let coordinator = makeCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: vault
  )
  let request = try CredentialGarbageCollectionRequest(
    snapshotDigest: CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32)),
    catalog: []
  )

  _ = try await coordinator.execute(.previewCredentialGarbageCollection(request))
  #expect(vault.capturedReferences() == [activeReference, pendingReference])
}
