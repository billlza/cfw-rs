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

// Builders for the start command tests: the credential vault, requests and
// their contexts, the coordinator, recovered stops, the readiness clocks, and
// failure expectations.
final class StartCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
  private let lock = NSLock()
  private var resolutions = 0
  var resolutionCount: Int { lock.withLock { resolutions } }
  private let material: CredentialMaterial
  init(material: CredentialMaterial = .empty) { self.material = material }
  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CredentialVaultReceipt {
    throw CredentialVaultError.missingVault
  }
  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CredentialPresence] { [] }
  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial {
    lock.withLock { resolutions += 1 }
    let expected = Set(slots.map { $0.reference.id })
    guard expected == Set(material.entries.map { $0.reference.id }) else {
      throw CredentialVaultError.missingVault
    }
    return material
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

func startRequest(
  tunnelOptions: TunnelNetworkOptions?,
  mode: NativeStartMode? = nil,
  generation: UInt64 = 7,
  credentialSlots: [CredentialSlot] = [],
  configuration: Data? = nil
) throws -> EngineStartRequest {
  let mode =
    mode
    ?? (tunnelOptions == nil
      ? .systemProxy : (tunnelOptions?.systemProxyPort == nil ? .tunnel : .tunnelSystemProxy))
  let configuration =
    configuration
    ?? Data(
      (mode == .localProxy
        ? #"{"inbounds":[{"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":7891}],"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}"#
        : #"{"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}"#).utf8)
  let context = try EngineCommandContext(
    installationID: #require(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
    configEpoch: 2,
    generation: generation)
  let contentDigest = try sha256(configuration)
  let audience = CredentialAudience(
    profileID: try #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
    profileDigest: try CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32)))
  let identity = IdentityDocument(
    configurationSHA256: contentDigest.hex,
    credentialAudience: audience,
    credentialSlots: credentialSlots,
    mode: mode == .localProxy ? "local_proxy" : (mode == .systemProxy ? "system_proxy" : "tunnel"),
    networkOptions: tunnelOptions,
    schemaVersion: NativeProtocolConstants.schemaVersion)
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  return try EngineStartRequest(
    mode: mode,
    context: context,
    credentialAudience: audience,
    configJSON: String(decoding: configuration, as: UTF8.self),
    configContentDigest: contentDigest,
    configDigest: try sha256(encoder.encode(identity)),
    credentialSlots: credentialSlots,
    tunnelOptions: tunnelOptions)
}

/// The request's installation and epoch at `generation`.
func context(
  _ request: EngineStartRequest, generation: UInt64
) throws -> EngineCommandContext {
  try EngineCommandContext(
    installationID: request.context.installationID,
    configEpoch: request.context.configEpoch, generation: generation)
}

func recoveredStop(
  for descriptor: ConfigurationDescriptor,
  ownerUID: UInt32 = 501
) throws -> NativeRecoveredStop {
  let mode = descriptor.slot.authorityMode
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch,
      generation: descriptor.generation),
    mode: mode,
    configSHA256: descriptor.sha256,
    identitySHA256: descriptor.identitySHA256,
    ownerUID: ownerUID,
    authorityRevision: 1)
  return try NativeRecoveredStop(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()))
}

func makeCoordinator(
  proxy: any ProxyAgentTransporting,
  tunnel: any TunnelHostBridging,
  observation: AuthorityOwnershipObservation,
  systemProxyPreparer: any SystemProxyStartPreparing = UnusedSystemProxyStartPreparer(),
  engineLease: (any NativeEngineLeaseInspecting)? = nil,
  credentialVault: any NativeCredentialVaulting = StartCredentialVault(),
  serviceBuildObserver: any CurrentAppServiceBuildObserving = FixedCurrentServiceBuildObserver(),
  serviceMaintainer: any CurrentAppServiceMaintaining = CurrentAppServiceMaintainer(),
  serviceRuntimeObserver: any CurrentAppServiceRuntimeObserving =
    ServiceUpgradeAbsentRuntimeObserver(),
  systemProxySwitchObserver: any CurrentSystemProxySwitchObserving =
    ServiceUpgradeDisabledProxyObserver(),
  armTunnelReadinessDeadline: (@Sendable (Duration) -> NativeReadinessDeadline)? = nil
) -> NativeBridgeCoordinator {
  let engineLease = engineLease ?? FixedEngineLease(observation: observation)
  let systemProxyPreparer: any SystemProxyStartPreparing =
    (engineLease as? RecordingEngineLease).map {
      CursorAdvancingSystemProxyStartPreparer(preparer: systemProxyPreparer, lease: $0)
    } ?? systemProxyPreparer
  guard let armTunnelReadinessDeadline else {
    return NativeBridgeCoordinator(
      proxy: proxy,
      systemProxyPreparer: systemProxyPreparer,
      tunnel: tunnel,
      engineLease: engineLease,
      credentialVault: credentialVault,
      hostOperationLease: AvailableNativeHostOperationLease(),
      serviceMaintainer: serviceMaintainer,
      serviceRuntimeObserver: serviceRuntimeObserver,
      systemProxySwitchObserver: systemProxySwitchObserver,
      serviceBuildObserver: serviceBuildObserver)
  }
  return NativeBridgeCoordinator(
    proxy: proxy,
    systemProxyPreparer: systemProxyPreparer,
    tunnel: tunnel,
    engineLease: engineLease,
    credentialVault: credentialVault,
    hostOperationLease: AvailableNativeHostOperationLease(),
    serviceMaintainer: serviceMaintainer,
    serviceRuntimeObserver: serviceRuntimeObserver,
    systemProxySwitchObserver: systemProxySwitchObserver,
    serviceBuildObserver: serviceBuildObserver,
    armTunnelReadinessDeadline: armTunnelReadinessDeadline)
}

/// Arms readiness deadlines whose clock reaches the end after a fixed number of
/// checks and records the length each wait asked for.
final class RecordedReadinessDeadlines: @unchecked Sendable {
  private let lock = NSLock()
  private var requested: [Duration] = []
  private var checks = 0
  private let checksBeforePassing: Int

  init(checksBeforePassing: Int) {
    self.checksBeforePassing = checksBeforePassing
  }

  var arm: @Sendable (Duration) -> NativeReadinessDeadline {
    { length in
      self.lock.withLock { self.requested.append(length) }
      let start = SuspendingClock.now
      let end = start.advanced(by: length)
      return NativeReadinessDeadline(end: end) {
        self.lock.withLock {
          self.checks += 1
          return self.checks > self.checksBeforePassing ? end : start
        }
      }
    }
  }

  var lengths: [Duration] { lock.withLock { requested } }

  var checkCount: Int { lock.withLock { checks } }
}

/// A readiness clock the test moves by hand.
final class ManualSuspendingClock: @unchecked Sendable {
  private let lock = NSLock()
  private var instant: SuspendingClock.Instant

  init(_ instant: SuspendingClock.Instant) { self.instant = instant }

  var now: SuspendingClock.Instant {
    get { lock.withLock { instant } }
    set { lock.withLock { instant = newValue } }
  }
}

/// Executes a command that is expected to fail closed and returns the stable typed
/// failure code, or records an issue if the command unexpectedly succeeded.
func failureCode(
  _ coordinator: NativeBridgeCoordinator,
  _ command: NativeBridgeCommand
) async -> NativeBridgeErrorCode? {
  await failure(coordinator, command)?.code
}

/// A failed start's cleanup receipt is one-use. The preparation the failed
/// start had left the Authority's cursor at its generation, so a stop repeated
/// after the receipt is spent proves that generation Off again through the
/// Authority, instead of using the receipt.
func expectRepeatedStopProvesOffAgain(
  _ coordinator: NativeBridgeCoordinator,
  _ stop: NativeBridgeCommand,
  lease: RecordingEngineLease
) async throws {
  let recoveries = await lease.recoverCount()
  guard case .acknowledged = try await coordinator.execute(stop) else {
    Issue.record("a repeated stop of a generation proven Off was not acknowledged")
    return
  }
  #expect(await lease.recoverCount() == recoveries + 1)
}

/// The Host's own failure, with the message the bridge response replaces by
/// its code's stable message.
func failure(
  _ coordinator: NativeBridgeCoordinator,
  _ command: NativeBridgeCommand
) async -> (code: NativeBridgeErrorCode, message: String)? {
  do {
    _ = try await coordinator.execute(command)
    Issue.record("expected a fail-closed error but the command succeeded")
    return nil
  } catch let error as NativeBridgeExecutionError {
    switch error {
    case .failure(let code, let message): return (code, message)
    }
  } catch {
    Issue.record("expected a typed NativeBridgeExecutionError, got \(error)")
    return nil
  }
}

// MARK: - Tests
