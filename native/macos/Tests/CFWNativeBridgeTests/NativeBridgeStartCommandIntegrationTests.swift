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

// Integration coverage for task 9.12 (Host / NativeBridge start commands): the
// serialized coordinator's `startSystemProxy` and `startTunnel` command paths are
// driven end to end through `execute(_:)` to prove:
//   - registration denial fails closed BEFORE any preference/network mutation, with
//     no runtime-byte transfer, no owner start, and no fallback to the other mode;
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

private func waitUntil(_ condition: @escaping @Sendable () async -> Bool) async -> Bool {
  for _ in 0..<1_000 {
    if await condition() { return true }
    await Task.yield()
  }
  return false
}

private final class NativeCleanupEventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [String] = []
  func append(_ value: String) { lock.withLock { values.append(value) } }
  var events: [String] { lock.withLock { values } }
}

// MARK: - Fakes

private actor RecordingSystemProxyStartPreparer: SystemProxyStartPreparing {
  private(set) var prepareCalls = 0
  private(set) var cancelCalls = 0

  func prepareSystemProxyStart(
    configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws -> HostPreparedSystemProxyStart {
    guard !configuration.isEmpty, descriptor.slot == .systemProxy else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    prepareCalls += 1
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: AuthorityIdentifier(descriptor.installationID),
        epoch: descriptor.epoch,
        generation: descriptor.generation),
      mode: .systemProxy,
      configSHA256: descriptor.sha256,
      identitySHA256: descriptor.identitySHA256,
      ownerUID: 501,
      authorityRevision: 1)
    return HostPreparedSystemProxyStart(
      context: try ProxyOwnerContext(
        operation: operation,
        leaseID: AuthorityIdentifier(UUID())),
      capability: try OwnerCapability(
        copying: Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes)))
  }

  func cancelSystemProxyStart(
    _ prepared: HostPreparedSystemProxyStart
  ) {
    cancelCalls += 1
    prepared.erase()
  }

  func counters() -> (prepare: Int, cancel: Int) {
    (prepareCalls, cancelCalls)
  }
}

private actor StartableProxyAgent: ProxyAgentTransporting {
  private let descriptor: ConfigurationDescriptor
  private let registrationError: ProxyAgentHostError?
  private let blocksSnapshot: Bool
  private var registered: Bool
  private var snapshotWait: CheckedContinuation<Void, Never>?
  private(set) var ensureCalls = 0
  private(set) var snapshotCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private(set) var startContexts: [ProxyOwnerContext] = []
  private(set) var startConfigurationDigests: [String] = []

  init(
    descriptor: ConfigurationDescriptor,
    registrationError: ProxyAgentHostError? = nil,
    initiallyRegistered: Bool = true,
    blocksSnapshot: Bool = false
  ) {
    self.descriptor = descriptor
    self.registrationError = registrationError
    registered = initiallyRegistered
    self.blocksSnapshot = blocksSnapshot
  }

  func registrationStatus() -> ProxyAgentRegistrationStatus {
    if registrationError != nil { return .requiresApproval }
    return registered ? .enabled : .notRegistered
  }

  func ensureRegistered() throws {
    ensureCalls += 1
    if let registrationError { throw registrationError }
    registered = true
  }

  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) throws {
    try descriptor.validateConfigurationBytes(configuration)
    let context = authorization.context
    guard
      context.operation.root.installationID.rawValue == descriptor.installationID,
      context.operation.root.epoch == descriptor.epoch,
      context.operation.root.generation == descriptor.generation,
      context.operation.configSHA256 == descriptor.sha256,
      context.operation.identitySHA256 == descriptor.identitySHA256
    else {
      authorization.erase()
      throw ProxyAgentHostError.malformedResponse
    }
    var capability = try authorization.consumeCapabilityData()
    defer {
      capability.resetBytes(in: capability.startIndex..<capability.endIndex)
      capability.removeAll(keepingCapacity: false)
    }
    guard capability.count == AuthorityV1Limits.capabilityBytes else {
      throw ProxyAgentHostError.malformedResponse
    }
    startContexts.append(context)
    startConfigurationDigests.append(
      SHA256.hash(data: configuration).map { String(format: "%02x", $0) }.joined())
    startCalls += 1
  }
  func stop(configuration: ConfigurationDescriptor) throws { stopCalls += 1 }

  func snapshot() async throws -> EngineSnapshot {
    snapshotCalls += 1
    if blocksSnapshot {
      await withCheckedContinuation { continuation in
        snapshotWait = continuation
      }
    }
    guard registered else { throw ProxyAgentHostError.registrationUnavailable }
    return startCalls > 0 && stopCalls == 0
      ? .proxyActive(configuration: descriptor, sequence: 1)
      : .off
  }

  func validateConfiguration(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {}

  func counters() -> (ensure: Int, snapshot: Int, start: Int, stop: Int) {
    (ensureCalls, snapshotCalls, startCalls, stopCalls)
  }
  func hasPendingSnapshot() -> Bool { snapshotWait != nil }
  func releaseSnapshot() {
    let continuation = snapshotWait
    snapshotWait = nil
    continuation?.resume()
  }
  func authorizedContexts() -> [ProxyOwnerContext] { startContexts }
  func transferredConfigurationDigests() -> [String] { startConfigurationDigests }
}

private actor StartableTunnelHost: TunnelHostBridging {
  private let descriptor: ConfigurationDescriptor
  private let recoveryStatus: RecoveryManagedTunnelStatus
  private let startError: AppleNetworkError?
  private let installResult: SystemExtensionInstallResult
  private let installError: AppleNetworkError?
  private let cleanupEvents: NativeCleanupEventLog?
  private(set) var installCalls = 0
  private(set) var cancelInstallCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private var started = false
  private var pendingPreferenceDescriptor: ConfigurationDescriptor?
  private(set) var compensationCalls = 0
  private(set) var finishCompensationCalls = 0

  init(
    descriptor: ConfigurationDescriptor,
    recoveryStatus: RecoveryManagedTunnelStatus = .disconnected,
    startError: AppleNetworkError? = nil,
    installResult: SystemExtensionInstallResult = .completed,
    installError: AppleNetworkError? = nil,
    pendingPreferenceDescriptor: ConfigurationDescriptor? = nil,
    cleanupEvents: NativeCleanupEventLog? = nil
  ) {
    self.descriptor = descriptor
    self.recoveryStatus = recoveryStatus
    self.startError = startError
    self.installResult = installResult
    self.installError = installError
    self.pendingPreferenceDescriptor = pendingPreferenceDescriptor
    self.cleanupEvents = cleanupEvents
  }

  func installTunnel() throws -> SystemExtensionInstallResult {
    installCalls += 1
    if let installError { throw installError }
    return installResult
  }
  func cancelTunnelInstallationWait() { cancelInstallCalls += 1 }

  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) throws {
    startCalls += 1
    if let startError { throw startError }
    started = true
  }

  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {
    stopCalls += 1
    started = false
  }

  func snapshot() -> EngineSnapshot {
    started
      ? .tunnelActive(configuration: descriptor, sequence: 1)
      : .off
  }

  func recoveryManagedTunnelStatus() -> RecoveryManagedTunnelStatus {
    recoveryStatus
  }

  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }
  func pendingPreferenceMutationConfiguration() -> ConfigurationDescriptor? {
    pendingPreferenceDescriptor
  }
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool {
    guard pendingPreferenceDescriptor == expectedConfiguration else { return false }
    try await revokePreparation()
    compensationCalls += 1
    started = false
    cleanupEvents?.append("compensate-preferences")
    return true
  }
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {
    guard pendingPreferenceDescriptor == expectedConfiguration else { return }
    finishCompensationCalls += 1
    pendingPreferenceDescriptor = nil
    cleanupEvents?.append("finish-preferences")
  }
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) {}

  func counters() -> (install: Int, start: Int, stop: Int) {
    (installCalls, startCalls, stopCalls)
  }
  func cancelInstallCount() -> Int { cancelInstallCalls }
  func compensationCounts() -> (compensate: Int, finish: Int) {
    (compensationCalls, finishCompensationCalls)
  }
  func injectPendingPreferenceMutation(_ descriptor: ConfigurationDescriptor) {
    pendingPreferenceDescriptor = descriptor
  }
}

/// Holds the first installation callback open until the test releases it as a
/// typed timeout, then completes the exact-generation retry. This exercises the
/// coordinator mutation lifetime without relying on a real System Extension.
private actor BlockingRetryableInstallationTunnelHost: TunnelHostBridging {
  private let descriptor: ConfigurationDescriptor
  private var firstWait: CheckedContinuation<Void, Never>?
  private(set) var installCalls = 0

  init(descriptor: ConfigurationDescriptor) {
    self.descriptor = descriptor
  }

  func installTunnel() async throws -> SystemExtensionInstallResult {
    installCalls += 1
    if installCalls == 1 {
      await withCheckedContinuation { continuation in
        firstWait = continuation
      }
      throw AppleNetworkError.systemExtensionInstallationTimedOut
    }
    return .completed
  }

  func hasPendingFirstWait() -> Bool { firstWait != nil }

  func releaseFirstWait() {
    let continuation = firstWait
    firstWait = nil
    continuation?.resume()
  }

  func cancelTunnelInstallationWait() {}
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {}
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {}
  func snapshot() -> EngineSnapshot { .off }
  func recoveryManagedTunnelStatus() -> RecoveryManagedTunnelStatus { .disconnected }
  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }
  func pendingPreferenceMutationConfiguration() -> ConfigurationDescriptor? { nil }
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool { false }
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {}
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) {}
}

/// Reports an exact Authority ownership observation. Concrete production inspectors
/// override the default coarse derivation; this stub returns the exact observation
/// so start-path activation agreement can be exercised deterministically.
private struct FixedEngineLease: NativeEngineLeaseInspecting {
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

private actor RecordingEngineLease: NativeEngineLeaseInspecting {
  private var observation: AuthorityOwnershipObservation
  private var remainingCompleteFailures: Int
  private let recoveredStop: NativeRecoveredStop?
  private let completeError: AuthorityDomainError?
  private let completeFailureCommits: Bool
  private let cancelPreparedResult: Bool
  private let cleanupEvents: NativeCleanupEventLog?
  private var stopContext: NativeAuthorityStopContext?
  private(set) var beginCalls = 0
  private(set) var completeCalls = 0
  private(set) var reconcileCalls = 0
  private(set) var recoverCalls = 0
  private(set) var cancelPreparedCalls = 0

  init(
    observation: AuthorityOwnershipObservation,
    completeFailures: Int = 0,
    recoveredStop: NativeRecoveredStop? = nil,
    completeError: AuthorityDomainError? = nil,
    completeFailureCommits: Bool = false,
    cancelPreparedResult: Bool = false,
    cleanupEvents: NativeCleanupEventLog? = nil
  ) {
    self.observation = observation
    remainingCompleteFailures = completeFailures
    self.recoveredStop = recoveredStop
    self.completeError = completeError
    self.completeFailureCommits = completeFailureCommits
    self.cancelPreparedResult = cancelPreparedResult
    self.cleanupEvents = cleanupEvents
  }

  func isAvailable() -> Bool { observation.state == .off }

  func authorityOwnership() -> AuthorityOwnershipObservation { observation }

  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) throws -> AuthorityOwnershipObservation {
    reconcileCalls += 1
    guard observation.state == .recovering,
      managedTunnel == .disconnected || managedTunnel == .invalid
    else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    return observation
  }

  func recoverStoppingLease() -> NativeRecoveredStop? {
    recoverCalls += 1
    return recoveredStop
  }

  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) -> Bool {
    cancelPreparedCalls += 1
    cleanupEvents?.append("cancel-prepared")
    if cancelPreparedResult {
      observation = AuthorityOwnershipObservation(state: .off, lease: nil)
    }
    return cancelPreparedResult
  }

  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) throws -> NativeAuthorityStopContext {
    beginCalls += 1
    cleanupEvents?.append("begin-stop")
    if let stopContext { return stopContext }
    let mode: AuthorityMode = descriptor.slot == .systemProxy ? .systemProxy : .tunnel
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: AuthorityIdentifier(descriptor.installationID),
        epoch: descriptor.epoch,
        generation: descriptor.generation),
      mode: mode,
      configSHA256: descriptor.sha256,
      identitySHA256: descriptor.identitySHA256,
      ownerUID: 501,
      authorityRevision: 1)
    let context = NativeAuthorityStopContext(
      operation: operation,
      leaseID: AuthorityIdentifier(UUID()))
    stopContext = context
    return context
  }

  func completeStop(_ context: NativeAuthorityStopContext) throws {
    completeCalls += 1
    cleanupEvents?.append("complete-stop")
    if let completeError { throw completeError }
    if remainingCompleteFailures > 0 {
      remainingCompleteFailures -= 1
      if completeFailureCommits {
        observation = AuthorityOwnershipObservation(state: .off, lease: nil)
      }
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "Injected Authority complete-stop failure.")
    }
    observation = AuthorityOwnershipObservation(state: .off, lease: nil)
  }

  func counters() -> (begin: Int, complete: Int) {
    (beginCalls, completeCalls)
  }

  func reconcileCount() -> Int { reconcileCalls }
  func recoverCount() -> Int { recoverCalls }
  func cancelPreparedCount() -> Int { cancelPreparedCalls }
  func currentState() -> AuthorityState { observation.state }
}

private final class EmptyCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
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
  let audience = CredentialAudience(
    profileID: try #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
    profileDigest: try CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32)))
  let identity = IdentityDocument(
    configurationSHA256: contentDigest.hex,
    credentialAudience: audience,
    credentialSlots: [],
    mode: tunnelOptions == nil ? "system_proxy" : "tunnel",
    networkOptions: tunnelOptions,
    schemaVersion: NativeProtocolConstants.schemaVersion)
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  return try EngineStartRequest(
    context: context,
    credentialAudience: audience,
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

private func recoveredStop(
  for descriptor: ConfigurationDescriptor,
  ownerUID: UInt32 = 501
) throws -> NativeRecoveredStop {
  let mode: AuthorityMode = descriptor.slot == .systemProxy ? .systemProxy : .tunnel
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

private func makeCoordinator(
  proxy: any ProxyAgentTransporting,
  tunnel: any TunnelHostBridging,
  observation: AuthorityOwnershipObservation,
  systemProxyPreparer: any SystemProxyStartPreparing = UnusedSystemProxyStartPreparer(),
  engineLease: (any NativeEngineLeaseInspecting)? = nil
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: proxy,
    systemProxyPreparer: systemProxyPreparer,
    tunnel: tunnel,
    engineLease: engineLease ?? FixedEngineLease(observation: observation),
    credentialVault: EmptyCredentialVault(),
    hostOperationLease: AvailableNativeHostOperationLease())
}

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
  @Test func directIPv4HostRouteParticipatesInTheNativeConfigurationIdentity() throws {
    let ordinary = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true)
    )
    let excluded = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(
        ipv6Enabled: true,
        directIPv4Hosts: [TunnelNetworkOptions.releasePacketTransportIPv4]
      )
    )

    #expect(ordinary.configJSON == excluded.configJSON)
    #expect(ordinary.configContentDigest == excluded.configContentDigest)
    #expect(ordinary.configDigest != excluded.configDigest)
    #expect(excluded.tunnelOptions?.directIPv4Hosts == ["35.194.216.98"])
  }

  @Test func preferenceNSErrorMappingPreservesProvenanceAndIgnoresDiagnosticPolicy() {
    #expect(
      NativeBridgeCoordinator.map(AppleNetworkError.preferenceMutationUncertain)
        .responseFailure.code == .busy)
    #expect(
      NativeBridgeCoordinator.map(
        AppleNetworkError.preferenceMutationJournalUnavailable("injected")
      ).responseFailure.code == .cleanupUnproven)
    let permission = NetworkExtensionOperationFailure(
      domain: NSPOSIXErrorDomain,
      code: Int(POSIXErrorCode.EPERM.rawValue),
      diagnostic: "operation not permitted"
    )
    let permissionFailure = NativeBridgeCoordinator.map(
      AppleNetworkError.preferenceSaveFailed(permission)
    )
    let permissionCode: NativeBridgeErrorCode
    let permissionMessage: String
    switch permissionFailure {
    case .failure(let code, let message):
      permissionCode = code
      permissionMessage = message
    }
    #expect(permissionCode == .permissionDenied)
    #expect(permissionMessage.contains("preference save failed"))
    #expect(!permissionMessage.contains("(operation)"))
    #expect(permissionMessage.contains("\(permission.domain):\(permission.code)"))

    let readWrite = NetworkExtensionOperationFailure(
      domain: NEVPNErrorDomain,
      code: NEVPNError.configurationReadWriteFailed.rawValue,
      diagnostic: "permission denied text must not change classification"
    )
    let readWriteFailure = NativeBridgeCoordinator.map(
      AppleNetworkError.preferenceLoadFailed(readWrite)
    )
    let readWriteCode: NativeBridgeErrorCode
    let readWriteMessage: String
    switch readWriteFailure {
    case .failure(let code, let message):
      readWriteCode = code
      readWriteMessage = message
    }
    #expect(readWriteCode == .unavailable)
    #expect(readWriteMessage.contains("preference load failed"))
    #expect(!readWriteMessage.contains("(operation)"))
    #expect(readWriteMessage.contains("\(readWrite.domain):\(readWrite.code)"))

    let authorizationRequired = NativeBridgeCoordinator.map(
      AppleNetworkError.systemExtensionInstallationFailed(
        domain: OSSystemExtensionErrorDomain,
        code: OSSystemExtensionError.authorizationRequired.rawValue,
        message: "authorization required"
      )
    ).responseFailure
    #expect(authorizationRequired.code == .approvalDenied)
    let unknownSystemExtensionFailure = NativeBridgeCoordinator.map(
      AppleNetworkError.systemExtensionInstallationFailed(
        domain: OSSystemExtensionErrorDomain,
        code: OSSystemExtensionError.unknown.rawValue,
        message: "authorization required text is not policy"
      )
    ).responseFailure
    #expect(unknownSystemExtensionFailure.code == .unavailable)
  }

  @Test func staleMutationCompletionCannotReleaseANewerMutation() async throws {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: StartableTunnelHost(descriptor: descriptor),
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    let firstMutation = try await coordinator.beginMutation()
    await coordinator.endMutation(firstMutation)
    let secondMutation = try await coordinator.beginMutation()
    await coordinator.endMutation(firstMutation)
    #expect(await coordinator.activeOperation == secondMutation)
    await coordinator.endMutation(secondMutation)
    #expect(await coordinator.activeOperation == nil)
  }

  @Test func installationTimeoutReleasesMutationAndAllowsExactConcurrentRetry()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = BlockingRetryableInstallationTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    let first = Task<NativeBridgeErrorCode?, Never> {
      await failureCode(coordinator, .installTunnel(request.context))
    }
    #expect(await waitUntil { await tunnel.hasPendingFirstWait() })

    // While the exact OS callback wait is unresolved, a reentrant mutation fails
    // Busy instead of starting a parallel System Extension request or projecting
    // a status through an incomplete mutation boundary.
    #expect(await failureCode(coordinator, .queryStatus) == .busy)
    #expect(await failureCode(coordinator, .installTunnel(request.context)) == .busy)
    await tunnel.releaseFirstWait()
    #expect(await first.value == .timeout)

    let differentContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(
      await failureCode(coordinator, .installTunnel(differentContext)) == .busy)

    guard
      case .tunnelInstall(.ready) = try await coordinator.execute(
        .installTunnel(request.context))
    else {
      Issue.record("exact-generation installation retry did not complete")
      return
    }
    #expect(await tunnel.installCalls == 2)
  }

  @Test func externalStatusRetainsOperationOwnershipAcrossReentrantOwnerQueries()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      blocksSnapshot: true)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    let status = Task<Bool, Never> {
      do {
        guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
          return false
        }
        return true
      } catch {
        return false
      }
    }
    #expect(await waitUntil { await proxy.hasPendingSnapshot() })
    #expect(await failureCode(coordinator, .installTunnel(request.context)) == .busy)
    await proxy.releaseSnapshot()
    #expect(await status.value)
  }

  @Test func terminalTunnelInstallationFailureRetainsAnExactCancelableReceipt()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      installResult: .requiresRestart)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    #expect(await failureCode(coordinator, .installTunnel(request.context)) == .unavailable)
    let wrongContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(
      await failureCode(coordinator, .cancelTunnelInstall(wrongContext))
        == .identityRejected)
    guard
      case .acknowledged = try await coordinator.execute(
        .cancelTunnelInstall(request.context))
    else {
      Issue.record("exact terminal installation receipt was not acknowledged")
      return
    }
    #expect(await tunnel.cancelInstallCount() == 1)
    #expect(
      await failureCode(coordinator, .cancelTunnelInstall(request.context))
        == .identityRejected)
  }

  @Test func failedTunnelPreparationCancelsExactlyAndTheRustStopReceiptIsOneUse()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      startError: .preferenceSaveFailed(
        NetworkExtensionOperationFailure(
          domain: NEVPNErrorDomain,
          code: NEVPNError.configurationReadWriteFailed.rawValue,
          diagnostic: "injected"
        )
      ))
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .preparing,
        lease: agreement(
          for: descriptor,
          mode: .tunnel,
          leaseState: .prepared)),
      cancelPreparedResult: true)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .unavailable)
    #expect(await lease.cancelPreparedCount() == 1)
    #expect((await tunnel.counters()).stop == 0)

    #expect(await failureCode(coordinator, .startTunnel(request)) == .cleanupUnproven)
    let wrongContext = try EngineCommandContext(
      installationID: request.context.installationID,
      configEpoch: request.context.configEpoch,
      generation: request.context.generation + 1)
    #expect(await failureCode(coordinator, .stopTunnel(wrongContext)) == .identityRejected)

    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("exact compensated Tunnel stop was not acknowledged")
      return
    }
    #expect(await failureCode(coordinator, .stopTunnel(request.context)) == .identityRejected)
  }

  @Test func firstStatusFailsClosedOnRecoveredPreferenceWriteAheadReceipt()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let cleanupEvents = NativeCleanupEventLog()
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      pendingPreferenceDescriptor: descriptor,
      cleanupEvents: cleanupEvents)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .preparing,
        lease: agreement(
          for: descriptor,
          mode: .tunnel,
          leaseState: .prepared)),
      cancelPreparedResult: true,
      cleanupEvents: cleanupEvents)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    // A read cannot project either Off or Active around a recovered write-ahead
    // receipt. Recovery belongs to the next serialized mutation boundary.
    #expect(await failureCode(coordinator, .queryStatus) == .cleanupUnproven)
    #expect(await lease.cancelPreparedCount() == 0)
    #expect(await tunnel.compensationCounts() == (compensate: 0, finish: 0))
    #expect(cleanupEvents.events.isEmpty)

    guard
      case .tunnelInstall(.ready) =
        try await coordinator.execute(.installTunnel(request.context))
    else {
      Issue.record("startup preference recovery did not unblock the exact mutation")
      return
    }
    #expect(await lease.cancelPreparedCount() == 2)
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == nil)
    #expect(
      cleanupEvents.events == [
        "cancel-prepared",
        "cancel-prepared",
        "compensate-preferences",
        "finish-preferences",
      ])
  }

  @Test func everyExternalStatusFailsClosedWhileAPreferenceReceiptRemains()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let tunnelDescriptor = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true)
    ).descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: tunnelDescriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("initial external status did not reach proven global Off")
      return
    }
    await tunnel.injectPendingPreferenceMutation(tunnelDescriptor)

    #expect(await failureCode(coordinator, .queryStatus) == .cleanupUnproven)
    #expect((await proxy.counters()).snapshot == 1)
  }

  @Test func ownerControlledStartupRecoveryCompletesAuthorityBeforeClearingJournal()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let cleanupEvents = NativeCleanupEventLog()
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      pendingPreferenceDescriptor: descriptor,
      cleanupEvents: cleanupEvents)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      cancelPreparedResult: false,
      cleanupEvents: cleanupEvents)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    guard
      case .tunnelInstall(.ready) =
        try await coordinator.execute(.installTunnel(request.context))
    else {
      Issue.record("owner-controlled preference recovery did not finish")
      return
    }

    #expect(await lease.cancelPreparedCount() == 1)
    #expect(await lease.counters() == (begin: 2, complete: 1))
    #expect(await lease.currentState() == .off)
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == nil)
    #expect(
      cleanupEvents.events == [
        "cancel-prepared",
        "begin-stop",
        "begin-stop",
        "compensate-preferences",
        "complete-stop",
        "finish-preferences",
      ])
  }

  @Test func startupRecoveryRetriesAfterLostAuthorityCompletionReplyWithoutRecompensating()
    async throws
  {
    let request = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let cleanupEvents = NativeCleanupEventLog()
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      pendingPreferenceDescriptor: descriptor,
      cleanupEvents: cleanupEvents)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      completeFailures: 1,
      completeFailureCommits: true,
      cancelPreparedResult: false,
      cleanupEvents: cleanupEvents)
    let coordinator = makeCoordinator(
      proxy: StartableProxyAgent(descriptor: descriptor),
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    #expect(
      await failureCode(coordinator, .installTunnel(request.context))
        == .unavailable)
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 0))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == descriptor)
    #expect(await lease.currentState() == .off)

    guard
      case .tunnelInstall(.ready) =
        try await coordinator.execute(.installTunnel(request.context))
    else {
      Issue.record("lost Authority completion reply did not remain exactly retryable")
      return
    }
    #expect(await tunnel.compensationCounts() == (compensate: 1, finish: 1))
    #expect(await tunnel.pendingPreferenceMutationConfiguration() == nil)
    #expect(await lease.counters() == (begin: 2, complete: 2))
    #expect(
      cleanupEvents.events == [
        "cancel-prepared",
        "begin-stop",
        "begin-stop",
        "compensate-preferences",
        "complete-stop",
        "complete-stop",
        "finish-preferences",
      ])
  }

  @Test func queryStatusRegistersFreshInstallBeforeProxySnapshotWhenAuthorityIsOff()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      initiallyRegistered: false)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("fresh-install registration did not reach proven global Off")
      return
    }
    let counters = await proxy.counters()
    #expect(counters.ensure == 1)
    #expect(counters.snapshot == 1)
  }

  @Test func queryStatusRegistrationApprovalDenialPrecedesEveryProxySnapshot()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      registrationError: .registrationRequiresApproval,
      initiallyRegistered: false)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    #expect(await failureCode(coordinator, .queryStatus) == .proxyAgentApprovalRequired)
    let counters = await proxy.counters()
    #expect(counters.ensure == 1)
    #expect(counters.snapshot == 0)
  }

  @Test func queryStatusMissingAgentIsTypedUnavailableBeforeProxySnapshot()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor,
      registrationError: .registrationUnavailable,
      initiallyRegistered: false)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))

    #expect(await failureCode(coordinator, .queryStatus) == .unavailable)
    let counters = await proxy.counters()
    #expect(counters.ensure == 1)
    #expect(counters.snapshot == 0)
  }

  @Test func queryStatusCompletesExactPersistedStoppingLeaseAfterHostRestart()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let recovery = try recoveredStop(for: descriptor)
    let stopping = AuthorityOwnershipObservation(
      state: .stopping,
      lease: agreement(
        for: descriptor,
        mode: .systemProxy,
        leaseState: .stopping))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: stopping,
      recoveredStop: recovery)
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: stopping,
      engineLease: lease)

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("exact persisted stopping lease did not complete global Off")
      return
    }
    #expect(recovery.commandContext == request.context)
    #expect(await lease.recoverCount() == 1)
    #expect(await lease.counters() == (begin: 0, complete: 1))
  }

  @Test func queryStatusDoesNotInferOwnerStoppedFromStableOwnerSnapshots()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let recovery = try recoveredStop(for: descriptor)
    let stopping = AuthorityOwnershipObservation(
      state: .stopping,
      lease: agreement(
        for: descriptor,
        mode: .systemProxy,
        leaseState: .stopping))
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: stopping,
      recoveredStop: recovery,
      completeError: AuthorityDomainError(code: .cleanupUnproven))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: stopping,
      engineLease: lease)

    #expect(await failureCode(coordinator, .queryStatus) == .cleanupUnproven)
    #expect(await lease.recoverCount() == 1)
    #expect(await lease.counters() == (begin: 0, complete: 1))
    #expect(await lease.currentState() == .stopping)
  }

  @Test func queryStatusNeverRecoversQuarantinedAuthorityAsOff() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let quarantined = AuthorityOwnershipObservation(state: .quarantined, lease: nil)
    let lease = RecordingEngineLease(
      observation: quarantined,
      recoveredStop: try recoveredStop(for: descriptor))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: quarantined,
      engineLease: lease)

    #expect(await failureCode(coordinator, .queryStatus) == .quarantined)
    #expect(await lease.recoverCount() == 0)
    #expect(await lease.counters() == (begin: 0, complete: 0))
  }

  @Test func queryStatusReconcilesRestartedAuthorityOnlyAfterBothOwnersProveOff()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      recoveryStatus: .disconnected)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil),
      engineLease: lease)

    guard case .status(.off) = try await coordinator.execute(.queryStatus) else {
      Issue.record("exact restart reconciliation did not return global Off")
      return
    }
    #expect((await proxy.counters()).ensure == 1)
    #expect(await lease.reconcileCount() == 1)
  }

  @Test func queryStatusKeepsAuthorityRecoveringForTransitionalManagedTunnel()
    async throws
  {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(
      descriptor: descriptor,
      recoveryStatus: .connecting)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil))
    let coordinator = makeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .recovering, lease: nil),
      engineLease: lease)

    let code = await failureCode(coordinator, .queryStatus)
    #expect(code == .cleanupUnproven)
    #expect(await lease.reconcileCount() == 1)
  }

  @Test func systemProxyRegistrationDenialFailsClosedBeforeAnyMutation() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(
      descriptor: descriptor, registrationError: .registrationRequiresApproval)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      systemProxyPreparer: preparer)

    let code = await failureCode(coordinator, .startSystemProxy(request))
    let proxyCounts = await proxy.counters()
    #expect(code == .proxyAgentApprovalRequired)
    #expect(proxyCounts.ensure == 1)
    #expect(await preparer.counters() == (prepare: 0, cancel: 0))
    // Registration denial fails closed before Authority preparation, runtime-byte
    // transfer, or owner start, and never falls back to the Tunnel owner.
    #expect(proxyCounts.start == 0)
    #expect(await proxy.transferredConfigurationDigests().isEmpty)
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.install == 0)
    #expect(tunnelCounts.start == 0)
  }

  @Test func systemProxyReachesActiveOnlyOnExactAuthorityAgreement() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .systemProxy)),
      systemProxyPreparer: preparer)

    guard case .runtime(let runtime) = try await coordinator.execute(.startSystemProxy(request))
    else {
      Issue.record("exact Authority agreement did not return a proxy runtime")
      return
    }
    #expect(runtime.owner == .proxyAgent)
    #expect(runtime.context == request.context)
    #expect(runtime.configDigest == request.configDigest.hex)
    #expect(runtime.ready)

    // The Authority-bound owner start is ordered after registration and carries
    // the exact in-memory runtime bytes; the Tunnel owner is never touched.
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.ensure == 2)
    #expect(proxyCounts.start == 1)
    #expect(await preparer.counters() == (prepare: 1, cancel: 0))
    let contexts = await proxy.authorizedContexts()
    #expect(contexts.count == 1)
    #expect(contexts.first?.operation.root.installationID.rawValue == descriptor.installationID)
    #expect(contexts.first?.operation.configSHA256 == descriptor.sha256)
    #expect(contexts.first?.operation.identitySHA256 == descriptor.identitySHA256)
    #expect(await proxy.transferredConfigurationDigests() == [descriptor.sha256.hex])
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 0)
  }

  @Test func systemProxyStartFailsClosedWhenAuthorityLeaseDisagrees() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(
          for: descriptor, mode: .systemProxy,
          generation: descriptor.generation + 1)))
    // The lease binds a different generation than the effective owner descriptor:
    // activation is refused and the already-started owner is rolled back to Off.
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(
          for: descriptor, mode: .systemProxy, generation: descriptor.generation + 1)),
      systemProxyPreparer: preparer,
      engineLease: lease)

    let code = await failureCode(coordinator, .startSystemProxy(request))
    let proxyCounts = await proxy.counters()
    #expect(code == .identityRejected)
    #expect(proxyCounts.start == 1)
    #expect(proxyCounts.stop == 1)
    #expect(await preparer.counters() == (prepare: 1, cancel: 0))
    #expect(await lease.counters() == (begin: 1, complete: 1))
    // The disagreement never falls back to the Tunnel owner.
    let tunnelCounts = await tunnel.counters()
    #expect(tunnelCounts.start == 0)
  }

  @Test func tunnelReachesActiveOnlyOnExactAuthorityAgreement() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active, lease: agreement(for: descriptor, mode: .tunnel)))

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
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(state: .off, lease: nil))
    // The provider reports active, but the Authority proves global Off: an
    // unresolved ownership ambiguity that must fail closed as Quarantined.
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(state: .off, lease: nil),
      engineLease: lease)

    let code = await failureCode(coordinator, .startTunnel(request))
    // Provider active while the Authority proves global Off is an ambiguity that
    // fails closed as Quarantined. It neither activates nor falls back.
    #expect(code == .quarantined)
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))
    let proxyCounts = await proxy.counters()
    #expect(proxyCounts.start == 0)
  }

  @Test func systemProxyStopRetriesOnlyIncompleteAuthorityCompletion() async throws {
    let request = try startRequest(tunnelOptions: nil)
    let descriptor = try request.descriptor(slot: .systemProxy)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let preparer = RecordingSystemProxyStartPreparer()
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .systemProxy)),
      completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .systemProxy)),
      systemProxyPreparer: preparer,
      engineLease: lease)

    _ = try await coordinator.execute(.startSystemProxy(request))
    let first = await failureCode(coordinator, .stopSystemProxy(request.context))
    #expect(first == .unavailable)
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))

    guard case .acknowledged = try await coordinator.execute(.stopSystemProxy(request.context))
    else {
      Issue.record("exact System Proxy stop retry was not acknowledged")
      return
    }
    #expect((await proxy.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 2))
  }

  @Test func tunnelStopRetriesOnlyIncompleteAuthorityCompletion() async throws {
    let request = try startRequest(tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
    let descriptor = try request.descriptor(slot: .tunnel)
    let proxy = StartableProxyAgent(descriptor: descriptor)
    let tunnel = StartableTunnelHost(descriptor: descriptor)
    let lease = RecordingEngineLease(
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      completeFailures: 1)
    let coordinator = makeCoordinator(
      proxy: proxy, tunnel: tunnel,
      observation: AuthorityOwnershipObservation(
        state: .active,
        lease: agreement(for: descriptor, mode: .tunnel)),
      engineLease: lease)

    _ = try await coordinator.execute(.startTunnel(request))
    let first = await failureCode(coordinator, .stopTunnel(request.context))
    #expect(first == .unavailable)
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 1))

    guard case .acknowledged = try await coordinator.execute(.stopTunnel(request.context)) else {
      Issue.record("exact Tunnel stop retry was not acknowledged")
      return
    }
    #expect((await tunnel.counters()).stop == 1)
    #expect(await lease.counters() == (begin: 1, complete: 2))
  }
}
