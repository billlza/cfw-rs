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

// In-memory ProxyAgents for the start command tests: one that starts and stops
// as told, one whose start fails as scripted, and a recording system proxy
// preparer.
actor RecordingSystemProxyStartPreparer: SystemProxyStartPreparing {
  private(set) var prepareCalls = 0
  private(set) var cancelCalls = 0
  private let failPreparation: Bool
  private let cancelError: AuthorityDomainError?

  init(failPreparation: Bool = false, cancelError: AuthorityDomainError? = nil) {
    self.failPreparation = failPreparation
    self.cancelError = cancelError
  }

  func prepareSystemProxyStart(
    configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws -> HostPreparedSystemProxyStart {
    guard !configuration.isEmpty, descriptor.slot.isProxyAgent else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    prepareCalls += 1
    if failPreparation { throw AuthorityDomainError(code: .invalidMessage) }
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: AuthorityIdentifier(descriptor.installationID),
        epoch: descriptor.epoch,
        generation: descriptor.generation),
      mode: descriptor.slot.authorityMode,
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
  ) throws {
    cancelCalls += 1
    prepared.erase()
    if let cancelError { throw cancelError }
  }

  func counters() -> (prepare: Int, cancel: Int) {
    (prepareCalls, cancelCalls)
  }
}

actor StartableProxyAgent: ProxyAgentTransporting {
  func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws
    -> [ProfileProxyDelay]
  {
    throw ProxyAgentHostError.malformedResponse
  }

  private(set) var authorizationCalls = 0
  func authorizeSystemProxy(restorationOnly: Bool) async throws { authorizationCalls += 1 }
  private let descriptor: ConfigurationDescriptor
  private let registrationError: ProxyAgentHostError?
  private let blocksSnapshot: Bool
  private let snapshotAdmission: NativeFixtureHandshake?
  nonisolated let snapshotHandshake = NativeFixtureHandshake()
  private var snapshotSequence: [EngineSnapshot]
  private let snapshotErrorAt: Int?
  private var registered: Bool
  private var runtimeFailed = false
  private var failureOmitsDescriptor = false
  private var ended = false
  private var reported: EngineSnapshot?
  private var stopFailures: [ProxyAgentHostError]
  private var restoreBeforeStopFailures: [ProxyAgentHostError]
  private let events: NativeCleanupEventLog?
  /// The configuration of each restore before a stop, in order.
  private(set) var restoresBeforeStop: [ConfigurationDescriptor] = []
  private(set) var ensureCalls = 0
  private(set) var snapshotCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private(set) var startContexts: [ProxyOwnerContext] = []
  private(set) var startConfigurationDigests: [String] = []

  /// Each stop throws the next of `stopFailures`, and each restore before a
  /// stop the next of `restoreBeforeStopFailures`; once none is left, they
  /// succeed.
  init(
    descriptor: ConfigurationDescriptor,
    registrationError: ProxyAgentHostError? = nil,
    initiallyRegistered: Bool = true,
    blocksSnapshot: Bool = false,
    snapshotAdmission: NativeFixtureHandshake? = nil,
    snapshotSequence: [EngineSnapshot] = [],
    snapshotErrorAt: Int? = nil,
    stopFailures: [ProxyAgentHostError] = [],
    restoreBeforeStopFailures: [ProxyAgentHostError] = [],
    events: NativeCleanupEventLog? = nil
  ) {
    self.descriptor = descriptor
    self.registrationError = registrationError
    registered = initiallyRegistered
    self.blocksSnapshot = blocksSnapshot
    self.snapshotAdmission = snapshotAdmission
    self.snapshotSequence = snapshotSequence
    self.snapshotErrorAt = snapshotErrorAt
    self.stopFailures = stopFailures
    self.restoreBeforeStopFailures = restoreBeforeStopFailures
    self.events = events
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
  func stop(configuration: ConfigurationDescriptor) throws {
    stopCalls += 1
    events?.append("proxy-stop")
    if !stopFailures.isEmpty { throw stopFailures.removeFirst() }
  }

  func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) throws {
    restoresBeforeStop.append(configuration)
    events?.append("restore-before-stop")
    if !restoreBeforeStopFailures.isEmpty { throw restoreBeforeStopFailures.removeFirst() }
  }

  func snapshot() async throws -> EngineSnapshot {
    snapshotCalls += 1
    if let snapshotAdmission { try await snapshotAdmission.enter() }
    if blocksSnapshot {
      try await snapshotHandshake.enter()
    }
    guard registered else { throw ProxyAgentHostError.registrationUnavailable }
    if snapshotCalls == snapshotErrorAt {
      throw ProxyAgentHostError.transportUnavailable("Injected snapshot failure")
    }
    if let reported { return reported }
    if let snapshot = snapshotSequence.first {
      if snapshotSequence.count > 1 { snapshotSequence.removeFirst() }
      return snapshot
    }
    guard startCalls > 0 && stopCalls == 0 && !ended else { return .off }
    if runtimeFailed {
      return try EngineSnapshot(
        mode: descriptor.slot.engineMode,
        state: .failed(
          EngineFailure(
            code: "runtime-failed", message: "Runtime stopped unexpectedly.", isRetryable: false)),
        configuration: failureOmitsDescriptor ? nil : descriptor, sequence: 2)
    }
    return .proxyActive(configuration: descriptor, sequence: 1)
  }

  func simulateExistingActiveSession() { startCalls = 1 }

  /// The ProxyAgent ended, for example after an engine it could not close; its
  /// successor holds no session.
  func simulateEnded() { ended = true }

  /// Every snapshot reports `snapshot` until it is nil again.
  func report(_ snapshot: EngineSnapshot?) { reported = snapshot }

  func simulateRuntimeFailure(omittingDescriptor: Bool = false) {
    runtimeFailed = true
    failureOmitsDescriptor = omittingDescriptor
  }

  func validateConfiguration(_ configuration: Data, descriptor: ConfigurationDescriptor) throws {}

  func counters() -> (ensure: Int, snapshot: Int, start: Int, stop: Int) {
    (ensureCalls, snapshotCalls, startCalls, stopCalls)
  }
  func releaseSnapshot() { snapshotHandshake.release() }
  func authorizedContexts() -> [ProxyOwnerContext] { startContexts }
  func transferredConfigurationDigests() -> [String] { startConfigurationDigests }
}

enum FailedStartRetryFault: CaseIterable, Equatable, Sendable {
  case ownerObservation
  case ownerStop
  case globalOffObservation
}

actor FailedStartProxyAgent: ProxyAgentTransporting {
  func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws
    -> [ProfileProxyDelay]
  {
    throw ProxyAgentHostError.malformedResponse
  }

  func authorizeSystemProxy(restorationOnly: Bool) async throws {}
  private let descriptor: ConfigurationDescriptor
  private let failure: EngineFailure
  private var remainingSnapshotFailures: Int
  private var remainingStopFailures: Int
  private var remainingSessionlessStops: Int
  private var failed = false
  private var stopped = false
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private(set) var restoresBeforeStop = 0

  /// The first `sessionlessStops` stops reply as a ProxyAgent with no record of the stop.
  init(
    descriptor: ConfigurationDescriptor,
    fault: FailedStartRetryFault?,
    failure: EngineFailure = EngineFailure(
      code: "mixed-endpoint-in-use",
      message: "The mixed listener endpoint is already in use.",
      isRetryable: false),
    sessionlessStops: Int = 0
  ) {
    self.descriptor = descriptor
    self.failure = failure
    remainingSnapshotFailures = fault == .ownerObservation ? 1 : 0
    remainingStopFailures = fault == .ownerStop ? 1 : 0
    remainingSessionlessStops = sessionlessStops
  }

  func registrationStatus() -> ProxyAgentRegistrationStatus { .enabled }
  func ensureRegistered() {}

  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) throws {
    try descriptor.validateConfigurationBytes(configuration)
    startCalls += 1
    failed = true
    throw ProxyAgentHostError.agentFailure(failure)
  }

  func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) throws {
    restoresBeforeStop += 1
    guard configuration == descriptor else {
      throw ProxyAgentHostError.responseMismatch
    }
  }

  func stop(configuration: ConfigurationDescriptor) throws {
    stopCalls += 1
    guard configuration == descriptor else {
      throw ProxyAgentHostError.responseMismatch
    }
    if remainingStopFailures > 0 {
      remainingStopFailures -= 1
      throw ProxyAgentHostError.transportUnavailable("injected owner stop failure")
    }
    if remainingSessionlessStops > 0 {
      remainingSessionlessStops -= 1
      throw ProxyAgentHostError.agentFailure(
        EngineFailure(
          .agent(.stopWithoutSession),
          message: "System Proxy holds no session for the stopped generation."))
    }
    stopped = true
  }

  func snapshot() throws -> EngineSnapshot {
    if remainingSnapshotFailures > 0 {
      remainingSnapshotFailures -= 1
      throw ProxyAgentHostError.transportUnavailable("injected owner observation failure")
    }
    return failed && !stopped
      ? .proxyFailed(failure, configuration: descriptor, sequence: 1)
      : .off
  }

  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws {}

  func counters() -> (start: Int, stop: Int) { (startCalls, stopCalls) }
}
