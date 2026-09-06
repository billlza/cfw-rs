import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWCredentialTransport
@testable import CFWProxyAgentCore

/// Test harness shorthand. The production coordinator requires one explicit
/// one-use runtime buffer and has no descriptor-only start path.
extension ProxySystemProxyOwnerCoordinator {
  func start(
    configuration descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: descriptor,
      authorization: authorization,
      completionHandler: completionHandler)
  }
}

private enum CoordinatorFixtureError: Error { case forced }

// MARK: - Ordering / recorders

private final class OrderLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []
  func record(_ event: String) { lock.withLock { events.append(event) } }
  var values: [String] { lock.withLock { events } }
}

private enum CoordinatorOutcome: Equatable {
  case success
  case failure(ProxySessionLifecycleError)
}

private final class CoordinatorRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let done = DispatchSemaphore(value: 0)
  private var outcomes: [CoordinatorOutcome] = []

  func record(_ result: Result<Void, ProxySessionLifecycleError>) {
    lock.withLock {
      switch result {
      case .success: outcomes.append(.success)
      case .failure(let error): outcomes.append(.failure(error))
      }
    }
    done.signal()
  }

  func wait() -> Bool { done.wait(timeout: .now() + 2) == .success }
  var values: [CoordinatorOutcome] { lock.withLock { outcomes } }
}

private final class SnapshotRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let done = DispatchSemaphore(value: 0)
  private var snapshots: [EngineSnapshot] = []

  func record(_ snapshot: EngineSnapshot) {
    lock.withLock { snapshots.append(snapshot) }
    done.signal()
  }

  func wait() -> Bool { done.wait(timeout: .now() + 2) == .success }
  var values: [EngineSnapshot] { lock.withLock { snapshots } }
}

private final class BlockingCallGate: @unchecked Sendable {
  private let entered = DispatchSemaphore(value: 0)
  private let released = DispatchSemaphore(value: 0)

  func block() {
    entered.signal()
    _ = released.wait(timeout: .now() + 2)
  }

  func waitUntilEntered() -> Bool {
    entered.wait(timeout: .now() + 2) == .success
  }

  func release() { released.signal() }
}

// MARK: - Authority fake

private final class FakeProxyOwnerAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private let orderLog: OrderLog
  private let makeLease: @Sendable () throws -> LeaseView
  private let bindThrows: AuthorityDomainError?
  private let readyThrows: Bool
  private let onBind: @Sendable () -> Void
  private let bindGate: BlockingCallGate?
  private let stoppedGate: BlockingCallGate?
  private var stoppedFailuresRemaining: Int
  private var bindCountValue = 0
  private var bindContextsValue: [ProxyOwnerContext] = []
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []
  private var stoppedAttemptCountValue = 0
  private let stoppedSignal = DispatchSemaphore(value: 0)

  init(
    orderLog: OrderLog,
    bindThrows: AuthorityDomainError? = nil,
    readyThrows: Bool = false,
    stoppedAttestationFailures: Int = 0,
    onBind: @escaping @Sendable () -> Void = {},
    bindGate: BlockingCallGate? = nil,
    stoppedGate: BlockingCallGate? = nil,
    makeLease: @escaping @Sendable () throws -> LeaseView
  ) {
    self.orderLog = orderLog
    self.bindThrows = bindThrows
    self.readyThrows = readyThrows
    self.onBind = onBind
    self.bindGate = bindGate
    self.stoppedGate = stoppedGate
    self.stoppedFailuresRemaining = stoppedAttestationFailures
    self.makeLease = makeLease
  }

  var bindCount: Int { lock.withLock { bindCountValue } }
  var bindContexts: [ProxyOwnerContext] { lock.withLock { bindContextsValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }
  var stoppedAttemptCount: Int { lock.withLock { stoppedAttemptCountValue } }
  func waitForStoppedAttempt() -> Bool {
    stoppedSignal.wait(timeout: .now() + 2) == .success
  }

  func bind(
    _ capability: OwnerCapability,
    context: ProxyOwnerContext
  ) async throws -> LeaseView {
    capability.erase()
    orderLog.record("bind")
    lock.withLock {
      bindCountValue += 1
      bindContextsValue.append(context)
    }
    if let bindThrows { throw bindThrows }
    onBind()
    bindGate?.block()
    return try makeLease()
  }

  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    ticket.erase()
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    lock.withLock { readyValue.append(attestation) }
    if readyThrows { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    let shouldFail = lock.withLock {
      stoppedAttemptCountValue += 1
      guard stoppedFailuresRemaining > 0 else {
        stoppedValue.append(attestation)
        return false
      }
      stoppedFailuresRemaining -= 1
      return true
    }
    stoppedSignal.signal()
    stoppedGate?.block()
    if shouldFail {
      throw AuthorityDomainError(code: .globalAuthorityUnavailable)
    }
  }
}

private struct FakeEffectiveSystemProxyObserver: EffectiveSystemProxyObserving {
  let applied: Bool
  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation {
    EffectiveSystemProxyObservation(
      httpApplied: applied, httpsApplied: applied, socksApplied: applied)
  }
}

private final class FakeClock: ProxyOwnerMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

// MARK: - Data-plane fakes

private final class FakeProxyEngine: ProxyEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private let orderLog: OrderLog
  private var eventHandler: (@Sendable (ProxyEngineEvent) -> Void)?
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFailuresRemaining: Int
  private let stopped = DispatchSemaphore(value: 0)

  init(orderLog: OrderLog, stopFailures: Int = 0) {
    self.orderLog = orderLog
    self.stopFailuresRemaining = stopFailures
  }

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }

  func start(
    configuration: Data,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    lock.withLock {
      startCountValue += 1
      self.eventHandler = eventHandler
    }
    orderLog.record("engine.start")
    started.signal()
  }

  func stop() throws {
    let shouldFail = lock.withLock {
      stopCountValue += 1
      guard stopFailuresRemaining > 0 else { return false }
      stopFailuresRemaining -= 1
      return true
    }
    stopped.signal()
    if shouldFail { throw CoordinatorFixtureError.forced }
  }
  func healthCheck() throws {}

  func waitUntilStarted() -> Bool { started.wait(timeout: .now() + 2) == .success }
  func waitForStopAttempt() -> Bool { stopped.wait(timeout: .now() + 2) == .success }

  func emit(_ event: ProxyEngineEvent) {
    let handler = lock.withLock { eventHandler }
    handler?(event)
  }
}

private struct FakeProxyEngineFactory: ProxyEngineFactory {
  let engine: FakeProxyEngine
  func makeEngine(configuration: Data) throws -> any ProxyEngine { engine }
}

private final class FakeJournalStore: ProxyOwnershipJournalStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var journalValue: ProxyOwnershipJournal?
  func load() throws -> ProxyOwnershipJournal? { lock.withLock { journalValue } }
  func save(_ journal: ProxyOwnershipJournal) throws { lock.withLock { journalValue = journal } }
  func remove() throws { lock.withLock { journalValue = nil } }
}

private final class FakeSystemProxyPreferences: SystemProxyPreferences, @unchecked Sendable {
  private let lock = NSLock()
  private let orderLog: OrderLog
  private var values: [SystemProxyField: ProxyPreferenceValue] = [:]
  private var applyCountValue = 0
  private var restoreCountValue = 0
  private var restoreFailuresRemaining: Int

  init(orderLog: OrderLog, restoreFailures: Int = 0) {
    self.orderLog = orderLog
    self.restoreFailuresRemaining = restoreFailures
  }

  var applyCount: Int { lock.withLock { applyCountValue } }
  var restoreCount: Int { lock.withLock { restoreCountValue } }

  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal {
    try lock.withLock {
      try Self.journal(configuration: configuration, endpoint: endpoint, originalValues: values)
    }
  }

  func apply(_ journal: ProxyOwnershipJournal) throws {
    lock.withLock {
      applyCountValue += 1
      for service in journal.services {
        for field in service.fields { values[field.field] = field.appliedValue }
      }
    }
    orderLog.record("apply")
  }

  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult {
    try lock.withLock {
      restoreCountValue += 1
      guard restoreFailuresRemaining == 0 else {
        restoreFailuresRemaining -= 1
        throw CoordinatorFixtureError.forced
      }
      for service in journal.services {
        for field in service.fields {
          if values[field.field] == field.appliedValue {
            if let original = field.originalValue {
              values[field.field] = original
            } else {
              values.removeValue(forKey: field.field)
            }
          }
        }
      }
      return ProxyRestoreResult(conflicts: [])
    }
  }

  static func journal(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint,
    originalValues: [SystemProxyField: ProxyPreferenceValue]
  ) throws -> ProxyOwnershipJournal {
    let applied: [SystemProxyField: ProxyPreferenceValue] = [
      .httpEnabled: .integer(1),
      .httpHost: .string(endpoint.host),
      .httpPort: .integer(Int(endpoint.port)),
      .httpsEnabled: .integer(1),
      .httpsHost: .string(endpoint.host),
      .httpsPort: .integer(Int(endpoint.port)),
      .socksEnabled: .integer(1),
      .socksHost: .string(endpoint.host),
      .socksPort: .integer(Int(endpoint.port)),
      .proxyAutoConfigEnabled: .integer(0),
      .proxyAutoDiscoveryEnabled: .integer(0),
    ]
    let fields = try SystemProxyField.allCases.map { field in
      guard let appliedValue = applied[field] else { throw CoordinatorFixtureError.forced }
      return OwnedSystemProxyField(
        field: field, originalValue: originalValues[field], appliedValue: appliedValue)
    }
    return try ProxyOwnershipJournal(
      phase: .prepared,
      configuration: configuration,
      services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)])
  }
}

// MARK: - Builders

private func proxyDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: CredentialAudience(
      profileID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "11", count: 32)))
}

private func matchingLease(_ descriptor: ConfigurationDescriptor) throws -> LeaseView {
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch, generation: descriptor.generation),
    mode: .systemProxy,
    configSHA256: descriptor.sha256,
    identitySHA256: descriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  return try LeaseView(
    leaseID: AuthorityIdentifier(UUID()), operation: operation,
    state: .starting, expiryMonotonic: 10_000)
}

private func mismatchedLease(_ descriptor: ConfigurationDescriptor) throws -> LeaseView {
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch, generation: descriptor.generation),
    mode: .systemProxy,
    configSHA256: SHA256Digest(hex: String(repeating: "22", count: 32)),
    identitySHA256: descriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
  return try LeaseView(
    leaseID: AuthorityIdentifier(UUID()), operation: operation,
    state: .starting, expiryMonotonic: 10_000)
}

private func readyEndpoint() throws -> MixedListenerEndpoint {
  try MixedListenerEndpoint(host: "127.0.0.1", port: 7_890)
}

private struct CoordinatorFixture {
  let coordinator: ProxySystemProxyOwnerCoordinator
  let authority: FakeProxyOwnerAuthorityClient
  let engine: FakeProxyEngine
  let preferences: FakeSystemProxyPreferences
  let revocation: ProxyRevocationChannel
  let descriptor: ConfigurationDescriptor
  let lease: LeaseView
  let boundLease: LeaseView
  let orderLog: OrderLog

  func authorization() throws -> ProxyOwnerAuthorization {
    ProxyOwnerAuthorization(
      context: try ProxyOwnerContext(
        operation: lease.operation,
        leaseID: lease.leaseID),
      capability: try OwnerCapability(
        copying: Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes)))
  }
}

private func makeFixture(
  bindThrows: AuthorityDomainError? = nil,
  readyThrows: Bool = false,
  effectiveApplied: Bool = true,
  engineStopFailures: Int = 0,
  preferencesRestoreFailures: Int = 0,
  stoppedAttestationFailures: Int = 0,
  returnMismatchedLease: Bool = false,
  onBind: @escaping @Sendable () -> Void = {},
  bindGate: BlockingCallGate? = nil,
  stoppedGate: BlockingCallGate? = nil,
  revocation: ProxyRevocationChannel = ProxyRevocationChannel(),
  clockValue: UInt64 = 777
) throws -> CoordinatorFixture {
  let orderLog = OrderLog()
  let descriptor = try proxyDescriptor()
  let engine = FakeProxyEngine(orderLog: orderLog, stopFailures: engineStopFailures)
  let preferences = FakeSystemProxyPreferences(
    orderLog: orderLog,
    restoreFailures: preferencesRestoreFailures)
  let lease = try matchingLease(descriptor)
  let boundLease = returnMismatchedLease ? try mismatchedLease(descriptor) : lease
  let authority = FakeProxyOwnerAuthorityClient(
    orderLog: orderLog,
    bindThrows: bindThrows,
    readyThrows: readyThrows,
    stoppedAttestationFailures: stoppedAttestationFailures,
    onBind: onBind,
    bindGate: bindGate,
    stoppedGate: stoppedGate
  ) { boundLease }
  let lifecycle = ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareOwnership: { _ in
        PreparedProxyOwnership(lease: UnleasedProxyOwnership())
      },
      recoverCleanupLease: { _ in UnleasedProxyOwnership() },
      engineFactory: FakeProxyEngineFactory(engine: engine),
      preferences: preferences,
      journalStore: FakeJournalStore(),
      readinessTimeout: 60))
  let coordinator = ProxySystemProxyOwnerCoordinator(
    authority: authority,
    observer: FakeEffectiveSystemProxyObserver(applied: effectiveApplied),
    lifecycle: lifecycle,
    revocation: revocation,
    clock: FakeClock(value: clockValue))
  return CoordinatorFixture(
    coordinator: coordinator, authority: authority, engine: engine,
    preferences: preferences, revocation: revocation,
    descriptor: descriptor, lease: lease, boundLease: boundLease, orderLog: orderLog)
}

// MARK: - Tests

@Suite(.serialized)
struct ProxySystemProxyOwnerCoordinatorTests {
  @Test func consumedAuthorizationFailsClosedBeforeAnyMutation() throws {
    let fixture = try makeFixture()
    let authorization = try fixture.authorization()
    let consumed = try authorization.consumeCapability()
    consumed.erase()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: authorization
    ) { start.record($0) }
    try #require(start.wait())

    let outcome = try #require(start.values.first)
    guard case .failure(.engineLease) = outcome else {
      Issue.record("Expected fail-closed engine-lease (Authority) failure")
      return
    }
    #expect(fixture.authority.bindCount == 0)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values.isEmpty)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func rejectedCapabilityFailsClosedBeforeLibboxOrPreferences() throws {
    let fixture = try makeFixture(
      bindThrows: AuthorityDomainError(code: .globalAuthorityIdentityRejected))
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected fail-closed Authority rejection")
      return
    }
    #expect(fixture.authority.bindCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values == ["bind"])
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func boundLeaseMismatchProvesStoppedAndAttestsExactAuthorityContext() throws {
    let fixture = try makeFixture(returnMismatchedLease: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected the mismatched bound lease to fail closed")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
    #expect(fixture.authority.stoppedAttestations.first?.leaseID == fixture.boundLease.leaseID)
  }

  @Test func boundMismatchAttestationFailureBlocksStartAndRetriesExactProof() throws {
    let fixture = try makeFixture(
      stoppedAttestationFailures: 1,
      returnMismatchedLease: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())
    guard case .failure(.cleanupFailed) = start.values[0] else {
      Issue.record("Expected the mismatch and stopped-attestation failures to be preserved")
      return
    }

    let blocked = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { blocked.record($0) }
    #expect(blocked.wait())
    #expect(blocked.values == [.failure(.lifecycleConflict)])
    #expect(fixture.authority.bindCount == 1)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
  }

  @Test func revocationLatchedAfterBindPreventsLocalStartAndAttestsStopped() throws {
    let revocation = ProxyRevocationChannel()
    let fixture = try makeFixture(
      onBind: { revocation.revoke() },
      revocation: revocation)
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected the claim-after-revoke start to fail closed")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func explicitStopDuringBindCancelsStartAndWaitsForExactStoppedProof() throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(bindGate: bindGate)
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(bindGate.waitUntilEntered())

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.values.isEmpty)
    bindGate.release()

    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(start.wait())
    #expect(start.values == [.failure(.startupCancelled)])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func ownerBindingPrecedesLibboxAndPreferencesAndAttestsReadyExactly() throws {
    let fixture = try makeFixture(clockValue: 4_242)
    let authorization = try fixture.authorization()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: authorization
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    // Binding to the Authority precedes libbox start, which precedes SCPreferences.
    #expect(fixture.orderLog.values == ["bind", "engine.start", "apply"])
    #expect(fixture.authority.bindCount == 1)
    #expect(
      fixture.authority.bindContexts == [
        try ProxyOwnerContext(
          operation: fixture.lease.operation,
          leaseID: fixture.lease.leaseID)
      ])
    #expect(throws: (any Error).self) {
      _ = try authorization.consumeCapability()
    }

    let ready = fixture.authority.readyAttestations
    #expect(ready.count == 1)
    #expect(ready.first?.ownerRole == .proxyAgent)
    #expect(ready.first?.readyFlags == .all)
    #expect(ready.first?.packetPumpLimits == nil)
    #expect(ready.first?.monotonicTimestamp == 4_242)
    #expect(ready.first?.operation.mode == .systemProxy)
    #expect(ready.first?.operation.configSHA256 == fixture.descriptor.sha256)
    #expect(ready.first?.operation.identitySHA256 == fixture.descriptor.identitySHA256)
  }

  @Test func readinessRefusedWhenEffectiveProxyStateIsNotApplied() throws {
    let fixture = try makeFixture(effectiveApplied: false)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected fail-closed readiness refusal")
      return
    }
    #expect(fixture.authority.readyAttestations.isEmpty)
    // The owned libbox runtime and System Proxy state are torn down on refusal.
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func readyAttestationFailureTearsDownAndFailsClosed() throws {
    let fixture = try makeFixture(readyThrows: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected fail-closed attestation failure")
      return
    }
    #expect(fixture.authority.readyAttestations.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func stopAttestsStoppedExactlyWithBoundContext() throws {
    let fixture = try makeFixture(clockValue: 909)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])

    let stopped = fixture.authority.stoppedAttestations
    #expect(stopped.count == 1)
    #expect(stopped.first?.libboxStopped == true)
    #expect(stopped.first?.transportClosed == true)
    #expect(stopped.first?.osRestored == true)
    #expect(stopped.first?.monotonicTimestamp == 909)
    #expect(stopped.first?.operation.mode == .systemProxy)
    #expect(fixture.engine.stopCount == 1)
  }

  @Test func engineCleanupFailureDoesNotAttestOrClearOwnerContext() throws {
    let fixture = try makeFixture(engineStopFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    guard case .failure(.engineStop) = failedStop.values[0] else {
      Issue.record("Expected the libbox cleanup failure to be reported explicitly")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    // The failed owner context remains bound. A retry completes the same cleanup
    // and only then proves stopped to the Authority.
    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.stopCount == 2)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func preferencesCleanupFailureDoesNotAttestOrClearOwnerContext() throws {
    let fixture = try makeFixture(preferencesRestoreFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    guard case .failure(.preferences) = failedStop.values[0] else {
      Issue.record("Expected the SCPreferences restore failure to be reported explicitly")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func stoppedAttestationFailureIsReportedAndRemainsRetryable() throws {
    let fixture = try makeFixture(stoppedAttestationFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    guard case .failure(.engineLease) = failedStop.values[0] else {
      Issue.record("Expected the Authority stopped-attestation failure")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    let failedSnapshot = SnapshotRecorder()
    fixture.coordinator.snapshot { failedSnapshot.record($0) }
    #expect(failedSnapshot.wait())
    #expect(failedSnapshot.values.first?.state.kind == .failed)
    #expect(failedSnapshot.values.first?.configuration == fixture.descriptor)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func readinessFailureRetainsOwnerContextWhenCleanupIsUnproven() throws {
    let fixture = try makeFixture(effectiveApplied: false, engineStopFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.cleanupFailed) = start.values[0] else {
      Issue.record("Expected readiness failure to include the unproven cleanup")
      return
    }
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttemptCount == 0)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.stopCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func revocationForcesStopAndAttestsStopped() throws {
    let fixture = try makeFixture()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func revocationRetainsContextUntilStoppedAttestationSucceeds() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(
      stoppedAttestationFailures: 1,
      stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(stoppedGate.waitUntilEntered())
    #expect(fixture.authority.waitForStoppedAttempt())
    let joinedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      joinedStop.record($0)
    }
    stoppedGate.release()
    #expect(joinedStop.wait())
    guard case .failure(.engineLease) = joinedStop.values[0] else {
      Issue.record("Expected the joined stop to observe the failed attestation")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    // Revocation is idempotently retryable after local Off because the exact owner
    // context was retained when the first Authority attestation failed.
    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentExplicitStopAndRevocationShareOneStopTransaction() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stoppedGate.waitUntilEntered())
    fixture.revocation.revoke()
    stoppedGate.release()

    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }
}
