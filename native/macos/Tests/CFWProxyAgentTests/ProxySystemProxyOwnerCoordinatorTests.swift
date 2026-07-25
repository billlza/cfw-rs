import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWProxyAgentCore

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

// MARK: - Authority fake

private final class FakeProxyOwnerAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private let orderLog: OrderLog
  private let makeLease: @Sendable () throws -> LeaseView
  private let bindThrows: AuthorityDomainError?
  private let readyThrows: Bool
  private var bindCountValue = 0
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []
  private let stoppedSignal = DispatchSemaphore(value: 0)

  init(
    orderLog: OrderLog,
    bindThrows: AuthorityDomainError? = nil,
    readyThrows: Bool = false,
    makeLease: @escaping @Sendable () throws -> LeaseView
  ) {
    self.orderLog = orderLog
    self.bindThrows = bindThrows
    self.readyThrows = readyThrows
    self.makeLease = makeLease
  }

  var bindCount: Int { lock.withLock { bindCountValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }
  func waitForStopped() -> Bool { stoppedSignal.wait(timeout: .now() + 2) == .success }

  func bind(_ capability: OwnerCapability) async throws -> LeaseView {
    capability.erase()
    orderLog.record("bind")
    lock.withLock { bindCountValue += 1 }
    if let bindThrows { throw bindThrows }
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
    lock.withLock { stoppedValue.append(attestation) }
    stoppedSignal.signal()
  }
}

private struct FakeProxyOwnerCapabilitySource: ProxyOwnerCapabilitySource {
  let throwsError: Bool
  func capability(for descriptor: ConfigurationDescriptor) throws -> OwnerCapability {
    if throwsError { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
    return try OwnerCapability(
      copying: Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes))
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

  init(orderLog: OrderLog) { self.orderLog = orderLog }

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

  func stop() throws { lock.withLock { stopCountValue += 1 } }
  func healthCheck() throws {}

  func waitUntilStarted() -> Bool { started.wait(timeout: .now() + 2) == .success }

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

  init(orderLog: OrderLog) { self.orderLog = orderLog }

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
    lock.withLock {
      restoreCountValue += 1
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
    state: .active, expiryMonotonic: 10_000)
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
  let orderLog: OrderLog
}

private func makeFixture(
  capabilityThrows: Bool = false,
  bindThrows: AuthorityDomainError? = nil,
  readyThrows: Bool = false,
  effectiveApplied: Bool = true,
  clockValue: UInt64 = 777
) throws -> CoordinatorFixture {
  let orderLog = OrderLog()
  let descriptor = try proxyDescriptor()
  let engine = FakeProxyEngine(orderLog: orderLog)
  let preferences = FakeSystemProxyPreferences(orderLog: orderLog)
  let capturedDescriptor = descriptor
  let authority = FakeProxyOwnerAuthorityClient(
    orderLog: orderLog, bindThrows: bindThrows, readyThrows: readyThrows
  ) { try matchingLease(capturedDescriptor) }
  let lifecycle = ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareConfiguration: { _ in
        PreparedProxyConfiguration(
          configuration: Data("{}".utf8), lease: UnleasedProxyOwnership())
      },
      recoverCleanupLease: { _ in UnleasedProxyOwnership() },
      engineFactory: FakeProxyEngineFactory(engine: engine),
      preferences: preferences,
      journalStore: FakeJournalStore(),
      readinessTimeout: 60))
  let revocation = ProxyRevocationChannel()
  let coordinator = ProxySystemProxyOwnerCoordinator(
    authority: authority,
    capabilitySource: FakeProxyOwnerCapabilitySource(throwsError: capabilityThrows),
    observer: FakeEffectiveSystemProxyObserver(applied: effectiveApplied),
    lifecycle: lifecycle,
    revocation: revocation,
    clock: FakeClock(value: clockValue))
  return CoordinatorFixture(
    coordinator: coordinator, authority: authority, engine: engine,
    preferences: preferences, revocation: revocation,
    descriptor: descriptor, orderLog: orderLog)
}

// MARK: - Tests

@Suite(.serialized)
struct ProxySystemProxyOwnerCoordinatorTests {
  @Test func unavailableCapabilityFailsClosedBeforeAnyMutation() throws {
    let fixture = try makeFixture(capabilityThrows: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected fail-closed engine-lease (Authority) failure")
      return
    }
    #expect(fixture.authority.bindCount == 0)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values.isEmpty)
  }

  @Test func rejectedCapabilityFailsClosedBeforeLibboxOrPreferences() throws {
    let fixture = try makeFixture(
      bindThrows: AuthorityDomainError(code: .globalAuthorityIdentityRejected))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected fail-closed Authority rejection")
      return
    }
    #expect(fixture.authority.bindCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values == ["bind"])
  }

  @Test func ownerBindingPrecedesLibboxAndPreferencesAndAttestsReadyExactly() throws {
    let fixture = try makeFixture(clockValue: 4_242)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    // Binding to the Authority precedes libbox start, which precedes SCPreferences.
    #expect(fixture.orderLog.values == ["bind", "engine.start", "apply"])
    #expect(fixture.authority.bindCount == 1)

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
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
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
  }

  @Test func readyAttestationFailureTearsDownAndFailsClosed() throws {
    let fixture = try makeFixture(readyThrows: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
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
  }

  @Test func stopAttestsStoppedExactlyWithBoundContext() throws {
    let fixture = try makeFixture(clockValue: 909)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
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

  @Test func revocationForcesStopAndAttestsStopped() throws {
    let fixture = try makeFixture()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStopped())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }
}
