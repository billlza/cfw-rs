import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWProxyAgentCore

// Integration coverage for task 9.12 (ProxyAgent): readiness is attested only when
// the effective System Proxy state is applied for EVERY proxy protocol (a partial
// application is refused and torn down), and a stop with no bound owner context
// attests nothing. All Authority (XPC), effective-proxy observation, and data-plane
// side effects live behind injected fakes; no real launchd, SystemConfiguration, or
// XPC is exercised.

private enum CoordinatorFixtureError: Error { case forced }

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

private final class FakeProxyOwnerAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private let orderLog: OrderLog
  private let makeLease: @Sendable () throws -> LeaseView
  private var bindCountValue = 0
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []

  init(orderLog: OrderLog, makeLease: @escaping @Sendable () throws -> LeaseView) {
    self.orderLog = orderLog
    self.makeLease = makeLease
  }

  var bindCount: Int { lock.withLock { bindCountValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }

  func bind(_ capability: OwnerCapability) async throws -> LeaseView {
    capability.erase()
    orderLog.record("bind")
    lock.withLock { bindCountValue += 1 }
    return try makeLease()
  }

  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    ticket.erase()
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    lock.withLock { readyValue.append(attestation) }
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    lock.withLock { stoppedValue.append(attestation) }
  }
}

private struct FakeProxyOwnerCapabilitySource: ProxyOwnerCapabilitySource {
  func capability(for descriptor: ConfigurationDescriptor) throws -> OwnerCapability {
    try OwnerCapability(copying: Data(repeating: 0x5, count: AuthorityV1Limits.capabilityBytes))
  }
}

/// Per-protocol effective System Proxy observer so a PARTIAL application (some
/// protocols applied, others not) can be exercised. `isFullyApplied` must require
/// every proxy protocol before readiness is attested.
private struct PartialEffectiveSystemProxyObserver: EffectiveSystemProxyObserving {
  let http: Bool
  let https: Bool
  let socks: Bool
  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation {
    EffectiveSystemProxyObservation(httpApplied: http, httpsApplied: https, socksApplied: socks)
  }
}

private final class FakeClock: ProxyOwnerMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

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
  private var values: [SystemProxyField: ProxyPreferenceValue] = [:]
  private var applyCountValue = 0
  private var restoreCountValue = 0

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

private func proxyDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    installationID: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
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
  let descriptor: ConfigurationDescriptor
}

private func makeFixture(
  observer: any EffectiveSystemProxyObserving
) throws -> CoordinatorFixture {
  let orderLog = OrderLog()
  let descriptor = try proxyDescriptor()
  let engine = FakeProxyEngine(orderLog: orderLog)
  let preferences = FakeSystemProxyPreferences()
  let captured = descriptor
  let authority = FakeProxyOwnerAuthorityClient(orderLog: orderLog) {
    try matchingLease(captured)
  }
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
  let coordinator = ProxySystemProxyOwnerCoordinator(
    authority: authority,
    capabilitySource: FakeProxyOwnerCapabilitySource(),
    observer: observer,
    lifecycle: lifecycle,
    revocation: ProxyRevocationChannel(),
    clock: FakeClock(value: 555))
  return CoordinatorFixture(
    coordinator: coordinator, authority: authority,
    engine: engine, preferences: preferences, descriptor: descriptor)
}

@Suite(.serialized)
struct ProxyOwnerBindingIntegrationTests {
  @Test func partialEffectiveApplicationRefusesReadinessAndTearsDown() throws {
    // HTTP and HTTPS applied, but SOCKS is not: `isFullyApplied` is false, so
    // readiness must be refused and the owned runtime/System Proxy torn down.
    let fixture = try makeFixture(
      observer: PartialEffectiveSystemProxyObserver(http: true, https: true, socks: false))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(configuration: fixture.descriptor) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected fail-closed readiness refusal for a partial application")
      return
    }
    // No ready attestation was ever sent, and the owned state is torn down.
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
  }

  @Test func stopWithoutABoundOwnerAttestsNothing() throws {
    let fixture = try makeFixture(
      observer: PartialEffectiveSystemProxyObserver(http: true, https: true, socks: true))

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())

    // No owner was ever bound, so no stopped attestation is sent for an unbound
    // context and no libbox owner ever started.
    #expect(fixture.authority.bindCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)
    #expect(fixture.engine.startCount == 0)
  }
}
