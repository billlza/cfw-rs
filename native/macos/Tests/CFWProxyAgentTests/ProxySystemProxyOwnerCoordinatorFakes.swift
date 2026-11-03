import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// The coordinator's fakes: the Authority client, the effective proxy observer
// and the clock, and the data plane's engine, journal store and preferences.
// The owner binding integration tests share its journal store.
// MARK: - Authority fake

final class FakeProxyOwnerAuthorityClient: ProxyOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private var leaseStatusesRemaining: [Result<OwnerLeaseStatus, AuthorityDomainError>]
  private var leaseStatusQueriesValue: [AuthorityIdentifier] = []
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
    leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = [],
    makeLease: @escaping @Sendable () throws -> LeaseView
  ) {
    self.leaseStatusesRemaining = leaseStatuses
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
  var leaseStatusQueries: [AuthorityIdentifier] { lock.withLock { leaseStatusQueriesValue } }

  /// Answers with the next scripted status; without one the Authority gives
  /// no answer, as an unreachable one would. Tests read the queries made.
  func ownerLeaseStatus(_ leaseID: AuthorityIdentifier) async throws -> OwnerLeaseStatus {
    let next = lock.withLock { () -> Result<OwnerLeaseStatus, AuthorityDomainError>? in
      leaseStatusQueriesValue.append(leaseID)
      return leaseStatusesRemaining.isEmpty ? nil : leaseStatusesRemaining.removeFirst()
    }
    orderLog.record("leaseStatus")
    guard let next else { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
    return try next.get()
  }
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
    // A held bind answers, with its lease or its failure, once released.
    bindGate?.block()
    if let bindThrows { throw bindThrows }
    onBind()
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

struct FakeEffectiveSystemProxyObserver: EffectiveSystemProxyObserving {
  let applied: Bool
  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation {
    EffectiveSystemProxyObservation(
      httpApplied: applied, httpsApplied: applied, socksApplied: applied)
  }
}

final class FakeClock: ProxyOwnerMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

// MARK: - Data-plane fakes

final class FakeProxyEngine: ProxyEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private let orderLog: OrderLog
  private var eventHandler: (@Sendable (ProxyEngineEvent) -> Void)?
  private var startCountValue = 0
  private var stopCountValue = 0
  private var startDeadlines: [EngineStartDeadline] = []
  private let startFailure: ProxyEngineError?
  private let closeFailure: LibboxInstanceUnclosable?
  private let stopped = DispatchSemaphore(value: 0)

  /// With `startFailure`, every start throws it. With `closeFailure`, every
  /// stop throws it, as an engine whose libbox instance could not be closed
  /// does.
  init(
    orderLog: OrderLog, startFailure: ProxyEngineError? = nil,
    closeFailure: LibboxInstanceUnclosable? = nil
  ) {
    self.orderLog = orderLog
    self.startFailure = startFailure
    self.closeFailure = closeFailure
  }

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }
  var deadlines: [EngineStartDeadline] { lock.withLock { startDeadlines } }

  func start(
    configuration: Data,
    deadline: EngineStartDeadline,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    lock.withLock {
      startCountValue += 1
      startDeadlines.append(deadline)
      self.eventHandler = eventHandler
    }
    orderLog.record("engine.start")
    started.signal()
    if let startFailure { throw startFailure }
  }

  func stop() throws(LibboxInstanceUnclosable) {
    lock.withLock { stopCountValue += 1 }
    stopped.signal()
    if let closeFailure { throw closeFailure }
  }
  func healthCheck() throws {}

  func waitUntilStarted() -> Bool { started.wait(timeout: .now() + 2) == .success }
  func waitForStopAttempt() -> Bool { stopped.wait(timeout: .now() + 2) == .success }

  func emit(_ event: ProxyEngineEvent) {
    let handler = lock.withLock { eventHandler }
    handler?(event)
  }
}

struct FakeProxyEngineFactory: ProxyEngineFactory {
  let engine: FakeProxyEngine
  func makeEngine(configuration: Data) throws -> any ProxyEngine { engine }
}

final class FakeJournalStore: ProxyOwnershipJournalStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var journalValue: ProxyOwnershipJournal?
  func load() throws -> ProxyOwnershipJournal? { lock.withLock { journalValue } }
  func save(_ journal: ProxyOwnershipJournal) throws { lock.withLock { journalValue = journal } }
  func remove() throws { lock.withLock { journalValue = nil } }
}

final class FakeSystemProxyPreferences: SystemProxyPreferences, @unchecked Sendable {
  func requireAuthorization() throws {}
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
