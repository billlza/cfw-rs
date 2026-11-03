import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// The session lifecycle's fakes: the engine and its factory, the lease, the
// journal stores and the system proxy preferences.
enum ForcedProxyFailure: Error {
  case requested
}

final class FakeLifecycleEngine: ProxyEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private var eventHandler: (@Sendable (ProxyEngineEvent) -> Void)?
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFailure: LibboxInstanceUnclosable?

  var startCount: Int {
    lock.withLock { startCountValue }
  }

  var stopCount: Int {
    lock.withLock { stopCountValue }
  }

  func start(
    configuration: Data,
    deadline: EngineStartDeadline,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    lock.withLock {
      startCountValue += 1
      self.eventHandler = eventHandler
    }
    started.signal()
  }

  func stop() throws(LibboxInstanceUnclosable) {
    let failure = lock.withLock { () -> LibboxInstanceUnclosable? in
      stopCountValue += 1
      return stopFailure
    }
    if let failure {
      throw failure
    }
  }

  func healthCheck() throws {}

  /// Makes this and every later stop throw `failure`, as an engine whose
  /// libbox instance could not be closed does.
  func failStops(with failure: LibboxInstanceUnclosable) {
    lock.withLock { stopFailure = failure }
  }

  func waitUntilStarted() -> Bool {
    started.wait(timeout: .now() + 1) == .success
  }

  func emit(_ event: ProxyEngineEvent) {
    let eventHandler = lock.withLock { self.eventHandler }
    eventHandler?(event)
  }
}

struct FakeLifecycleEngineFactory: ProxyEngineFactory {
  let engine: FakeLifecycleEngine
  let creationFails: Bool

  func makeEngine(configuration: Data) throws -> any ProxyEngine {
    if creationFails {
      throw ForcedProxyFailure.requested
    }
    return engine
  }
}

final class FakeLease: ProxyEngineLeaseHolding, @unchecked Sendable {
  private let lock = NSLock()
  private var releaseCountValue = 0

  var releaseCount: Int {
    lock.withLock { releaseCountValue }
  }

  func release() throws {
    lock.withLock {
      releaseCountValue += 1
    }
  }
}

final class FakeLifecycleJournalStore: ProxyOwnershipJournalStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var journalValue: ProxyOwnershipJournal?
  private var saveCountValue = 0
  private var removeCountValue = 0

  init(journal: ProxyOwnershipJournal? = nil) {
    journalValue = journal
  }

  var journal: ProxyOwnershipJournal? {
    lock.withLock { journalValue }
  }

  var saveCount: Int {
    lock.withLock { saveCountValue }
  }

  var removeCount: Int {
    lock.withLock { removeCountValue }
  }

  func load() throws -> ProxyOwnershipJournal? {
    lock.withLock { journalValue }
  }

  func save(_ journal: ProxyOwnershipJournal) throws {
    lock.withLock {
      saveCountValue += 1
      journalValue = journal
    }
  }

  func remove() throws {
    lock.withLock {
      removeCountValue += 1
      journalValue = nil
    }
  }
}

final class MemoryLifecycleJournalDataStore: JournalDataStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var data: Data?
  private var loadFailure: JournalAuthenticationError?
  private var saveFailure: JournalAuthenticationError?

  func load() throws(JournalAuthenticationError) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    if let loadFailure {
      throw loadFailure
    }
    return data
  }

  func save(_ data: Data) throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let saveFailure {
      throw saveFailure
    }
    self.data = data
  }

  func remove() throws(JournalAuthenticationError) {
    lock.withLock {
      data = nil
    }
  }

  func failLoads(with error: JournalAuthenticationError) {
    lock.withLock {
      loadFailure = error
    }
  }

  func failSaves(with error: JournalAuthenticationError) {
    lock.withLock {
      saveFailure = error
    }
  }
}

final class FakeLifecyclePreferences: SystemProxyPreferences, @unchecked Sendable {
  private let authorizationFailure: SystemProxyPreferencesError?
  func requireAuthorization() throws {
    if let authorizationFailure { throw authorizationFailure }
  }
  private let lock = NSLock()
  private var values: [SystemProxyField: ProxyPreferenceValue]
  private var prepareCountValue = 0
  private var applyCountValue = 0
  private var restoreCountValue = 0
  private var restoreFailuresRemaining = 0
  private let prepareFailure: SystemProxyPreferencesError?
  var applyFailsAfterPartialMutation = false

  init(
    values: [SystemProxyField: ProxyPreferenceValue] = [:],
    prepareFailure: SystemProxyPreferencesError? = nil,
    authorizationFailure: SystemProxyPreferencesError? = nil
  ) {
    self.values = values
    self.prepareFailure = prepareFailure
    self.authorizationFailure = authorizationFailure
  }

  var prepareCount: Int {
    lock.withLock { prepareCountValue }
  }

  var applyCount: Int {
    lock.withLock { applyCountValue }
  }

  var restoreCount: Int {
    lock.withLock { restoreCountValue }
  }

  func failNextRestore() {
    lock.withLock {
      restoreFailuresRemaining += 1
    }
  }

  func currentValue(_ field: SystemProxyField) -> ProxyPreferenceValue? {
    lock.withLock { values[field] }
  }

  func setExternalValue(_ value: ProxyPreferenceValue?, field: SystemProxyField) {
    lock.withLock {
      set(value, field: field)
    }
  }

  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal {
    try lock.withLock {
      prepareCountValue += 1
      if let prepareFailure { throw prepareFailure }
      return try Self.journal(
        configuration: configuration,
        endpoint: endpoint,
        originalValues: values
      )
    }
  }

  func apply(_ journal: ProxyOwnershipJournal) throws {
    try lock.withLock {
      applyCountValue += 1
      var changedFields = 0
      for service in journal.services {
        for field in service.fields {
          values[field.field] = field.appliedValue
          changedFields += 1
          if applyFailsAfterPartialMutation, changedFields == 1 {
            throw ForcedProxyFailure.requested
          }
        }
      }
    }
  }

  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult {
    try lock.withLock {
      restoreCountValue += 1
      if restoreFailuresRemaining > 0 {
        restoreFailuresRemaining -= 1
        throw ForcedProxyFailure.requested
      }
      var conflicts: [ProxyOwnershipConflict] = []
      for service in journal.services {
        for field in service.fields {
          let current = values[field.field]
          if current == field.appliedValue {
            set(field.originalValue, field: field.field)
          } else if current != field.originalValue {
            conflicts.append(
              ProxyOwnershipConflict(
                serviceID: service.serviceID,
                field: field.field,
                reason: .valueChanged(current: current)
              )
            )
          }
        }
      }
      return ProxyRestoreResult(conflicts: conflicts)
    }
  }

  private func set(_ value: ProxyPreferenceValue?, field: SystemProxyField) {
    if let value {
      values[field] = value
    } else {
      values.removeValue(forKey: field)
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
      guard let appliedValue = applied[field] else {
        throw ForcedProxyFailure.requested
      }
      return OwnedSystemProxyField(
        field: field,
        originalValue: originalValues[field],
        appliedValue: appliedValue
      )
    }
    return try ProxyOwnershipJournal(
      phase: .prepared,
      configuration: configuration,
      services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)]
    )
  }
}
