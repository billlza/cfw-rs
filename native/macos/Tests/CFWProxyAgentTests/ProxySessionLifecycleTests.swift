import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Security
import Testing

@testable import CFWProxyAgentCore

private enum ForcedProxyFailure: Error {
  case requested
}

private struct SecretEchoFailure: LocalizedError {
  let secret: String
  var errorDescription: String? { "libbox echoed secret: \(secret)" }
}

private struct SecretEchoConfigurationChecker: LibboxConfigurationChecking {
  let secret: String

  func check(configuration: Data) throws {
    _ = configuration
    throw SecretEchoFailure(secret: secret)
  }
}

@Test func proxyValidationResponseNeverEchoesUnderlyingSecretError() throws {
  let secret = "credential-that-must-never-leave-agent"
  let service = ProxyAgentService(
    lifecycle: makeFixture().lifecycle,
    configurationChecker: SecretEchoConfigurationChecker(secret: secret)
  )
  let request = RequestEnvelope(
    command: try NativeCommand(
      kind: .validateConfiguration,
      configuration: descriptor()
    )
  )
  var responseData: Data?
  var responseError: NSError?
  service.validateConfiguration(
    Data("{\"password\":\"\(secret)\"}".utf8),
    request: try ProtocolCodec.encode(request)
  ) { data, error in
    responseData = data
    responseError = error
  }

  #expect(responseError == nil)
  let data = try #require(responseData)
  #expect(!String(decoding: data, as: UTF8.self).contains(secret))
  let response = try ProtocolCodec.decodeResponse(data)
  #expect(response.failure?.code == "configuration-validator-failed")
  #expect(
    response.failure?.message
      == "Configuration validation failed at an explicit internal boundary."
  )
}

private final class FakeProxyEngine: ProxyEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private var eventHandler: (@Sendable (ProxyEngineEvent) -> Void)?
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFails = false

  var startCount: Int {
    lock.withLock { startCountValue }
  }

  var stopCount: Int {
    lock.withLock { stopCountValue }
  }

  func start(
    configuration: Data,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    lock.withLock {
      startCountValue += 1
      self.eventHandler = eventHandler
    }
    started.signal()
  }

  func stop() throws {
    try lock.withLock {
      stopCountValue += 1
      if stopFails {
        throw ForcedProxyFailure.requested
      }
    }
  }

  func healthCheck() throws {}

  func setStopFails(_ value: Bool) {
    lock.withLock {
      stopFails = value
    }
  }

  func waitUntilStarted() -> Bool {
    started.wait(timeout: .now() + 1) == .success
  }

  func emit(_ event: ProxyEngineEvent) {
    let eventHandler = lock.withLock { self.eventHandler }
    eventHandler?(event)
  }
}

private struct FakeProxyEngineFactory: ProxyEngineFactory {
  let engine: FakeProxyEngine
  let creationFails: Bool

  func makeEngine(configuration: Data) throws -> any ProxyEngine {
    if creationFails {
      throw ForcedProxyFailure.requested
    }
    return engine
  }
}

private final class FakeLease: ProxyEngineLeaseHolding, @unchecked Sendable {
  private let lock = NSLock()
  private var releaseCountValue = 0
  private var failedStopCountValue = 0

  var releaseCount: Int {
    lock.withLock { releaseCountValue }
  }

  var failedStopCount: Int {
    lock.withLock { failedStopCountValue }
  }

  func release() throws {
    lock.withLock {
      releaseCountValue += 1
    }
  }

  func markStopFailed() throws {
    lock.withLock {
      failedStopCountValue += 1
    }
  }
}

private final class FakeJournalStore: ProxyOwnershipJournalStoring, @unchecked Sendable {
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

private final class MemoryLifecycleJournalDataStore: JournalDataStoring, @unchecked Sendable {
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

private final class FakeSystemProxyPreferences: SystemProxyPreferences, @unchecked Sendable {
  private let lock = NSLock()
  private var values: [SystemProxyField: ProxyPreferenceValue]
  private var prepareCountValue = 0
  private var applyCountValue = 0
  private var restoreCountValue = 0
  private var restoreFailuresRemaining = 0
  var applyFailsAfterPartialMutation = false

  init(values: [SystemProxyField: ProxyPreferenceValue] = [:]) {
    self.values = values
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

private enum OperationOutcome: Equatable {
  case success
  case failure(ProxySessionLifecycleError)
}

private final class OperationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let completed = DispatchSemaphore(value: 0)
  private var outcomes: [OperationOutcome] = []

  func record(_ result: Result<Void, ProxySessionLifecycleError>) {
    lock.withLock {
      switch result {
      case .success: outcomes.append(.success)
      case .failure(let error): outcomes.append(.failure(error))
      }
    }
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
  }

  var values: [OperationOutcome] {
    lock.withLock { outcomes }
  }
}

private struct ProxyFixture {
  let lifecycle: ProxySessionLifecycle
  let engine: FakeProxyEngine
  let lease: FakeLease
  let preferences: FakeSystemProxyPreferences
  let journalStore: FakeJournalStore
}

private func descriptor(generation: UInt64 = 1) throws -> ConfigurationDescriptor {
  guard
    let installationID = UUID(
      uuidString: "11111111-1111-1111-1111-111111111111"
    )
  else {
    throw ForcedProxyFailure.requested
  }
  return try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    installationID: installationID,
    epoch: 1,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

private func makeFixture(
  creationFails: Bool = false,
  preferences: FakeSystemProxyPreferences = FakeSystemProxyPreferences(),
  journalStore: FakeJournalStore = FakeJournalStore(),
  readinessTimeout: TimeInterval = 60
) -> ProxyFixture {
  let engine = FakeProxyEngine()
  let lease = FakeLease()
  let lifecycle = ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareConfiguration: { _ in
        PreparedProxyConfiguration(configuration: Data("{}".utf8), lease: lease)
      },
      recoverCleanupLease: { _ in lease },
      engineFactory: FakeProxyEngineFactory(
        engine: engine,
        creationFails: creationFails
      ),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: readinessTimeout
    )
  )
  return ProxyFixture(
    lifecycle: lifecycle,
    engine: engine,
    lease: lease,
    preferences: preferences,
    journalStore: journalStore
  )
}

private func readyEndpoint() throws -> MixedListenerEndpoint {
  try MixedListenerEndpoint(host: "127.0.0.1", port: 7_890)
}

private func keychainRecoveryStore(
  dataStore: any JournalDataStoring
) -> KeychainProxyOwnershipJournalStore {
  KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
}

private func recoveryLifecycle(
  preferences: FakeSystemProxyPreferences,
  journalStore: any ProxyOwnershipJournalStoring
) -> ProxySessionLifecycle {
  let engine = FakeProxyEngine()
  let lease = FakeLease()
  return ProxySessionLifecycle(
    dependencies: ProxySessionDependencies(
      prepareConfiguration: { _ in
        PreparedProxyConfiguration(configuration: Data("{}".utf8), lease: lease)
      },
      recoverCleanupLease: { _ in lease },
      engineFactory: FakeProxyEngineFactory(engine: engine, creationFails: false),
      preferences: preferences,
      journalStore: journalStore,
      readinessTimeout: 60
    )
  )
}

@Suite(.serialized)
struct ProxySessionLifecycleTests {
  @Test func preferencesAreNotAppliedBeforeMixedListenerReadiness() throws {
    let fixture = makeFixture()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())

    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(start.values.isEmpty)

    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(fixture.preferences.applyCount == 1)
    #expect(fixture.journalStore.journal?.phase == .applied)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  @Test func applyFailureRollsBackPreferencesAndStopsEngine() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    preferences.applyFailsAfterPartialMutation = true
    let fixture = makeFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func externalModificationIsPreservedAndReportedAsOwnershipConflict() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    preferences.setExternalValue(.string("external"), field: .httpHost)
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    guard case .failure(.ownershipConflict(let conflicts)) = stop.values[0] else {
      Issue.record("Expected an explicit ownership conflict")
      return
    }
    #expect(conflicts.count == 1)
    #expect(conflicts[0].field == .httpHost)
    #expect(preferences.currentValue(.httpHost) == .string("external"))
    #expect(preferences.currentValue(.httpsHost) == nil)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.journalStore.journal != nil)

    let repeatedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) {
      repeatedStop.record($0)
    }
    #expect(repeatedStop.wait())
    guard case .failure(.ownershipConflict) = repeatedStop.values[0] else {
      Issue.record("Repeated stop must retain the ownership conflict")
      return
    }
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)

    let blockedStart = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) {
      blockedStart.record($0)
    }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.failure(.lifecycleConflict)])

    preferences.setExternalValue(.string("original"), field: .httpHost)
    let resolvedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { resolvedStop.record($0) }
    #expect(resolvedStop.wait())
    #expect(resolvedStop.values == [.success])
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.journalStore.journal == nil)
  }

  @Test func engineCrashRestoresPreferencesAndReleasesLease() throws {
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let fixture = makeFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    fixture.engine.emit(
      .failed(ProxyEngineFailure(code: "engine-exited", message: "terminated"))
    )
    _ = fixture.lifecycle.testingSnapshot()

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func engineCrashBeforeReadinessNeverPublishesProxySettings() throws {
    let fixture = makeFixture()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())

    let failure = ProxyEngineFailure(code: "startup-crash", message: "terminated")
    fixture.engine.emit(.failed(failure))
    #expect(start.wait())

    #expect(start.values == [.failure(.engineFailed(failure))])
    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func listenerReadinessTimeoutStopsEngineWithoutPublishingPreferences() throws {
    let fixture = makeFixture(readinessTimeout: 0.01)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(start.wait())

    #expect(start.values == [.failure(.listenerReadinessTimedOut)])
    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
  }

  @Test func staleStopDoesNotTouchActiveRuntimeOrPreferences() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor(generation: 1)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: try descriptor(generation: 2)) {
      stop.record($0)
    }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.staleStopRequest)])
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.preferences.restoreCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  @Test func repeatedStopAfterSuccessfulCleanupIsIdempotent() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let firstStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { firstStop.record($0) }
    #expect(firstStop.wait())
    let secondStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { secondStop.record($0) }
    #expect(secondStop.wait())

    #expect(firstStop.values == [.success])
    #expect(secondStop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func lateReadyCallbackAfterStopCannotApplyPreferences() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    #expect(start.wait())
    #expect(start.values == [.failure(.startupCancelled)])
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    _ = fixture.lifecycle.testingSnapshot()

    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func engineStopFailureRetainsLeaseUntilAConfirmedRetry() throws {
    let fixture = makeFixture()
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.setStopFails(true)

    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    guard case .failure(.engineStop) = failedStop.values[0] else {
      Issue.record("Expected an explicit engine stop failure")
      return
    }
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    fixture.engine.setStopFails(false)
    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.stopCount == 2)
    #expect(fixture.lease.releaseCount == 1)
  }

  @Test func missingLibboxFailsBeforeLeaseOrPreferences() throws {
    let fixture = makeFixture(creationFails: true)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineCreation) = start.values[0] else {
      Issue.record("Expected fail-closed engine creation failure")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.preferences.prepareCount == 0)
    #expect(fixture.preferences.applyCount == 0)
  }

  @Test func persistedJournalIsRecoveredBeforeNewCommands() throws {
    let activeConfiguration = try descriptor()
    let endpoint = try readyEndpoint()
    let prepared = try FakeSystemProxyPreferences.journal(
      configuration: activeConfiguration,
      endpoint: endpoint,
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(prepared)
    let journalStore = FakeJournalStore(journal: prepared)

    let fixture = makeFixture(preferences: preferences, journalStore: journalStore)

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func failedRestorePublicationRetainsJournalUntilExplicitRetry() throws {
    let configuration = try descriptor()
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    let journalStore = FakeJournalStore(journal: journal)
    let fixture = makeFixture(preferences: preferences, journalStore: journalStore)

    #expect(preferences.restoreCount == 1)
    #expect(journalStore.journal == journal)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(preferences.restoreCount == 2)
    #expect(journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func preparedKeychainJournalRecoversCrashAfterPreferencesApply() throws {
    let configuration = try descriptor()
    let preparedJournal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    )
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(preparedJournal)
    let dataStore = MemoryLifecycleJournalDataStore()
    let initialStore = keychainRecoveryStore(dataStore: dataStore)
    try initialStore.save(preparedJournal)

    let restartedStore = keychainRecoveryStore(dataStore: dataStore)
    let lifecycle = recoveryLifecycle(
      preferences: preferences,
      journalStore: restartedStore
    )

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(try restartedStore.load() == nil)
    #expect(lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func unavailableKeychainBlocksRecoveryWithoutChangingPreferences() throws {
    let configuration = try descriptor()
    let journal = try FakeSystemProxyPreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeSystemProxyPreferences()
    try preferences.apply(journal)
    let dataStore = MemoryLifecycleJournalDataStore()
    let unavailableStore = keychainRecoveryStore(dataStore: dataStore)
    try unavailableStore.save(journal)
    dataStore.failLoads(with: .keychainReadFailed(errSecInteractionNotAllowed))

    let lifecycle = recoveryLifecycle(
      preferences: preferences,
      journalStore: unavailableStore
    )

    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    #expect(preferences.restoreCount == 0)
    #expect(lifecycle.testingSnapshot().state.kind == .failed)

    let start = OperationRecorder()
    lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(start.wait())
    guard case .failure(.recoveryBlocked) = start.values[0] else {
      Issue.record("Expected authentication failure to block all new starts")
      return
    }
    #expect(preferences.applyCount == 1)
    #expect(preferences.restoreCount == 0)
  }

  @Test func unavailableKeychainBlocksActivationBeforeChangingPreferences() throws {
    let dataStore = MemoryLifecycleJournalDataStore()
    dataStore.failSaves(with: .keychainWriteFailed(errSecInteractionNotAllowed))
    let unavailableStore = keychainRecoveryStore(dataStore: dataStore)
    let preferences = FakeSystemProxyPreferences(values: [.httpHost: .string("original")])
    let engine = FakeProxyEngine()
    let lease = FakeLease()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareConfiguration: { _ in
          PreparedProxyConfiguration(configuration: Data("{}".utf8), lease: lease)
        },
        recoverCleanupLease: { _ in lease },
        engineFactory: FakeProxyEngineFactory(engine: engine, creationFails: false),
        preferences: preferences,
        journalStore: unavailableStore,
        readinessTimeout: 60
      )
    )
    let start = OperationRecorder()
    lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(engine.waitUntilStarted())

    engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.ownershipJournal) = start.values[0] else {
      Issue.record("Expected Keychain failure to abort authenticated journal persistence")
      return
    }
    #expect(preferences.prepareCount == 1)
    #expect(preferences.applyCount == 0)
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(engine.stopCount == 1)
    #expect(lease.releaseCount == 1)
  }
}
