import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Ownership journal recovery: restores retried once the user grants the
// rights, and the Keychain journal's recovery and activation.
extension ProxySessionLifecycleTests {
  @Test func persistedJournalIsRecoveredBeforeNewCommands() throws {
    let activeConfiguration = try descriptor()
    let endpoint = try readyEndpoint()
    let prepared = try FakeLifecyclePreferences.journal(
      configuration: activeConfiguration,
      endpoint: endpoint,
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeLifecyclePreferences()
    try preferences.apply(prepared)
    let journalStore = FakeLifecycleJournalStore(journal: prepared)

    let fixture = makeLifecycleFixture(preferences: preferences, journalStore: journalStore)

    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(preferences.restoreCount == 1)
    #expect(journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func failedRestorePublicationRetainsJournalUntilExplicitRetry() throws {
    let configuration = try descriptor()
    let journal = try FakeLifecyclePreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    let journalStore = FakeLifecycleJournalStore(journal: journal)
    let fixture = makeLifecycleFixture(preferences: preferences, journalStore: journalStore)

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

  /// A launch whose recovery could not restore the settings, for example
  /// because the agent had no rights yet, restores them once the user grants
  /// the rights, which the Host asks for before every Off and before quitting.
  @Test func failedRecoveryRestoresOnceTheUserGrantsTheRights() throws {
    let configuration = try descriptor()
    let journal = try FakeLifecyclePreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    let journalStore = FakeLifecycleJournalStore(journal: journal)
    let fixture = makeLifecycleFixture(preferences: preferences, journalStore: journalStore)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 2)
    #expect(journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
    // The Host's Off for that generation then succeeds without restoring again.
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(preferences.restoreCount == 2)
  }

  @Test func restoreThatStillFailsAfterAuthorizationKeepsItsJournal() throws {
    let configuration = try descriptor()
    let journal = try FakeLifecyclePreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    preferences.failNextRestore()
    preferences.failNextRestore()
    let journalStore = FakeLifecycleJournalStore(journal: journal)
    let fixture = makeLifecycleFixture(preferences: preferences, journalStore: journalStore)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 2)
    #expect(journalStore.journal == journal)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  /// A spent agent whose restore failed restores the settings once the user
  /// grants the rights again, and then ends.
  @Test func spentAgentRestoresOnceTheUserGrantsTheRightsThenEnds() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    preferences.failNextRestore()
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.endRecorder.values.isEmpty)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(fixture.endRecorder.wait())
    #expect(preferences.restoreCount == 2)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.endRecorder.values == [.engineUnclosable(closeFailure)])
  }

  /// A stop whose engine stopped but whose restore failed leaves the session
  /// failed with its journal; the rights the user grants restore the settings,
  /// and the Host's Off for that generation then succeeds without restoring
  /// again.
  @Test func aStopWhoseRestoreFailedRestoresOnceTheUserGrantsTheRights() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let configuration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    preferences.failNextRestore()
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(failedStop.values != [.success])
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 2)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(preferences.restoreCount == 2)
  }

  /// A spent agent ends only once its settings are restored: rights that still
  /// do not restore them leave it running with its journal.
  @Test func aSpentAgentWhoseRestoreStillFailsKeepsRunning() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let configuration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.failStops(
      with: LibboxInstanceUnclosable(closeFailure: "close network: monitor"))
    preferences.failNextRestore()
    preferences.failNextRestore()
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { failedStop.record($0) }
    #expect(failedStop.wait())

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    // Anything the restore queued behind itself has run by now.
    _ = fixture.lifecycle.testingSnapshot()
    #expect(preferences.restoreCount == 2)
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.endRecorder.values.isEmpty)
  }

  @Test func grantedRightsWithNothingLeftToRestoreChangeNothing() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 0)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot() == .off)
  }

  /// Granted rights change nothing for a session whose engine runs: its
  /// settings stay applied until it stops.
  @Test func grantedRightsLeaveARunningSessionsSettingsApplied() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    #expect(restoreAfterAuthorization(fixture.lifecycle))
    #expect(preferences.restoreCount == 0)
    #expect(fixture.journalStore.journal != nil)
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  @Test func preparedKeychainJournalRecoversCrashAfterPreferencesApply() throws {
    let configuration = try descriptor()
    let preparedJournal = try FakeLifecyclePreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    )
    let preferences = FakeLifecyclePreferences()
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
    let journal = try FakeLifecyclePreferences.journal(
      configuration: configuration,
      endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let preferences = FakeLifecyclePreferences()
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
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let engine = FakeLifecycleEngine()
    let lease = FakeLease()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { _ in
          PreparedProxyOwnership(lease: lease)
        },
        recoverCleanupLease: { _ in lease },
        engineFactory: FakeLifecycleEngineFactory(engine: engine, creationFails: false),
        preferences: preferences,
        journalStore: unavailableStore,
        readinessTimeout: 60,
        endProcess: { _ in Issue.record("every engine in this test closes") }
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
