import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Local proxy sessions, and system proxy starts: authorization, listener
// readiness, preference writes and their conflicts, and engine crashes and
// timeouts.
@Suite(.serialized)
struct ProxySessionLifecycleTests {
  @Test func localProxyStartsWithoutNetworkAuthorizationAndNeverWritesPreferences() throws {
    let preferences = FakeLifecyclePreferences(
      values: [.httpHost: .string("other-app"), .httpPort: .integer(7890)],
      authorizationFailure: .authorizationDenied(-60007))
    let fixture = makeLifecycleFixture(preferences: preferences)
    let configuration = try descriptor(slot: .localProxy)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(start.values.isEmpty)
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(fixture.lifecycle.testingSnapshot().mode == .localProxy)
    #expect(preferences.prepareCount == 0)
    #expect(preferences.applyCount == 0)
    #expect(fixture.journalStore.saveCount == 0)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpHost) == .string("other-app"))
    #expect(preferences.currentValue(.httpPort) == .integer(7890))
    #expect(fixture.lifecycle.testingSnapshot().mode == .off)
  }

  @Test func localProxyStopRequiresExactModeAndEndsTheProcessWhenItsEngineCannotClose() throws {
    let fixture = makeLifecycleFixture()
    let configuration = try descriptor(slot: .localProxy)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let wrongMode = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: try descriptor()) { wrongMode.record($0) }
    #expect(wrongMode.wait())
    #expect(wrongMode.values == [.failure(.staleStopRequest)])
    #expect(fixture.engine.stopCount == 0)
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.endRecorder.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.events.values == ["stop", "end"])
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
    #expect(fixture.lifecycle.testingSnapshot().mode == .localProxy)
    #expect(fixture.lease.releaseCount == 0)

    // libbox closes an instance once, so a retry reports the same cause without
    // reaching the engine or ending the process again.
    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.endRecorder.values == [.engineUnclosable(closeFailure)])
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.preferences.restoreCount == 0)
  }

  @Test func legacyJournalKeepsItsIdentityAndRecoversBeforeLocalProxyStart() throws {
    // This is the pre-LocalProxy descriptor wire shape. Its identity is retained,
    // not recomputed with the new configuration identity schema.
    let legacyDescriptor = Data(
      #"{"slot":"systemProxy","credentialAudience":{"profile_id":"11111111-1111-1111-1111-111111111111","profile_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"installationID":"11111111-1111-1111-1111-111111111111","epoch":1,"generation":1,"byteCount":2,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","identitySHA256":"1111111111111111111111111111111111111111111111111111111111111111","credentialSlots":[]}"#
        .utf8)
    let oldConfiguration = try JSONDecoder().decode(
      ConfigurationDescriptor.self, from: legacyDescriptor)
    let oldJournal = try FakeLifecyclePreferences.journal(
      configuration: oldConfiguration, endpoint: readyEndpoint(),
      originalValues: [.httpHost: .string("original")]
    ).markingApplied()
    let services = String(decoding: try JSONEncoder().encode(oldJournal.services), as: UTF8.self)
    let legacyJournal = Data(
      "{\"schemaVersion\":1,\"phase\":\"applied\",\"configuration\":\(String(decoding: legacyDescriptor, as: UTF8.self)),\"services\":\(services)}"
        .utf8)
    let recovered = try JSONDecoder().decode(ProxyOwnershipJournal.self, from: legacyJournal)
    #expect(recovered.configuration.identitySHA256.hex == String(repeating: "11", count: 32))
    #expect(recovered.configuration.slot == .systemProxy)
    let preferences = FakeLifecyclePreferences()
    try preferences.apply(recovered)
    let store = FakeLifecycleJournalStore(journal: recovered)
    let fixture = makeLifecycleFixture(preferences: preferences, journalStore: store)
    #expect(preferences.restoreCount == 1)
    #expect(store.journal == nil)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor(generation: 2, slot: .localProxy)) {
      start.record($0)
    }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(store.saveCount == 0)
    #expect(preferences.applyCount == 1)
    #expect(preferences.restoreCount == 1)
  }

  @Test func unresolvedOldOwnershipPreventsLocalProxyStart() throws {
    let journal = try FakeLifecyclePreferences.journal(
      configuration: descriptor(), endpoint: readyEndpoint(), originalValues: [:]
    ).markingApplied()
    let preferences = FakeLifecyclePreferences()
    preferences.failNextRestore()
    let store = FakeLifecycleJournalStore(journal: journal)
    let fixture = makeLifecycleFixture(preferences: preferences, journalStore: store)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor(generation: 2, slot: .localProxy)) {
      start.record($0)
    }
    #expect(start.wait())
    #expect(start.values == [.failure(.lifecycleConflict)])
    #expect(fixture.engine.startCount == 0)
    #expect(store.journal == journal)
  }

  @Test func ungrantedAuthorizationStartsNoEngineAndWritesNoPreferences() throws {
    let preferences = FakeLifecyclePreferences(
      authorizationFailure: .authorizationDenied(-60007))
    let fixture = makeLifecycleFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.failure(.authorizationRequired)])
    #expect(fixture.engine.startCount == 0)
    #expect(preferences.prepareCount == 0)
    #expect(preferences.applyCount == 0)
    #expect(fixture.journalStore.journal == nil)
  }

  @Test func existingProxyFailurePreservesTheCauseAndMakesNoPreferenceWrite() throws {
    let preferences = FakeLifecyclePreferences(
      values: [.httpEnabled: .integer(1), .httpPort: .integer(7_890)],
      prepareFailure: .existingProxyConfiguration(serviceID: "other-app", field: .httpEnabled))
    let fixture = makeLifecycleFixture(preferences: preferences)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: try descriptor()) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.failure(.existingSystemProxy)])
    #expect(
      ProxySessionLifecycleError.existingSystemProxy.engineFailure.code == "existing-system-proxy")
    #expect(preferences.applyCount == 0)
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpPort) == .integer(7_890))
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.journalStore.journal == nil)
  }

  @Test func preferencesAreNotAppliedBeforeMixedListenerReadiness() throws {
    let fixture = makeLifecycleFixture()
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
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    preferences.applyFailsAfterPartialMutation = true
    let fixture = makeLifecycleFixture(preferences: preferences)
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
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
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
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
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
    let fixture = makeLifecycleFixture()
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

  @Test func libboxStartTimeoutFailsTheStartCleanlyWithItsOwnCause() throws {
    let runtime = TimedOutLibboxRuntime()
    let lease = FakeLease()
    let preferences = FakeLifecyclePreferences()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { _ in PreparedProxyOwnership(lease: lease) },
        resolveConfiguration: { _, _ in receiptConfiguration() },
        recoverCleanupLease: { _ in lease },
        engineFactory: LibboxProxyEngineFactory(
          runtimeFactory: StubLibboxRuntimeFactory(runtime: runtime)),
        preferences: preferences,
        journalStore: FakeLifecycleJournalStore(),
        readinessTimeout: 60,
        endProcess: { _ in Issue.record("a runtime that timed out still closes") }))
    let configuration = try descriptor()
    let deadline = EngineStartDeadline(receivedAt: .now)
    let start = OperationRecorder()
    lifecycle.start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: configuration,
      deadline: deadline
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.failure(.engineStartTimedOut)])
    #expect(runtime.deadlines == [deadline])
    #expect(runtime.stopCount == 1)
    #expect(lease.releaseCount == 1)
    #expect(preferences.prepareCount == 0)
    #expect(preferences.applyCount == 0)
    #expect(
      lifecycle.testingSnapshot().state.failure?.code
        == ProxyAgentFailureCode.engineStartTimedOut.rawValue)

    let stop = OperationRecorder()
    lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(lifecycle.testingSnapshot().mode == .off)
    #expect(runtime.stopCount == 1)
  }

  @Test func listenerReadinessTimeoutStopsEngineWithoutPublishingPreferences() throws {
    let fixture = makeLifecycleFixture(readinessTimeout: 0.01)
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
}
