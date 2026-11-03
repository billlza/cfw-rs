import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Retiring and spent agents, quarantined stops, late readiness, engines and
// runtimes that cannot close, and a missing libbox.
/// A check or probe that must never reach "libbox".
private struct UnreachedLibbox: LibboxConfigurationChecking, LibboxProfileProbing {
  func check(configuration: Data) throws {
    Issue.record("a configuration check reached libbox")
  }

  func test(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) throws -> [ProfileProxyDelay] {
    Issue.record("a profile probe reached libbox")
    return []
  }
}

extension ProxySessionLifecycleTests {
  /// A start its owner admitted just as the agent retired fails without a
  /// session, and its stop finds that failure, so the owner proves Off.
  @Test func aStartAsTheAgentRetiresFailsWithoutASession() throws {
    let fixture = makeLifecycleFixture()
    let configuration = try descriptor()
    fixture.lifecycle.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    #expect(!fixture.lifecycle.callsLibbox)
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.failure(.agentEnding)])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
    #expect(fixture.endRecorder.values.isEmpty)
  }

  /// A retired agent ends only when its owner asks and only once it holds no
  /// session, so no settings it applied outlive it, and it ends once.
  @Test func aRetiredAgentEndsOnlyWithoutASessionWhenItsOwnerAsks() throws {
    let fixture = makeLifecycleFixture()
    let activeConfiguration = try descriptor()
    try startActiveSession(fixture, activeConfiguration)
    fixture.lifecycle.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    fixture.lifecycle.endProcessIfRetired()
    // Each read waits for the work queued before it, the end's second hop too.
    _ = fixture.lifecycle.testingSnapshot()
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.endRecorder.values.isEmpty)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    _ = fixture.lifecycle.testingSnapshot()
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.endRecorder.values.isEmpty)

    fixture.lifecycle.endProcessIfRetired()
    fixture.lifecycle.endProcessIfRetired()
    #expect(fixture.endRecorder.wait())
    _ = fixture.lifecycle.testingSnapshot()
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.endRecorder.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
  }

  /// libbox may still hold what a spent agent could not close, so the agent
  /// checks and probes nothing more and answers that it is ending.
  @Test func aSpentAgentRefusesChecksAndProbes() throws {
    let fixture = makeLifecycleFixture()
    let activeConfiguration = try descriptor()
    try startActiveSession(fixture, activeConfiguration)
    fixture.engine.failStops(with: LibboxInstanceUnclosable(closeFailure: "close network: monitor"))
    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(!fixture.lifecycle.callsLibbox)

    let service = ProxyAgentService(
      lifecycle: ValidationOnlyProxyOwner(lifecycle: fixture.lifecycle),
      configurationChecker: UnreachedLibbox(),
      preferences: SCPreferencesSystemProxyPreferences(),
      journalStore: FakeLifecycleJournalStore(),
      profileProbe: UnreachedLibbox()
    )
    let (data, error) = try validationReply(
      service, Data("{}".utf8),
      RequestEnvelope(
        command: try NativeCommand(kind: .validateConfiguration, configuration: descriptor())))
    #expect(error == nil)
    let failure = try #require(try ProtocolCodec.decodeResponse(data).failure)
    #expect(failure.code == "proxy-agent-ending")
    #expect(failure.isRetryable)

    let probed = DispatchSemaphore(value: 0)
    let probeError = Mutex<NSError?>(nil)
    service.testProfileProxies(
      Data("{}".utf8), proxies: try JSONEncoder().encode(["p"]), timeoutMS: 500, targetURL: "",
      expectedStatus: ""
    ) { _, error in
      probeError.withLock { $0 = error }
      probed.signal()
    }
    #expect(probed.wait(timeout: .now() + 5) == .success)
    let refused = try #require(probeError.withLock { $0 })
    #expect(refused.domain == ProfileProbeServiceFailure.domain)
    #expect(refused.code == ProfileProbeServiceFailure.agentEnding.rawValue)
  }

  /// An agent whose stop the Authority quarantined ends only once it holds no
  /// session, so no System Proxy settings it applied outlive it, and it ends
  /// once however often it is asked.
  @Test func aQuarantinedStopEndsOnlyAnAgentWithoutASessionAndOnlyOnce() throws {
    let fixture = makeLifecycleFixture()
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    fixture.lifecycle.endProcessAfterQuarantinedStop()
    // Each read waits for the work queued before it, the end's second hop too.
    _ = fixture.lifecycle.testingSnapshot()
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.endRecorder.values.isEmpty)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    fixture.lifecycle.endProcessAfterQuarantinedStop()
    fixture.lifecycle.endProcessAfterQuarantinedStop()
    #expect(fixture.endRecorder.wait())
    _ = fixture.lifecycle.testingSnapshot()
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.endRecorder.values == [.quarantinedStop])
  }

  @Test func lateReadyCallbackAfterStopCannotApplyPreferences() throws {
    let fixture = makeLifecycleFixture()
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

  @Test func unclosableEngineEndsTheProcessAfterItsSettingsAreRestored() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    let failedStop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.endRecorder.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.events.values == ["stop", "end"])
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.lease.releaseCount == 0)
    let failed = fixture.lifecycle.testingSnapshot()
    #expect(failed.state.kind == .failed)
    #expect(failed.state.failure?.code == "proxy-engine-unclosable")

    // Nothing the engine reports afterwards revives the session.
    fixture.engine.emit(.failed(ProxyEngineFailure(code: "crash", message: "Runtime exited.")))
    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    let blockedStart = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.failure(.engineUnclosable(closeFailure))])
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(preferences.restoreCount == 1)
    #expect(fixture.endRecorder.values == [.engineUnclosable(closeFailure)])
  }

  @Test func unclosableEngineKeepsTheProcessUntilItsSettingsAreRestored() throws {
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
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    _ = fixture.lifecycle.testingSnapshot()
    // Only this process holds the authorization to restore the settings
    // without asking the user again, so it stays until they are restored.
    #expect(fixture.endRecorder.values.isEmpty)
    #expect(fixture.journalStore.journal != nil)
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))

    let retry = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { result in
      fixture.events.record("stop")
      retry.record(result)
    }
    #expect(retry.wait())
    #expect(fixture.endRecorder.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.events.values == ["stop", "stop", "end"])
    #expect(preferences.restoreCount == 2)
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.endRecorder.values == [.engineUnclosable(closeFailure)])
  }

  @Test func unclosableRuntimeFailsTheStartAndLeavesTheAgentSpent() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close failed service")
    let runtime = UnclosableLibboxRuntime(closeFailure: closeFailure)
    let lease = FakeLease()
    let events = EventLog()
    let ends = EndProcessRecorder()
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { _ in PreparedProxyOwnership(lease: lease) },
        resolveConfiguration: { _, _ in receiptConfiguration() },
        recoverCleanupLease: { _ in lease },
        engineFactory: LibboxProxyEngineFactory(
          runtimeFactory: StubLibboxRuntimeFactory(runtime: runtime)),
        preferences: FakeLifecyclePreferences(),
        journalStore: FakeLifecycleJournalStore(),
        readinessTimeout: 60,
        endProcess: { failure in
          events.record("end")
          ends.record(failure)
        }))
    let configuration = try descriptor()
    let start = OperationRecorder()
    lifecycle.start(
      configuration: SensitiveDataBuffer(copying: Data("{}".utf8)),
      descriptor: configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { result in
      events.record("start")
      start.record(result)
    }
    #expect(start.wait())
    #expect(ends.wait())
    #expect(start.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(events.values == ["start", "end"])
    #expect(lifecycle.testingSnapshot().state.failure?.code == "proxy-engine-unclosable")
    #expect(lease.releaseCount == 0)

    let blockedStart = OperationRecorder()
    lifecycle.start(configuration: configuration) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.failure(.engineUnclosable(closeFailure))])
    let stop = OperationRecorder()
    lifecycle.stop(expectedConfiguration: configuration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.engineUnclosable(closeFailure))])
    _ = lifecycle.testingSnapshot()
    #expect(runtime.startCount == 1)
    #expect(runtime.stopCount == 1)
    #expect(ends.values == [.engineUnclosable(closeFailure)])
  }

  @Test func missingLibboxFailsBeforeLeaseOrPreferences() throws {
    let fixture = makeLifecycleFixture(creationFails: true)
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
}
