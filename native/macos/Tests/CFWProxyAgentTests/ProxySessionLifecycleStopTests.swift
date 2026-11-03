import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Stops: without a session, stale and repeated, and the settings restored
// before a stop.
extension ProxySessionLifecycleTests {
  /// A stop that reaches no session says so, so the Host can tell an owner that
  /// ended, whose successor holds nothing, from one holding another generation.
  @Test func stopWithoutASessionIsToldApartFromAStaleStop() throws {
    let fixture = makeLifecycleFixture()
    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: try descriptor(generation: 1)) {
      stop.record($0)
    }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.stopWithoutSession)])
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func staleStopDoesNotTouchActiveRuntimeOrPreferences() throws {
    let fixture = makeLifecycleFixture()
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
    let fixture = makeLifecycleFixture()
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

  /// Before its stop is ordered, an active session gives the OS back its
  /// settings while its engine still answers. It keeps its engine, lease and
  /// active state until the stop, which then has nothing left to restore.
  @Test func aRestoreBeforeAStopGivesTheSettingsBackWhileTheEngineRuns() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    try startActiveSession(fixture, activeConfiguration)
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))

    #expect(restoreBeforeStop(fixture, activeConfiguration) == [.success])
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(preferences.restoreCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  /// A restore before a stop that cannot reach the settings fails with the
  /// proxy still running and its settings and journal kept, so the stop can be
  /// asked again, and a later restore that reaches them gives them back.
  @Test func aRestoreBeforeAStopThatCannotReachTheSettingsKeepsTheProxyRunning() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    try startActiveSession(fixture, activeConfiguration)

    preferences.failNextRestore()
    guard case .failure(.preferences)? = restoreBeforeStop(fixture, activeConfiguration).first
    else {
      Issue.record("a restore that could not reach the settings did not fail")
      return
    }
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    #expect(fixture.journalStore.journal != nil)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)

    #expect(restoreBeforeStop(fixture, activeConfiguration) == [.success])
    #expect(preferences.currentValue(.httpHost) == .string("original"))
    #expect(fixture.journalStore.journal == nil)
  }

  /// Settings the user changed since the start stay the user's. The restore
  /// before the stop gives back the rest and lets the stop go ahead, which
  /// reports the change as it always did.
  @Test func aRestoreBeforeAStopLeavesTheUsersChangesForTheStopToReport() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    try startActiveSession(fixture, activeConfiguration)

    preferences.setExternalValue(.string("external"), field: .httpHost)
    #expect(restoreBeforeStop(fixture, activeConfiguration) == [.success])
    #expect(preferences.currentValue(.httpHost) == .string("external"))
    #expect(fixture.engine.stopCount == 0)

    let stop = OperationRecorder()
    fixture.lifecycle.stop(expectedConfiguration: activeConfiguration) { stop.record($0) }
    #expect(stop.wait())
    guard case .failure(.ownershipConflict)? = stop.values.first else {
      Issue.record("the stop did not report the user's change")
      return
    }
    #expect(fixture.engine.stopCount == 1)
  }

  /// Only the session the request names has settings to give back before its
  /// stop: with no session, one still starting, which applied none yet, or
  /// another generation's, the restore answers at once and changes nothing.
  @Test func aRestoreBeforeAStopOfAnotherSessionOrNoneChangesNothing() throws {
    let preferences = FakeLifecyclePreferences(values: [.httpHost: .string("original")])
    let fixture = makeLifecycleFixture(preferences: preferences)
    let activeConfiguration = try descriptor()
    #expect(restoreBeforeStop(fixture, activeConfiguration) == [.success])

    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: activeConfiguration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(restoreBeforeStop(fixture, activeConfiguration) == [.success])
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    #expect(restoreBeforeStop(fixture, try descriptor(generation: 2)) == [.success])
    #expect(preferences.restoreCount == 0)
    #expect(preferences.currentValue(.httpHost) == .string("127.0.0.1"))
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .proxyActive)
  }

  func startActiveSession(
    _ fixture: ProxyFixture, _ configuration: ConfigurationDescriptor
  ) throws {
    let start = OperationRecorder()
    fixture.lifecycle.start(configuration: configuration) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
  }

  private func restoreBeforeStop(
    _ fixture: ProxyFixture, _ configuration: ConfigurationDescriptor
  ) -> [OperationOutcome] {
    let restore = OperationRecorder()
    fixture.lifecycle.restoreSettingsBeforeStop(expectedConfiguration: configuration) {
      restore.record($0)
    }
    #expect(restore.wait())
    return restore.values
  }
}
