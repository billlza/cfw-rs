import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Cleanup that cannot be proven: unclosable engines, failed preference
// restores and stopped attestations, and the retries that settle them.
extension ProxySystemProxyOwnerCoordinatorTests {
  @Test func unclosableEngineNeverAttestsAndEndsTheProcessAfterTheStopReply() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(engineCloseFailure: closeFailure)
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
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { result in
      fixture.orderLog.record("stopReply")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.processEnds.wait())
    #expect(failedStop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["stopReply", "endProcess"])
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    // The owner context stays bound; a retry reaches neither libbox nor the
    // Authority and ends nothing again.
    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    let snapshot = SnapshotRecorder()
    fixture.coordinator.snapshot { snapshot.record($0) }
    #expect(snapshot.wait())
    #expect(snapshot.values.first?.state.failure?.code == "proxy-engine-unclosable")
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
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

  /// The coordinator keeps the owner context of a stop whose restore failed.
  /// Once the rights the user grants restored the settings, the Host's Off
  /// attests Stopped to the Authority and leaves the agent Off, without
  /// restoring again.
  @Test func settingsRestoredAfterAuthorizationLetTheNextStopAttestStopped() throws {
    let fixture = try makeFixture(preferencesRestoreFailures: 1)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    let failedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      failedStop.record($0)
    }
    #expect(failedStop.wait())
    #expect(fixture.authority.stoppedAttemptCount == 0)

    let restored = DispatchSemaphore(value: 0)
    fixture.coordinator.restoreSettingsAfterAuthorization { restored.signal() }
    #expect(restored.wait(timeout: .now() + 1) == .success)
    #expect(fixture.preferences.restoreCount == 2)

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.lease.operation)
    let snapshot = DispatchSemaphore(value: 0)
    let observed = Mutex<EngineSnapshot?>(nil)
    fixture.coordinator.snapshot { value in
      observed.withLock { $0 = value }
      snapshot.signal()
    }
    #expect(snapshot.wait(timeout: .now() + 1) == .success)
    #expect(observed.withLock { $0 }?.state.kind == .off)
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

  @Test func readinessFailureWithAnUnclosableEngineReportsUnprovenCleanupThenEnds() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(effectiveApplied: false, engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { result in
      fixture.orderLog.record("startReply")
      start.record(result)
    }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(fixture.processEnds.wait())
    guard case .failure(let failure) = start.values[0],
      failure.engineFailure.code == "proxy-cleanup-failed"
    else {
      Issue.record("Expected readiness failure to include the unproven cleanup")
      return
    }
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["startReply", "endProcess"])
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttemptCount == 0)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }

  /// A start whose engine fails and then cannot be closed is answered by the
  /// stop the coordinator queues for that failure, not by the failure itself,
  /// so the process ends only after that later stop handed over the reply.
  @Test func engineStartFailureWithAnUnclosableEngineRepliesBeforeTheProcessEnds() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(
      engineStartFailure: .runtime("libbox could not close its service instance"),
      engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { result in
      fixture.orderLog.record("startReply")
      start.record(result)
    }
    #expect(start.wait())
    #expect(fixture.processEnds.wait())
    guard case .failure(let failure) = start.values.first,
      failure.engineFailure.code == "proxy-cleanup-failed"
    else {
      Issue.record("Expected the failed start to include the unproven cleanup")
      return
    }
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["startReply", "endProcess"])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }
}
