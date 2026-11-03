import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// Stops: during network settings, after a startup whose rollback release needs
// a retry, after a duplicate callback, and repeated.
extension ProviderLifecycleTests {
  @Test func stopDuringNetworkSettingsInvalidatesLateCallbacksAndCleansOnce() throws {
    let fixture = try makeProviderFixture(failingAt: nil)
    let start = StartCompletionRecorder()
    let stop = StopCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    #expect(fixture.engine.startCount == 0)

    fixture.lifecycle.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(successfulStopProof(stop.values.first) != nil)
    #expect(start.wait())
    #expect(start.values == [.startupCancelled])
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)

    fixture.settingsGate.complete(nil)
    fixture.settingsGate.complete(ForcedFailure.requested)
    _ = fixture.lifecycle.testingSnapshot()

    #expect(start.values.count == 1)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.pumpHolder.pump?.startCount == 0)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test(arguments: [StartupFailureStage.engineCreation, .pumpCreation])
  func failedStartupRetainsLeaseWhenRollbackReleaseNeedsRetry(
    stage: StartupFailureStage
  ) throws {
    let fixture = try makeProviderFixture(failingAt: stage)
    fixture.lease.failNextRelease()
    let start = StartCompletionRecorder()

    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values.count == 1)
    #expect(start.values[0] != nil)
    #expect(fixture.lease.releaseAttemptCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let blockedStart = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])

    let stop = StopCompletionRecorder()
    fixture.lifecycle.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(successfulStopProof(stop.values.first) != nil)
    #expect(fixture.lease.releaseAttemptCount == 2)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func duplicateNetworkSettingsCallbackCompletesStartExactlyOnce() throws {
    let fixture = try makeProviderFixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())

    fixture.settingsGate.complete(nil)
    fixture.settingsGate.complete(ForcedFailure.requested)
    #expect(start.wait())
    _ = fixture.lifecycle.testingSnapshot()

    #expect(start.values.count == 1)
    #expect(start.values[0] == nil)
    #expect(fixture.pumpHolder.pump?.startCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .tunnelActive)

    let stop = StopCompletionRecorder()
    fixture.lifecycle.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(successfulStopProof(stop.values.first) != nil)
  }

  @Test func repeatedStopIsIdempotentForAllOwnedResources() throws {
    let fixture = try makeProviderFixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())

    let firstStop = StopCompletionRecorder()
    fixture.lifecycle.stop { firstStop.record($0) }
    #expect(firstStop.wait())
    let secondStop = StopCompletionRecorder()
    fixture.lifecycle.stop { secondStop.record($0) }
    #expect(secondStop.wait())

    #expect(successfulStopProof(firstStop.values.first) != nil)
    #expect(successfulStopProof(secondStop.values.first) != nil)

    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.cancelRecorder.values.isEmpty)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }
}
