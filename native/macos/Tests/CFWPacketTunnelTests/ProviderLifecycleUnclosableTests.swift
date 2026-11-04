import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// Spent lifecycles and unclosable engines: the process end armed before the
// stop completes or the start fails, and pump failures cancelled once.
extension ProviderLifecycleTests {
  /// With the extension's process end armed, the failure's own stop
  /// completion ends nothing: the extension ends once Network Extension's stop
  /// was answered after it, and a start in between is refused.
  @Test func aSpentLifecycleEndsTheExtensionOnlyAfterTheStopWasAnswered() throws {
    let manual = ManualProcessEnd()
    let processEnd = manual.processEnd()
    let fixture = try makeProviderFixture(failingAt: nil, processEnd: processEnd)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    let failedStop = StopCompletionRecorder()
    let completion = PacketTunnelProvider.stopCompletion(
      { fixture.events.record("answered") }, processEnd: processEnd)
    fixture.lifecycle.stop { result in
      completion()
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(unclosableFailure(failedStop.values.first) == closeFailure)
    #expect(fixture.events.values == ["end", "answered"])
    #expect(manual.exits.isEmpty, "the end ran inside the stop's completion")
    #expect(PacketTunnelProvider.startRefusal(processEnd, configuration: fixture.descriptor) != nil)
    try #require(manual.deadlines.count == 2)
    manual.run(1)
    #expect(manual.exits == [EX_SOFTWARE])
  }

  @Test func unclosableEngineIsSpentAndArmsTheProcessEndBeforeTheStopCompletes() throws {
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
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    let failedStop = StopCompletionRecorder()
    fixture.lifecycle.stop { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.endRecorder.wait())
    #expect(unclosableFailure(failedStop.values.first) == closeFailure)
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "stop"])
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    let failed = fixture.lifecycle.testingSnapshot()
    #expect(failed.state.kind == .failed)
    #expect(failed.state.failure?.code == "tunnel-engine-unclosable")

    // The extension is spent: no stop reaches libbox again, no start begins,
    // and the process ends once.
    let secondStop = StopCompletionRecorder()
    fixture.lifecycle.stop { secondStop.record($0) }
    #expect(secondStop.wait())
    #expect(unclosableFailure(secondStop.values.first) == closeFailure)
    let blockedStart = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.engineUnclosable(closeFailure)])
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.leaseAcquisitionCounter.count == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.endRecorder.values.count == 1)
    #expect(fixture.cancelRecorder.values.isEmpty)
  }

  @Test func unclosableEngineAfterAFailedStartArmsTheProcessEndThenFailsTheStart() throws {
    let fixture = try makeProviderFixture(failingAt: .engineStart)
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close failed service")
    fixture.engine.failStops(with: closeFailure)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { error in
      fixture.events.record("start")
      start.record(error)
    }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    #expect(fixture.endRecorder.wait())

    #expect(start.values == [.engineUnclosable(closeFailure)])
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "start"])
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.cancelRecorder.values.isEmpty)
    #expect(
      fixture.lifecycle.testingSnapshot().state.failure?.code == "tunnel-engine-unclosable")
  }

  @Test func unclosableEngineAfterAPumpFailureArmsTheProcessEndThenCancelsTheTunnel() throws {
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
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    let pump = try #require(fixture.pumpHolder.pump)

    pump.fail(.packetFlowWriteFailed)
    pump.fail(.socketReadFailed(EIO))
    #expect(fixture.cancelRecorder.wait())
    #expect(fixture.endRecorder.wait())
    _ = fixture.lifecycle.testingSnapshot()

    #expect(fixture.cancelRecorder.values == [.engineUnclosable(closeFailure)])
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "cancel"])
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(pump.stopCount == 1)
  }

  @Test func repeatedRuntimePumpFailureCancelsAndCleansExactlyOnce() throws {
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
    let pump = try #require(fixture.pumpHolder.pump)

    pump.fail(.packetFlowWriteFailed)
    pump.fail(.socketReadFailed(EIO))
    #expect(fixture.cancelRecorder.wait())
    _ = fixture.lifecycle.testingSnapshot()

    #expect(fixture.cancelRecorder.values == [.packetPump(.packetFlowWriteFailed)])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(pump.stopCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }
}
