import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// The production clocks and budgets: the deadline's tolerance, the interrupt
// limit in awake time, and the durations the budgets name.
/// The continuous clock, recording each sleep the watchdog asks it for and when
/// that sleep ends.
private struct RecordingContinuousClock: Clock {
  typealias Instant = ContinuousClock.Instant

  enum Event: Equatable, Sendable {
    case began(deadline: Instant, tolerance: Duration?)
    case ended
  }

  let events: AsyncStream<Event>.Continuation

  var now: Instant { ContinuousClock.now }
  var minimumResolution: Duration { ContinuousClock().minimumResolution }

  func sleep(until deadline: Instant, tolerance: Duration?) async throws {
    events.yield(.began(deadline: deadline, tolerance: tolerance))
    defer { events.yield(.ended) }
    try await ContinuousClock().sleep(until: deadline, tolerance: tolerance)
  }
}

/// Without an explicit tolerance the system may fire an 11-second sleep about a
/// second late, which the Host's waits do not leave room for. Cancelling the
/// deadline, as a start that returned in time does, ends the sleep at once.
@Test func productionDeadlineSleepsWithTheBudgetToleranceUntilCancelled() async throws {
  let (events, recorder) = AsyncStream.makeStream(of: RecordingContinuousClock.Event.self)
  let deadline = EngineStartDeadline(receivedAt: .now)
  let schedule = LibboxStartWatchdog.sleeping(on: RecordingContinuousClock(events: recorder))
  let cancel = schedule(deadline.instant) { Issue.record("a cancelled deadline fired") }
  // Ends the stream if the sleeper stops reporting, so the test fails instead
  // of hanging.
  let giveUp = Task {
    try await Task.sleep(for: .seconds(5))
    recorder.finish()
  }
  var observed = events.makeAsyncIterator()
  let began = await observed.next()
  #expect(
    began == .began(deadline: deadline.instant, tolerance: EngineStartBudget.deadlineTolerance))
  cancel()
  let ended = await observed.next()
  giveUp.cancel()
  #expect(ended == .ended, "cancelling the deadline did not end its sleep")
}

/// The suspending clock, recording each sleep the watchdog asks it for and
/// when that sleep ends.
private struct RecordingSuspendingClock: Clock {
  typealias Instant = SuspendingClock.Instant

  enum Event: Equatable, Sendable {
    case began(deadline: Instant, tolerance: Duration?)
    case ended
  }

  let events: AsyncStream<Event>.Continuation

  var now: Instant { SuspendingClock.now }
  var minimumResolution: Duration { SuspendingClock().minimumResolution }

  func sleep(until deadline: Instant, tolerance: Duration?) async throws {
    events.yield(.began(deadline: deadline, tolerance: tolerance))
    defer { events.yield(.ended) }
    try await SuspendingClock().sleep(until: deadline, tolerance: tolerance)
  }
}

/// The interrupt limit sleeps the whole limit of awake time from when it is
/// armed, with the budget's tolerance, and cancelling it ends the sleep.
@Test func productionInterruptLimitSleepsInAwakeTimeUntilCancelled() async throws {
  let (events, recorder) = AsyncStream.makeStream(of: RecordingSuspendingClock.Event.self)
  let afterAwake = LibboxStartWatchdog.sleepingAwake(on: RecordingSuspendingClock(events: recorder))
  let armedAt = SuspendingClock.now
  let cancel = afterAwake(EngineStartBudget.interruptLimit) {
    Issue.record("a cancelled interrupt limit passed")
  }
  let giveUp = Task {
    try await Task.sleep(for: .seconds(5))
    recorder.finish()
  }
  var observed = events.makeAsyncIterator()
  guard case .began(let until, let tolerance)? = await observed.next() else {
    Issue.record("the interrupt limit did not sleep")
    return
  }
  #expect(tolerance == EngineStartBudget.deadlineTolerance)
  let limit = armedAt.duration(to: until)
  #expect(limit >= EngineStartBudget.interruptLimit)
  #expect(limit < EngineStartBudget.interruptLimit + .milliseconds(250))
  cancel()
  let ended = await observed.next()
  giveUp.cancel()
  #expect(ended == .ended, "cancelling the interrupt limit did not end its sleep")
}

@Test func timedOutStartNamesTheBudgetAndStaysDistinctFromAStartFailure() {
  let timedOut = LibboxRuntimeError.serviceStartTimedOut
  let description = timedOut.localizedDescription
  #expect(description.contains("11 seconds"))
  #expect(timedOut != .serviceStartFailed(LibboxDiagnostic(description)))
}

/// An interrupt that lands while libbox waits for its first network path
/// returns only once that wait, which libbox cannot interrupt, has ended and the
/// start has closed what it built. The interrupt limit leaves room for both, so
/// only a start or interrupt that hangs inside libbox is abandoned.
@Test func interruptLimitCoversTheFirstNetworkPathWaitAndTheClose() {
  #expect(LibboxInterfaceMonitorTiming.firstPathWait == .seconds(5))
  #expect(EngineStartBudget.interruptLimit == .milliseconds(5_500))
  #expect(
    EngineStartBudget.interruptLimit
      >= LibboxInterfaceMonitorTiming.firstPathWait + EngineStartBudget.interruptAllowance)
}

/// Waits in Dispatch keep a duration's fraction of a second.
@Test func durationsKeepTheirNanosecondsForDispatch() {
  #expect(Duration.milliseconds(5_500).dispatchTimeInterval == .nanoseconds(5_500_000_000))
  #expect(Duration.seconds(5).dispatchTimeInterval == .seconds(5))
  #expect(Duration.nanoseconds(1).dispatchTimeInterval == .nanoseconds(1))
}
