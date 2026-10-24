import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

private enum WatchdogTestError: Error, Equatable {
  case start
}

private struct CloseTestFailure: LocalizedError {
  static let text = "watchdog test: the close failed"
  var errorDescription: String? { Self.text }
}

private let interruptFailure = LibboxInstanceUnclosable(closeFailure: CloseTestFailure.text)

/// A timer the watchdog armed: the deadline at an instant of the continuous
/// clock, or the interrupt limit after a duration of awake time.
private enum ArmedTimer: Equatable {
  case at(ContinuousClock.Instant)
  case awake(Duration)
}

/// Records each timer the watchdog arms instead of arming it, so each test
/// decides when (and whether) each one fires: first the deadline, then the
/// interrupt limit that a fired deadline arms. `onArm` runs as each timer is
/// armed, with its index.
private final class ManualStartDeadline: @unchecked Sendable {
  private let lock = NSLock()
  private var scheduled: [(timer: ArmedTimer, action: @Sendable () -> Void)] = []
  private var cancelledIndices: [Int] = []
  private let onArm: @Sendable (Int) -> Void

  init(onArm: @escaping @Sendable (Int) -> Void = { _ in }) { self.onArm = onArm }

  var schedule: LibboxStartWatchdog.Schedule {
    { instant, action in self.arm(.at(instant), action) }
  }

  var afterAwake: LibboxStartWatchdog.AwakeTimer {
    { duration, action in self.arm(.awake(duration), action) }
  }

  private func arm(
    _ timer: ArmedTimer, _ action: @escaping @Sendable () -> Void
  ) -> LibboxStartWatchdog.Cancel {
    let index = lock.withLock { () -> Int in
      scheduled.append((timer, action))
      return scheduled.count - 1
    }
    onArm(index)
    return { self.lock.withLock { self.cancelledIndices.append(index) } }
  }

  var timers: [ArmedTimer] { lock.withLock { scheduled.map(\.timer) } }
  var cancelCount: Int { lock.withLock { cancelledIndices.count } }
  /// The index of each timer cancelled, in the order of the cancels.
  var cancelled: [Int] { lock.withLock { cancelledIndices } }

  /// Runs the action of the `index`-th timer armed, as that timer would.
  func fire(_ index: Int = 0) {
    let action = lock.withLock {
      scheduled.indices.contains(index) ? scheduled[index].action : nil
    }
    guard let action else {
      Issue.record("no timer \(index) was armed")
      return
    }
    action()
  }
}

/// The watchdog's clock, moved by hand.
private final class ManualNow: @unchecked Sendable {
  private let lock = NSLock()
  private var instant: ContinuousClock.Instant

  init(_ instant: ContinuousClock.Instant) { self.instant = instant }

  var now: @Sendable () -> ContinuousClock.Instant { { self.lock.withLock { self.instant } } }
}

private final class InterruptRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  private let failure: LibboxInstanceUnclosable?

  init(failure: LibboxInstanceUnclosable? = nil) { self.failure = failure }

  var calls: Int { lock.withLock { count } }

  func interrupt() throws(LibboxInstanceUnclosable) {
    lock.withLock { count += 1 }
    if let failure { throw failure }
  }
}

/// Holds a fake libbox call until the test opens it. A call held for thirty
/// seconds gives up and records that it stalled, so a test that never opens
/// the gate does not leave a thread behind; tests wait far less for anything
/// that must happen while a call is held.
private final class Gate: Sendable {
  private let entered = DispatchSemaphore(value: 0)
  private let opened = DispatchSemaphore(value: 0)
  private let stalled = Atomic<Bool>(false)
  private let entryCount = Atomic<Int>(0)

  /// The fake call: reports that it entered, then waits for the gate.
  func pass() {
    entryCount.add(1, ordering: .sequentiallyConsistent)
    entered.signal()
    if opened.wait(timeout: .now() + .seconds(30)) == .timedOut {
      stalled.store(true, ordering: .sequentiallyConsistent)
    }
  }

  func awaitEntry() -> Bool { entered.wait(timeout: .now() + .seconds(10)) == .success }
  func open() { opened.signal() }
  var hasStalled: Bool { stalled.load(ordering: .sequentiallyConsistent) }
  var entries: Int { entryCount.load(ordering: .sequentiallyConsistent) }
}

/// Runs the watchdog off the test's thread, so a run that does not return
/// fails the test instead of hanging it.
private final class BackgroundRun<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var outcome: LibboxStartWatchdog.Outcome<Value>?
  private let returned = DispatchSemaphore(value: 0)

  init(_ run: @escaping @Sendable () -> LibboxStartWatchdog.Outcome<Value>) {
    DispatchQueue.global(qos: .userInitiated).async {
      let outcome = run()
      self.lock.withLock { self.outcome = outcome }
      self.returned.signal()
    }
  }

  /// What the run returned, or nil while it has not returned within `timeout`.
  func awaitOutcome(within timeout: DispatchTimeInterval) -> LibboxStartWatchdog.Outcome<Value>? {
    if let outcome = lock.withLock({ outcome }) { return outcome }
    guard returned.wait(timeout: .now() + timeout) == .success else { return nil }
    return lock.withLock { outcome }
  }
}

private let now = ContinuousClock.now
private let deadline = EngineStartDeadline(receivedAt: now)

private func watchdog(
  _ manual: ManualStartDeadline, now clock: ManualNow = ManualNow(now)
) -> LibboxStartWatchdog {
  LibboxStartWatchdog(now: clock.now, schedule: manual.schedule, afterAwake: manual.afterAwake)
}

/// Runs the watchdog off the test's thread and returns its outcome, or nil
/// after recording an issue when it did not return within ten seconds.
private func bounded<Value: Sendable>(
  _ run: @escaping @Sendable () -> LibboxStartWatchdog.Outcome<Value>,
  sourceLocation: SourceLocation = #_sourceLocation
) -> LibboxStartWatchdog.Outcome<Value>? {
  let outcome = BackgroundRun(run).awaitOutcome(within: .seconds(10))
  if outcome == nil {
    Issue.record("the watchdog run did not return", sourceLocation: sourceLocation)
  }
  return outcome
}

@Test func startThatReturnsBeforeTheDeadlineIsNeverInterrupted() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome = bounded {
    watchdog(manual).run(deadline: deadline, interrupt: interrupts.interrupt, start: { 7 })
  }
  guard case .completed(.success(7))? = outcome else {
    Issue.record("expected an in-time completion, got \(String(describing: outcome))")
    return
  }
  #expect(manual.timers == [.at(deadline.instant)])
  #expect(manual.cancelCount == 1)
  manual.fire()
  #expect(interrupts.calls == 0)
  #expect(manual.timers == [.at(deadline.instant)], "a late deadline armed the limit")
}

@Test func startErrorBeforeTheDeadlineIsReportedUnchanged() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome: LibboxStartWatchdog.Outcome<Int>? = bounded {
    watchdog(manual).run(
      deadline: deadline, interrupt: interrupts.interrupt,
      start: { throw WatchdogTestError.start })
  }
  guard case .completed(.failure(let error))? = outcome else {
    Issue.record("expected the start error, got \(String(describing: outcome))")
    return
  }
  #expect(error as? WatchdogTestError == .start)
  #expect(manual.cancelCount == 1)
  manual.fire()
  #expect(interrupts.calls == 0)
}

@Test func deadlineDuringStartInterruptsOnceAndKeepsWhatTheStartReturned() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome = bounded {
    watchdog(manual).run(
      deadline: deadline, interrupt: interrupts.interrupt,
      start: { () -> Int in
        manual.fire()
        manual.fire()
        return 7
      })
  }
  guard case .interrupted(start: .success(7), interruption: .success)? = outcome else {
    Issue.record("expected an interrupted start, got \(String(describing: outcome))")
    return
  }
  #expect(interrupts.calls == 1)
}

@Test func deadlineDuringAFailingStartKeepsTheStartsOwnError() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let outcome: LibboxStartWatchdog.Outcome<Int>? = bounded {
    watchdog(manual).run(
      deadline: deadline, interrupt: interrupts.interrupt,
      start: {
        manual.fire()
        throw WatchdogTestError.start
      })
  }
  guard case .interrupted(start: .failure(let error), interruption: .success)? = outcome else {
    Issue.record(
      "expected the start's own error beside the interrupt, got \(String(describing: outcome))")
    return
  }
  #expect(error as? WatchdogTestError == .start)
  #expect(interrupts.calls == 1)
}

@Test func failedInterruptIsSurfacedToTheCaller() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder(failure: interruptFailure)
  let outcome = bounded {
    watchdog(manual).run(
      deadline: deadline, interrupt: interrupts.interrupt,
      start: { () -> Int in
        manual.fire()
        return 7
      })
  }
  guard case .interrupted(start: .success(7), interruption: .failure(let error))? = outcome
  else {
    Issue.record("expected the interrupt failure, got \(String(describing: outcome))")
    return
  }
  #expect(error == interruptFailure)
  #expect(interrupts.calls == 1)
}

@Test func startNeedsTheMinimumWindowBeforeTheDeadline() {
  // A deadline landing while libbox still builds the instance costs the rest of
  // the build, so a start with less than the window left fails before it begins.
  #expect(LibboxStartWatchdog.minimumStartWindow == .seconds(2))
  let window = LibboxStartWatchdog.minimumStartWindow
  for (remaining, starts) in [
    (window, true), (window - .nanoseconds(1), false), (.zero, false), (.seconds(-3), false),
  ] {
    let manual = ManualStartDeadline()
    let interrupts = InterruptRecorder()
    let startCalls = InterruptRecorder()
    let at = deadline.instant.advanced(by: .zero - remaining)
    let outcome = bounded {
      LibboxStartWatchdog(
        now: { at }, schedule: manual.schedule, afterAwake: manual.afterAwake
      ).run(
        deadline: deadline, interrupt: interrupts.interrupt,
        start: { () -> Int in
          try startCalls.interrupt()
          return 7
        })
    }
    switch outcome {
    case .completed(.success(7))?:
      #expect(starts, "started with \(remaining) left")
      #expect(manual.timers == [.at(deadline.instant)])
    case .notStarted?:
      #expect(!starts, "refused with \(remaining) left")
      #expect(manual.timers.isEmpty)
      #expect(startCalls.calls == 0)
    default:
      Issue.record("unexpected outcome \(String(describing: outcome)) with \(remaining) left")
    }
    #expect(interrupts.calls == 0)
  }
}

@Test func runWaitsForAFiredInterruptThatIsStillRunning() {
  let manual = ManualStartDeadline()
  let interrupt = Gate()
  let subject = watchdog(manual)
  let run = BackgroundRun {
    subject.run(
      deadline: deadline, interrupt: { interrupt.pass() },
      start: { () -> Int in
        manual.fire()
        return 7
      })
  }
  #expect(interrupt.awaitEntry())
  // The start has returned while the interrupt is still running: no return yet.
  #expect(run.awaitOutcome(within: .milliseconds(300)) == nil)
  interrupt.open()
  guard
    case .interrupted(start: .success(7), interruption: .success)? =
      run.awaitOutcome(within: .seconds(5))
  else {
    Issue.record("expected the interrupted start once its interrupt returned")
    return
  }
  #expect(!interrupt.hasStalled)
}

/// The deadline may fire late, as when the Mac slept through it: the
/// interrupt still has the whole limit of awake time from then on.
@Test func firedDeadlineArmsTheWholeInterruptLimitInAwakeTime() {
  let manual = ManualStartDeadline()
  let interrupts = InterruptRecorder()
  let armedBeforeTheDeadline = Mutex<[ArmedTimer]>([])
  let outcome = bounded {
    watchdog(manual).run(
      deadline: deadline, interrupt: interrupts.interrupt,
      start: { () -> Int in
        armedBeforeTheDeadline.withLock { $0 = manual.timers }
        manual.fire()
        return 7
      })
  }
  guard case .interrupted(start: .success(7), interruption: .success)? = outcome else {
    Issue.record("expected an interrupted start, got \(String(describing: outcome))")
    return
  }
  #expect(armedBeforeTheDeadline.withLock { $0 } == [.at(deadline.instant)])
  #expect(manual.timers == [.at(deadline.instant), .awake(EngineStartBudget.interruptLimit)])
  // The attempt ended, so both of its timers are cancelled.
  #expect(manual.cancelCount == 2)
  manual.fire(1)
  #expect(interrupts.calls == 1)
}

@Test func startThatNeverReturnsIsAbandonedAtTheInterruptLimit() {
  let manual = ManualStartDeadline()
  let start = Gate()
  let interruptRan = DispatchSemaphore(value: 0)
  let subject = watchdog(manual)
  let run = BackgroundRun {
    subject.run(
      deadline: deadline, interrupt: { interruptRan.signal() },
      start: { () -> Int in
        start.pass()
        return 7
      })
  }
  #expect(start.awaitEntry())
  manual.fire()
  #expect(interruptRan.wait(timeout: .now() + .seconds(10)) == .success)
  // The interrupt returned, but the start it interrupted is still inside libbox.
  #expect(run.awaitOutcome(within: .milliseconds(300)) == nil)
  #expect(manual.timers == [.at(deadline.instant), .awake(EngineStartBudget.interruptLimit)])
  manual.fire(1)
  guard case .abandoned? = run.awaitOutcome(within: .seconds(5)) else {
    Issue.record("a start that never returned was not abandoned at the interrupt limit")
    start.open()
    return
  }
  start.open()
}

@Test func interruptThatNeverReturnsIsAbandonedAtTheInterruptLimit() {
  let manual = ManualStartDeadline()
  let interrupt = Gate()
  let subject = watchdog(manual)
  let run = BackgroundRun {
    subject.run(
      deadline: deadline, interrupt: { interrupt.pass() },
      start: { () -> Int in
        manual.fire()
        return 7
      })
  }
  #expect(interrupt.awaitEntry())
  #expect(run.awaitOutcome(within: .milliseconds(300)) == nil)
  manual.fire(1)
  guard case .abandoned? = run.awaitOutcome(within: .seconds(5)) else {
    Issue.record("an interrupt that never returned was not abandoned at the interrupt limit")
    interrupt.open()
    return
  }
  interrupt.open()
}

/// Should the limit pass before the thread that fired the deadline records
/// its cancel, as a thread stalled that long would see, the attempt was
/// abandoned and its interrupt never reaches libbox.
@Test func aLimitThatPassedBeforeTheInterruptRanKeepsLibboxUntouched() {
  let manual = ManualStartDeadline()
  let start = Gate()
  let interrupts = InterruptRecorder()
  let subject = LibboxStartWatchdog(
    now: ManualNow(now).now, schedule: manual.schedule,
    afterAwake: { _, passed in
      passed()
      return {}
    })
  let run = BackgroundRun {
    subject.run(
      deadline: deadline, interrupt: interrupts.interrupt,
      start: { () -> Int in
        start.pass()
        return 7
      })
  }
  #expect(start.awaitEntry())
  manual.fire()
  guard case .abandoned? = run.awaitOutcome(within: .seconds(5)) else {
    Issue.record("the attempt was not abandoned when its limit passed")
    start.open()
    return
  }
  // An interrupt dispatched anyway would have run by now.
  Thread.sleep(forTimeInterval: 0.3)
  #expect(interrupts.calls == 0)
  start.open()
}

@Test func returnsAfterAnAbandonmentChangeNothing() {
  let manual = ManualStartDeadline()
  let start = Gate()
  let interrupt = Gate()
  let startLeft = DispatchSemaphore(value: 0)
  let interruptLeft = DispatchSemaphore(value: 0)
  let subject = watchdog(manual)
  let run = BackgroundRun {
    subject.run(
      deadline: deadline,
      interrupt: {
        interrupt.pass()
        interruptLeft.signal()
      },
      start: { () -> Int in
        start.pass()
        startLeft.signal()
        return 7
      })
  }
  #expect(start.awaitEntry())
  manual.fire()
  #expect(interrupt.awaitEntry())
  manual.fire(1)
  guard case .abandoned? = run.awaitOutcome(within: .seconds(5)) else {
    Issue.record("the start was not abandoned at the interrupt limit")
    start.open()
    interrupt.open()
    return
  }
  // libbox returns late from both calls, and both timers fire again: the
  // abandoned attempt arms nothing more and interrupts nothing again.
  start.open()
  interrupt.open()
  #expect(startLeft.wait(timeout: .now() + .seconds(5)) == .success)
  #expect(interruptLeft.wait(timeout: .now() + .seconds(5)) == .success)
  manual.fire()
  manual.fire(1)
  #expect(manual.timers.count == 2)
  #expect(interrupt.entries == 1)
  #expect(!start.hasStalled)
  #expect(!interrupt.hasStalled)
}

@Test func aHungInterruptDoesNotHoldBackAnotherStartsInterrupt() {
  let hungManual = ManualStartDeadline()
  let hungInterrupt = Gate()
  let hungRun = BackgroundRun {
    watchdog(hungManual).run(
      deadline: deadline, interrupt: { hungInterrupt.pass() },
      start: { () -> Int in
        hungManual.fire()
        return 7
      })
  }
  #expect(hungInterrupt.awaitEntry())

  // Another start in the same process reaches its deadline while that
  // interrupt still hangs; its own interrupt runs at once.
  let manual = ManualStartDeadline()
  let interruptRan = DispatchSemaphore(value: 0)
  let run = BackgroundRun {
    watchdog(manual).run(
      deadline: deadline, interrupt: { interruptRan.signal() },
      start: { () -> Bool in
        manual.fire()
        return interruptRan.wait(timeout: .now() + .seconds(5)) == .success
      })
  }
  guard
    case .interrupted(start: .success(true), interruption: .success)? =
      run.awaitOutcome(within: .seconds(5))
  else {
    Issue.record("the second start's interrupt waited behind the hung one")
    hungInterrupt.open()
    return
  }
  hungManual.fire(1)
  guard case .abandoned? = hungRun.awaitOutcome(within: .seconds(5)) else {
    Issue.record("the hung interrupt was not abandoned at the interrupt limit")
    hungInterrupt.open()
    return
  }
  hungInterrupt.open()
}

/// Releases two threads at once so the deadline firing and the start returning
/// genuinely race. A thread that waits five seconds for the other gives up and
/// records it, so a lost thread fails the test instead of spinning forever.
private final class StartingLine: Sendable {
  private let arrivals = Atomic<Int>(0)
  private let gaveUp = Atomic<Bool>(false)

  func arriveAndWait() {
    arrivals.add(1, ordering: .sequentiallyConsistent)
    let giveUpAt = ContinuousClock.now.advanced(by: .seconds(5))
    while arrivals.load(ordering: .sequentiallyConsistent) < 2 {
      if ContinuousClock.now >= giveUpAt {
        gaveUp.store(true, ordering: .sequentiallyConsistent)
        return
      }
    }
  }

  var hasGivenUp: Bool { gaveUp.load(ordering: .sequentiallyConsistent) }
}

@Test func completionRacingTheDeadlineHasExactlyOneConsistentOutcome() {
  for _ in 0..<2_000 {
    let manual = ManualStartDeadline()
    let interrupts = InterruptRecorder()
    let fired = DispatchSemaphore(value: 0)
    let line = StartingLine()
    let outcome = bounded {
      watchdog(manual).run(
        deadline: deadline, interrupt: interrupts.interrupt,
        start: { () -> Int in
          DispatchQueue.global().async {
            line.arriveAndWait()
            manual.fire()
            fired.signal()
          }
          line.arriveAndWait()
          return 7
        })
    }
    #expect(fired.wait(timeout: .now() + .seconds(5)) == .success)
    #expect(!line.hasGivenUp)
    switch outcome {
    case .completed(.success(7))?:
      #expect(interrupts.calls == 0)
    case .interrupted(start: .success(7), interruption: .success)?:
      #expect(interrupts.calls == 1)
    default:
      Issue.record("unexpected outcome \(String(describing: outcome))")
    }
  }
}

@Test func productionDeadlineInterruptsABlockedStart() {
  let interruptRan = DispatchSemaphore(value: 0)
  let soon = EngineStartDeadline(
    receivedAt: ContinuousClock.now.advanced(
      by: LibboxStartWatchdog.minimumStartWindow + .milliseconds(200)
        - EngineStartBudget.ownerLibboxStart))
  let outcome = bounded {
    LibboxStartWatchdog().run(
      deadline: soon,
      interrupt: { interruptRan.signal() },
      start: { () -> Bool in
        interruptRan.wait(timeout: .now() + .seconds(10)) == .success
      })
  }
  let lateness = soon.instant.duration(to: .now)
  guard case .interrupted(start: .success(true), interruption: .success)? = outcome else {
    Issue.record(
      "expected the production deadline to interrupt, got \(String(describing: outcome))")
    return
  }
  #expect(lateness >= .zero)
  #expect(
    lateness < EngineStartBudget.deadlineTolerance + .milliseconds(250),
    "the deadline fired \(lateness) late")
}

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

/// What a verdict tells the runtime, in a form tests can compare.
private enum StartMeaning: Equatable {
  case started
  case conflict(Int)
  case timedOut
  case failed(WatchdogTestError)
}

private enum InterruptMeaning: Equatable {
  case notFired
  case closed
  case unclosable(LibboxInstanceUnclosable)
}

private func meaning(_ verdict: LibboxStartVerdict<Int>) -> (StartMeaning, InterruptMeaning)? {
  let start: StartMeaning
  switch verdict.start {
  case .success(nil):
    start = .started
  case .success(let conflict?):
    start = .conflict(conflict)
  case .failure(let error):
    if error as? LibboxRuntimeError == .serviceStartTimedOut {
      start = .timedOut
    } else if let error = error as? WatchdogTestError {
      start = .failed(error)
    } else {
      return nil
    }
  }
  switch verdict.interruption {
  case nil:
    return (start, .notFired)
  case .success:
    return (start, .closed)
  case .failure(let error):
    return (start, .unclosable(error))
  }
}

@Test func everyStartOutcomeHasOneMeaningForTheRuntime() {
  typealias Outcome = LibboxStartWatchdog.Outcome<Int?>
  let table: [(Outcome, StartMeaning, InterruptMeaning)] = [
    (.notStarted, .timedOut, .notFired),
    (.completed(.success(nil)), .started, .notFired),
    (.completed(.success(7)), .conflict(7), .notFired),
    (.completed(.failure(WatchdogTestError.start)), .failed(.start), .notFired),
    // libbox reports an interrupted start as success: that start timed out.
    (.interrupted(start: .success(nil), interruption: .success(())), .timedOut, .closed),
    (.interrupted(start: .success(7), interruption: .success(())), .conflict(7), .closed),
    (
      .interrupted(start: .failure(WatchdogTestError.start), interruption: .success(())),
      .failed(.start), .closed
    ),
    (
      .interrupted(start: .success(nil), interruption: .failure(interruptFailure)),
      .timedOut, .unclosable(interruptFailure)
    ),
    // A thread may still be inside libbox, so the runtime cannot be closed.
    (.abandoned, .timedOut, .unclosable(LibboxInstanceUnclosable(.interruptDidNotReturn))),
  ]
  for (outcome, start, interruption) in table {
    let verdict: LibboxStartVerdict<Int> = outcome.verdict()
    guard let observed = meaning(verdict) else {
      Issue.record("\(outcome) produced an unexpected error")
      continue
    }
    #expect(observed.0 == start, "\(outcome)")
    #expect(observed.1 == interruption, "\(outcome)")
  }
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

@Test func boundedCloseReportsWhatTheCloseReturned() {
  #expect(LibboxBoundedClose().bound == EngineStopBudget.libboxClose)
  let bounded = LibboxBoundedClose(bound: .seconds(10))
  #expect(bounded.run {} == .closed)
  #expect(
    bounded.run { throw CloseTestFailure() } == .failed(LibboxDiagnostic(CloseTestFailure.text)))
}

@Test func boundedCloseStopsWaitingAtItsBound() {
  let close = Gate()
  let bound = Duration.milliseconds(200)
  let began = ContinuousClock.now
  let outcome = LibboxBoundedClose(bound: bound).run { close.pass() }
  let waited = began.duration(to: .now)
  close.open()
  #expect(outcome == .didNotReturn)
  #expect(waited >= bound, "gave up after \(waited)")
  #expect(waited < bound + .seconds(1), "gave up after \(waited)")
}

/// What one bounded call delivered, in order, in a form tests compare.
private enum CallEvent: Equatable {
  case replied(Int)
  case repliedFailure
  case repliedStillRunning
  case returned(Int)
  case returnedFailure
  case abandoned(LibboxInstanceUnclosable)
}

private final class CallRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recorded: [CallEvent] = []
  private let ended = DispatchSemaphore(value: 0)
  private let replied = DispatchSemaphore(value: 0)

  var events: [CallEvent] { lock.withLock { recorded } }

  func reply(_ reply: LibboxCallReply<Int>) {
    lock.withLock {
      switch reply {
      case .returned(.success(let value)): recorded.append(.replied(value))
      case .returned(.failure): recorded.append(.repliedFailure)
      case .stillRunning: recorded.append(.repliedStillRunning)
      }
    }
    replied.signal()
  }

  func end(_ end: LibboxCallEnd<Int>) {
    lock.withLock {
      switch end {
      case .returned(.success(let value)): recorded.append(.returned(value))
      case .returned(.failure): recorded.append(.returnedFailure)
      case .abandoned(let failure): recorded.append(.abandoned(failure))
      }
    }
    ended.signal()
  }

  func awaitReply() -> Bool { replied.wait(timeout: .now() + .seconds(5)) == .success }
  func awaitEnd() -> Bool { ended.wait(timeout: .now() + .seconds(5)) == .success }
}

private func boundedCall(
  _ timers: ManualStartDeadline, replyDeadline: Duration = .seconds(3),
  _ recorder: CallRecorder, _ call: @escaping @Sendable () throws -> Int
) {
  LibboxBoundedCall(afterAwake: timers.afterAwake, startCall: LibboxBoundedCall.onItsOwnQueue).run(
    replyDeadline: replyDeadline, qos: .userInitiated, call,
    reply: { recorder.reply($0) }, ended: { recorder.end($0) })
}

/// Holds a bounded call's work instead of starting its thread, so a test runs
/// it exactly where the race it pins needs the return.
private final class HeldCallStart: @unchecked Sendable {
  private let lock = NSLock()
  private var work: (@Sendable () -> Void)?

  var start: LibboxBoundedCall.StartCall {
    { _, work in self.lock.withLock { self.work = work } }
  }

  /// Runs the held call on this thread, as its own thread would.
  func runHeld() {
    let work = lock.withLock { () -> (@Sendable () -> Void)? in
      defer { self.work = nil }
      return self.work
    }
    guard let work else {
      Issue.record("no bounded call was held")
      return
    }
    work()
  }
}

/// A call that returns before its deadline answers with its result and ends
/// once; the deadline timer is cancelled and no limit is armed.
@Test func aCallReturningBeforeItsReplyAnswersWithItsResultOnce() {
  let timers = ManualStartDeadline()
  let recorder = CallRecorder()
  boundedCall(timers, replyDeadline: .seconds(3), recorder) { 42 }
  #expect(recorder.awaitEnd())
  #expect(recorder.events == [.replied(42), .returned(42)])
  #expect(timers.timers == [.awake(.seconds(3))])
  #expect(timers.cancelled == [0])

  let failing = CallRecorder()
  boundedCall(ManualStartDeadline(), failing) { throw WatchdogTestError.start }
  #expect(failing.awaitEnd())
  #expect(failing.events == [.repliedFailure, .returnedFailure])
}

/// A call still running at its deadline answers that it still runs, and only
/// then is the limit armed. Its later return ends it once, and the limit,
/// should it still fire, changes nothing.
@Test func aCallPastItsReplyAnswersStillRunningAndEndsWhenItReturns() {
  let timers = ManualStartDeadline()
  let recorder = CallRecorder()
  let call = Gate()
  boundedCall(timers, replyDeadline: .seconds(3), recorder) {
    call.pass()
    return 7
  }
  #expect(call.awaitEntry())
  #expect(timers.timers == [.awake(.seconds(3))])
  timers.fire(0)
  #expect(recorder.events == [.repliedStillRunning])
  #expect(timers.timers == [.awake(.seconds(3)), .awake(ProxyAgentCallBudget.abandonAfterReply)])

  call.open()
  #expect(recorder.awaitEnd())
  #expect(recorder.events == [.repliedStillRunning, .returned(7)])
  #expect(timers.cancelled == [1])
  timers.fire(1)
  #expect(recorder.events == [.repliedStillRunning, .returned(7)])
  #expect(!call.hasStalled)
}

/// A call still inside libbox at the limit is abandoned once, and its late
/// return changes nothing.
@Test func aCallStillInsideLibboxAtTheLimitIsAbandonedOnce() {
  let timers = ManualStartDeadline()
  let recorder = CallRecorder()
  let call = Gate()
  let returned = DispatchSemaphore(value: 0)
  boundedCall(timers, recorder) {
    call.pass()
    returned.signal()
    return 7
  }
  #expect(call.awaitEntry())
  timers.fire(0)
  timers.fire(1)
  #expect(
    recorder.events == [
      .repliedStillRunning, .abandoned(LibboxInstanceUnclosable(.callDidNotReturn)),
    ])
  timers.fire(1)
  call.open()
  #expect(returned.wait(timeout: .now() + .seconds(5)) == .success)
  Thread.sleep(forTimeInterval: 0.05)
  #expect(
    recorder.events == [
      .repliedStillRunning, .abandoned(LibboxInstanceUnclosable(.callDidNotReturn)),
    ])
}

/// However a return races the deadline, the call answers once and ends once,
/// in that order.
@Test func aReturnRacingTheReplyDeadlineAnswersAndEndsOnce() {
  for _ in 0..<200 {
    let timers = ManualStartDeadline()
    let recorder = CallRecorder()
    let call = Gate()
    boundedCall(timers, recorder) {
      call.pass()
      return 1
    }
    #expect(call.awaitEntry())
    DispatchQueue.global(qos: .userInitiated).async { timers.fire(0) }
    call.open()
    #expect(recorder.awaitEnd())
    let events = recorder.events
    #expect(
      events == [.replied(1), .returned(1)] || events == [.repliedStillRunning, .returned(1)],
      "\(events)")
  }
}

/// A call that returns while its `stillRunning` reply is on its way ends
/// with its result right after that reply, and no limit is armed for it.
@Test func aCallReturningDuringItsStillRunningReplyEndsRightAfterIt() {
  let timers = ManualStartDeadline()
  let held = HeldCallStart()
  let recorder = CallRecorder()
  LibboxBoundedCall(afterAwake: timers.afterAwake, startCall: held.start).run(
    replyDeadline: .seconds(3), qos: .userInitiated, { 5 },
    reply: { reply in
      recorder.reply(reply)
      if case .stillRunning = reply { held.runHeld() }
    },
    ended: { recorder.end($0) })
  timers.fire(0)
  #expect(recorder.events == [.repliedStillRunning, .returned(5)])
  #expect(timers.timers == [.awake(.seconds(3))])
}

/// A call that returns after its `stillRunning` reply but before the limit is
/// kept ends with its result, and the limit armed after it is cancelled at
/// once.
@Test func aCallReturningAsItsLimitIsArmedCancelsThatLimit() {
  let held = HeldCallStart()
  let timers = ManualStartDeadline(onArm: { index in
    if index == 1 { held.runHeld() }
  })
  let recorder = CallRecorder()
  LibboxBoundedCall(afterAwake: timers.afterAwake, startCall: held.start).run(
    replyDeadline: .seconds(3), qos: .userInitiated, { 6 },
    reply: { recorder.reply($0) }, ended: { recorder.end($0) })
  timers.fire(0)
  #expect(recorder.events == [.repliedStillRunning, .returned(6)])
  #expect(timers.timers == [.awake(.seconds(3)), .awake(ProxyAgentCallBudget.abandonAfterReply)])
  #expect(timers.cancelled == [0, 1])
  timers.fire(1)
  #expect(recorder.events == [.repliedStillRunning, .returned(6)])
}

/// Each call has its own thread, so one held inside libbox holds back no other.
@Test func aHeldCallHoldsBackNoOtherCall() {
  let held = Gate()
  let heldRecorder = CallRecorder()
  boundedCall(ManualStartDeadline(), heldRecorder) {
    held.pass()
    return 1
  }
  #expect(held.awaitEntry())
  let other = CallRecorder()
  boundedCall(ManualStartDeadline(), other) { 2 }
  #expect(other.awaitEnd())
  #expect(other.events == [.replied(2), .returned(2)])
  #expect(heldRecorder.events.isEmpty)
  held.open()
  #expect(heldRecorder.awaitEnd())
}

#if canImport(Libbox)
  /// Binds `descriptor` to a loopback TCP port (0 picks a free one) and returns
  /// the port.
  private func bindLoopback(_ descriptor: Int32, port: UInt16) throws -> UInt16 {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = port.bigEndian
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        Darwin.bind(descriptor, socketAddress, length) == 0
          && getsockname(descriptor, socketAddress, &length) == 0
      }
    }
    guard bound else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    return UInt16(bigEndian: address.sin_port)
  }

  /// Binds a fresh loopback socket to `port`, closes it, and returns the port.
  /// Binding fails with `EADDRINUSE` while a socket of this user is still bound
  /// to 127.0.0.1 at that port, which is where the linked configuration has
  /// libbox listen; `SO_REUSEADDR` keeps connections that were closed but linger
  /// in TIME_WAIT from failing it too.
  private func probeLoopbackPort(_ port: UInt16) throws -> UInt16 {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { Darwin.close(descriptor) }
    var reuse: Int32 = 1
    guard
      setsockopt(
        descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0
    else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return try bindLoopback(descriptor, port: port)
  }

  /// A loopback TCP server for linked starts, on plain sockets so that tearing
  /// down its connections logs nothing. It counts the connections it accepts
  /// and either holds them unanswered, so a download from it stalls until the
  /// client gives up, or answers each request once with `response`.
  private final class LoopbackServer: @unchecked Sendable {
    let port: UInt16
    private let listener: Int32
    private let response: Data?
    private let queue = DispatchQueue(label: "com.bill.clashformac.tests.loopback-server")
    private let lock = NSLock()
    private var connections: [Int32] = []
    private let acceptSource: any DispatchSourceRead

    /// `response` is the whole HTTP response written once a request's headers
    /// arrived; nil leaves every request unanswered.
    init(response: Data?) throws {
      self.response = response
      let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
      guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
      do {
        port = try bindLoopback(descriptor, port: 0)
        guard Darwin.listen(descriptor, 16) == 0,
          fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK) == 0
        else {
          throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
      } catch {
        Darwin.close(descriptor)
        throw error
      }
      listener = descriptor
      acceptSource = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
      acceptSource.setEventHandler { [weak self] in self?.acceptPending() }
      acceptSource.setCancelHandler { Darwin.close(descriptor) }
      acceptSource.resume()
    }

    var acceptedConnections: Int { lock.withLock { connections.count } }

    func cancel() {
      acceptSource.cancel()
      queue.sync {
        lock.withLock {
          for connection in connections { Darwin.close(connection) }
          connections.removeAll()
        }
      }
    }

    private func acceptPending() {
      while true {
        let connection = Darwin.accept(listener, nil, nil)
        guard connection >= 0 else { return }
        lock.withLock { connections.append(connection) }
        if let response {
          Self.answer(connection, with: response)
        }
      }
    }

    /// Reads one request's headers, then writes the response and ends the
    /// stream. A connection that fails either step is reset, which fails the
    /// client's download visibly; a client that closed first fails the write
    /// instead of raising SIGPIPE in the test process.
    private static func answer(_ connection: Int32, with response: Data) {
      var timeout = timeval(tv_sec: 5, tv_usec: 0)
      var noSignal: Int32 = 1
      guard fcntl(connection, F_SETFL, fcntl(connection, F_GETFL) & ~O_NONBLOCK) == 0,
        setsockopt(
          connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
          == 0,
        setsockopt(
          connection, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
          == 0
      else {
        _ = Darwin.shutdown(connection, SHUT_RDWR)
        return
      }
      var request = Data()
      var buffer = [UInt8](repeating: 0, count: 4_096)
      while request.range(of: Data("\r\n\r\n".utf8)) == nil {
        let count = Darwin.read(connection, &buffer, buffer.count)
        guard count > 0 else {
          _ = Darwin.shutdown(connection, SHUT_RDWR)
          return
        }
        request.append(contentsOf: buffer[0..<count])
      }
      let written = response.withUnsafeBytes { bytes -> Bool in
        guard let base = bytes.baseAddress else { return false }
        var sent = 0
        while sent < bytes.count {
          let count = Darwin.write(connection, base + sent, bytes.count - sent)
          guard count > 0 else { return false }
          sent += count
        }
        return true
      }
      _ = Darwin.shutdown(connection, written ? SHUT_WR : SHUT_RDWR)
    }
  }

  /// One remote rule set of a linked configuration, downloaded through the
  /// outbound `detour` names.
  private struct LinkedRuleSet {
    let tag: String
    let url: String
    let format: String
    var detour = "direct"
  }

  /// The loopback ports of one linked System Proxy runtime.
  private struct LinkedEndpoints {
    let mixedPort: UInt16
    let controllerPort: UInt16

    init() throws {
      let mixed = try probeLoopbackPort(0)
      var controller = try probeLoopbackPort(0)
      while controller == mixed {
        controller = try probeLoopbackPort(0)
      }
      mixedPort = mixed
      controllerPort = controller
    }

    /// A configuration the runtime admits whose remote rule sets download from
    /// their URLs, with libbox's cache file at `cacheFile`. With `proxyPort`
    /// it also has a SOCKS outbound tagged `proxy` to that loopback port.
    func configuration(
      ruleSets: [LinkedRuleSet], cacheFile: URL, proxyPort: UInt16? = nil
    ) throws -> Data {
      var outbounds: [[String: Any]] = [["type": "direct", "tag": "direct"]]
      if let proxyPort {
        outbounds.append([
          "type": "socks", "tag": "proxy", "server": "127.0.0.1",
          "server_port": Int(proxyPort),
        ])
      }
      return try JSONSerialization.data(withJSONObject: [
        "log": ["level": "error"],
        "inbounds": [
          [
            "type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1",
            "listen_port": Int(mixedPort),
          ]
        ],
        "outbounds": outbounds,
        "route": [
          "rule_set": ruleSets.map { ruleSet in
            [
              "type": "remote", "tag": ruleSet.tag, "format": ruleSet.format,
              "url": ruleSet.url, "download_detour": ruleSet.detour,
            ]
          },
          "rules": [
            ["rule_set": ruleSets.map(\.tag), "action": "route", "outbound": "direct"]
          ],
          "final": "direct",
        ],
        "experimental": [
          "cache_file": ["enabled": true, "path": cacheFile.path],
          "clash_api": [
            "external_controller": "127.0.0.1:\(controllerPort)", "secret": "linked-test",
          ],
        ],
      ])
    }
  }

  private final class StartResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<Void, any Error>?
    func record(_ result: Result<Void, any Error>) { lock.withLock { value = result } }
    var result: Result<Void, any Error>? { lock.withLock { value } }
  }

  /// A step expected to fail that started anyway leaves libbox running; stop
  /// it so the later steps and the cleanup still find an idle runtime.
  private func stopIfStarted(
    _ runtime: SourceBuiltLibboxServiceRuntime, _ result: Result<Void, any Error>
  ) {
    guard case .success = result else { return }
    do {
      try runtime.stop()
    } catch {
      Issue.record(error, "a start that should have failed did not stop")
    }
  }

  /// Every close of libbox's network monitor in a runtime that throws this
  /// fault fails with it, so libbox fails to close that runtime's instance.
  private struct LinkedMonitorCloseFault: LocalizedError {
    static let text = "linked test: the network monitor did not close"
    var errorDescription: String? { Self.text }
  }

  /// Holds every close of libbox's network monitor in a runtime that waits on
  /// it until the test releases it, so libbox's close of that runtime's
  /// instance does not return. A close held for a minute gives up, so a test
  /// that ends early does not leave the thread inside libbox for good.
  private final class LinkedMonitorCloseStall: Sendable {
    private let released = DispatchSemaphore(value: 0)

    func hold() {
      _ = released.wait(timeout: .now() + .seconds(60))
    }

    func release() {
      released.signal()
    }
  }

  /// What stopping `runtime` threw, or nil when it stopped.
  private func closeFailure(
    of runtime: SourceBuiltLibboxServiceRuntime
  ) -> LibboxInstanceUnclosable? {
    do {
      try runtime.stop()
      return nil
    } catch {
      return error
    }
  }

  /// Starts on another queue so an interrupt that never ends the start fails
  /// the test instead of hanging the lane. Nil means the start never returned.
  private func boundedStart(
    _ runtime: SourceBuiltLibboxServiceRuntime, _ configuration: Data,
    deadline: EngineStartDeadline
  ) -> Result<Void, any Error>? {
    let returned = DispatchSemaphore(value: 0)
    let outcome = StartResult()
    DispatchQueue.global(qos: .userInitiated).async {
      outcome.record(
        Result {
          try runtime.start(
            configuration: configuration, packetFileDescriptor: nil, deadline: deadline)
        })
      returned.signal()
    }
    guard returned.wait(timeout: .now() + .seconds(20)) == .success else { return nil }
    return outcome.result
  }

  /// The real runtime ends every start in a state it can start from again. A
  /// start that fails before libbox starts the network leaves it idle; a stalled
  /// rule-set download is interrupted at the owner's deadline, while a rule set
  /// that finished downloading is kept for the next start; a download stalled
  /// at its proxy is interrupted alike; a start with too little time left never
  /// begins; and a later start from the kept rule set listens, then stops and
  /// releases its listeners. A runtime whose close fails, at a stop, at the
  /// interrupt or after a start's own failure, is spent instead: it reports
  /// that close failure from then on and never reaches libbox again. So is a
  /// runtime whose close never returns, at a stop once the stop's bound passed
  /// and at the interrupt once the interrupt limit passed.
  /// libbox takes its directories once per process, so this is the bundle's only
  /// test that starts it.
  @Test func linkedRuntimeBoundsEveryStartAndStaysStartable() throws {
    let stalled = try LoopbackServer(response: nil)
    defer { stalled.cancel() }
    let ruleSet = Data(#"{"version":1,"rules":[{"domain_suffix":["linked-test.invalid"]}]}"#.utf8)
    let headers =
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
      + "Content-Length: \(ruleSet.count)\r\nConnection: close\r\n\r\n"
    let served = try LoopbackServer(response: Data(headers.utf8) + ruleSet)
    defer { served.cancel() }
    let stalledProxy = try LoopbackServer(response: nil)
    defer { stalledProxy.cancel() }
    let stalledSet = LinkedRuleSet(
      tag: "stalled", url: "http://127.0.0.1:\(stalled.port)/stalled.srs", format: "binary")
    let servedSet = LinkedRuleSet(
      tag: "served", url: "http://127.0.0.1:\(served.port)/linked.json", format: "source")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer {
      do { try FileManager.default.removeItem(at: root) } catch { Issue.record(error) }
    }
    let directories = try LibboxRuntimeDirectories.prepare(container: root, role: .systemProxy)
    let runtime = try SourceBuiltLibboxServiceRuntime(role: .systemProxy, directories: directories)
    let endpoints = try LinkedEndpoints()
    let cache = root.appendingPathComponent("cache.db")

    // libbox cannot open a cache file that is a directory, so the start fails
    // before the network starts, and nothing that started is left to close.
    let blockedCache = root.appendingPathComponent("blocked-cache.db", isDirectory: true)
    try FileManager.default.createDirectory(at: blockedCache, withIntermediateDirectories: false)
    let failed = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(ruleSets: [stalledSet], cacheFile: blockedCache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start that failed early never returned")
    stopIfStarted(runtime, failed)
    guard case .failure(let error) = failed,
      case .serviceStartFailed(let diagnostic)? = error as? LibboxRuntimeError
    else {
      Issue.record("expected a start failure whose cleanup succeeded, got \(failed)")
      return
    }
    // libbox names the cache path it could not open; however the failure is
    // printed or described, that text stays inside libbox's own type.
    #expect(diagnostic.text.contains("blocked-cache"))
    var dumped = ""
    dump(error, to: &dumped)
    for rendering in [
      String(describing: error), String(reflecting: error), "\(error)", dumped,
      error.localizedDescription, (error as NSError).description,
      String(describing: (error as NSError).userInfo),
    ] {
      #expect(!rendering.contains("blocked-cache"), "\(rendering)")
    }

    // Each stalled start also carries a rule set that downloads at once.
    let stalledConfiguration = try endpoints.configuration(
      ruleSets: [servedSet, stalledSet], cacheFile: cache)
    for attempt in 1...2 {
      let deadline = EngineStartDeadline(
        receivedAt: ContinuousClock.now.advanced(
          by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
      let timedOut = try #require(
        boundedStart(runtime, stalledConfiguration, deadline: deadline),
        "the interrupt never ended stalled start \(attempt)")
      stopIfStarted(runtime, timedOut)
      let lateness = deadline.instant.duration(to: .now)
      #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try timedOut.get() }
      #expect(lateness >= .zero, "start \(attempt) returned \(lateness) before its deadline")
      #expect(
        lateness < EngineStartBudget.deadlineTolerance + EngineStartBudget.interruptAllowance,
        "start \(attempt) returned \(lateness) after its deadline")
      #expect(stalled.acceptedConnections == attempt, "the stall was not the rule-set download")
    }
    #expect(
      served.acceptedConnections == 1,
      "a rule set that finished downloading before the interrupt was not kept")

    // Rule sets download through the outbound their `download_detour` names,
    // in production the profile's selected node. A proxy that accepts the
    // connection and never answers must not hold the start past its deadline
    // either; the URL is the served one, so a download that skipped the proxy
    // would succeed.
    let proxiedSet = LinkedRuleSet(
      tag: "proxied", url: "http://127.0.0.1:\(served.port)/proxied.json", format: "source",
      detour: "proxy")
    let proxiedDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let proxied = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(
          ruleSets: [proxiedSet], cacheFile: cache, proxyPort: stalledProxy.port),
        deadline: proxiedDeadline),
      "the interrupt never ended a start stalled at its proxy")
    stopIfStarted(runtime, proxied)
    let proxiedLateness = proxiedDeadline.instant.duration(to: .now)
    #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try proxied.get() }
    #expect(proxiedLateness >= .zero)
    #expect(
      proxiedLateness < EngineStartBudget.deadlineTolerance + EngineStartBudget.interruptAllowance,
      "a start stalled at its proxy returned \(proxiedLateness) after its deadline")
    #expect(stalledProxy.acceptedConnections == 1, "the stall was not the proxy")
    #expect(served.acceptedConnections == 1, "the proxied download reached the server")

    // With less than the minimum start window left the runtime never begins
    // the start: it times out without downloading anything.
    let tooLate = try #require(
      boundedStart(
        runtime, stalledConfiguration,
        deadline: EngineStartDeadline(
          receivedAt: ContinuousClock.now.advanced(
            by: .seconds(1) - EngineStartBudget.ownerLibboxStart))),
      "a start with too little time left never returned")
    stopIfStarted(runtime, tooLate)
    #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try tooLate.get() }
    #expect(stalled.acceptedConnections == 2, "a start that never began downloaded its rule set")

    let started = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(ruleSets: [servedSet], cacheFile: cache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start from the kept rule set never returned")
    try started.get()
    #expect(served.acceptedConnections == 1, "the start downloaded a rule set it had kept")
    try runtime.healthCheck()
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: POSIXError(.EADDRINUSE), "libbox does not listen on \(port)") {
        _ = try probeLoopbackPort(port)
      }
    }
    try runtime.stop()
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: Never.self, "libbox still listens on \(port)") {
        _ = try probeLoopbackPort(port)
      }
    }

    // libbox closes an instance once, so a close that fails leaves the runtime
    // spent. Its monitor fails here while libbox still closes every other part,
    // listeners included.
    let servedConfiguration = try endpoints.configuration(
      ruleSets: [servedSet], cacheFile: cache)
    let stopSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { throw LinkedMonitorCloseFault() })
    try #require(
      boundedStart(stopSpent, servedConfiguration, deadline: EngineStartDeadline(receivedAt: .now)),
      "a start whose close will fail never returned"
    ).get()
    let stopFailure = try #require(
      closeFailure(of: stopSpent), "a close whose network monitor failed reported success")
    guard case .closeFailed(let stopDiagnostic) = stopFailure.cause else {
      Issue.record("expected the close's own failure, got \(stopFailure.cause)")
      return
    }
    #expect(stopDiagnostic.text.contains(LinkedMonitorCloseFault.text))
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: Never.self, "libbox still listens on \(port) after its failed close") {
        _ = try probeLoopbackPort(port)
      }
    }
    #expect(closeFailure(of: stopSpent) == stopFailure, "a later stop reached libbox again")
    #expect(throws: stopFailure) {
      try stopSpent.start(
        configuration: servedConfiguration, packetFileDescriptor: nil,
        deadline: EngineStartDeadline(receivedAt: .now))
    }

    // A stalled start whose close fails when it is interrupted is spent alike.
    let interruptSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { throw LinkedMonitorCloseFault() })
    let spentDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let interrupted = try #require(
      boundedStart(interruptSpent, stalledConfiguration, deadline: spentDeadline),
      "the interrupt never ended a start whose close fails")
    stopIfStarted(interruptSpent, interrupted)
    guard case .failure(let error) = interrupted,
      let startFailure = error as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the interrupted start to report its failed close, got \(interrupted)")
      return
    }
    #expect(stalled.acceptedConnections == 3, "the stall was not the rule-set download")
    #expect(closeFailure(of: interruptSpent) == startFailure)

    // A start that fails on its own closes its instance itself. When that close
    // fails libbox keeps the instance and cannot close it again, so the runtime
    // is spent rather than idle. libbox closes only what started, so these
    // starts fail once the network monitor runs: their rule set downloads
    // through an outbound the configuration lacks, which fails before any
    // connection to the stalled server.
    let missingDetourSet = LinkedRuleSet(
      tag: stalledSet.tag, url: stalledSet.url, format: stalledSet.format, detour: "missing")
    let failedSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { throw LinkedMonitorCloseFault() })
    let ownFailure = try #require(
      boundedStart(
        failedSpent,
        try endpoints.configuration(
          ruleSets: [missingDetourSet], cacheFile: root.appendingPathComponent("own-failure.db")),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start that failed early and could not close never returned")
    stopIfStarted(failedSpent, ownFailure)
    guard case .failure(let ownError) = ownFailure,
      let ownCloseFailure = ownError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the failed start to report its failed close, got \(ownFailure)")
      return
    }
    #expect(stalled.acceptedConnections == 3, "a start that failed early downloaded its rule set")
    #expect(
      closeFailure(of: failedSpent) == ownCloseFailure,
      "the failed start did not leave the runtime spent")

    // libbox closes the instance of a start that failed on its own inside that
    // start, holding its lifecycle lock. A close that never returns there
    // holds the start and the interrupt alike, so the start is abandoned at
    // the interrupt limit and leaves the runtime spent.
    let ownStall = LinkedMonitorCloseStall()
    defer { ownStall.release() }
    let ownStalled = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { ownStall.hold() })
    let ownStallDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let ownStalledStart = try #require(
      boundedStart(
        ownStalled,
        try endpoints.configuration(
          ruleSets: [missingDetourSet], cacheFile: root.appendingPathComponent("own-stall.db")),
        deadline: ownStallDeadline),
      "a start that failed early and whose close stalled was not abandoned")
    let ownStallLateness = ownStallDeadline.instant.duration(to: .now)
    stopIfStarted(ownStalled, ownStalledStart)
    guard case .failure(let ownStallError) = ownStalledStart,
      let ownStallFailure = ownStallError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the failed start's stalled close to spend it, got \(ownStalledStart)")
      return
    }
    #expect(ownStallFailure.cause == .interruptDidNotReturn)
    #expect(ownStallLateness >= EngineStartBudget.interruptLimit)
    #expect(
      ownStallLateness
        < EngineStartBudget.interruptLimit + EngineStartBudget.deadlineTolerance * 2
        + .milliseconds(500),
      "the stalled failed start returned \(ownStallLateness) after its deadline")
    #expect(stalled.acceptedConnections == 3, "a start that failed early downloaded its rule set")
    #expect(closeFailure(of: ownStalled) == ownStallFailure)

    // A stalled start whose interrupted close never returns is abandoned at
    // the interrupt limit. Each stalled close keeps its cache file locked, so
    // these runtimes use their own.
    let interruptStall = LinkedMonitorCloseStall()
    defer { interruptStall.release() }
    let interruptStalled = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { interruptStall.hold() })
    let abandonedDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let abandoned = try #require(
      boundedStart(
        interruptStalled,
        try endpoints.configuration(
          ruleSets: [stalledSet], cacheFile: root.appendingPathComponent("interrupt-stall.db")),
        deadline: abandonedDeadline),
      "a start whose interrupt never returned was not abandoned")
    let abandonedLateness = abandonedDeadline.instant.duration(to: .now)
    stopIfStarted(interruptStalled, abandoned)
    guard case .failure(let abandonedError) = abandoned,
      let abandonedFailure = abandonedError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the abandoned start to report the runtime spent, got \(abandoned)")
      return
    }
    #expect(abandonedFailure.cause == .interruptDidNotReturn)
    #expect(abandonedLateness >= EngineStartBudget.interruptLimit)
    #expect(
      abandonedLateness
        < EngineStartBudget.interruptLimit + EngineStartBudget.deadlineTolerance * 2
        + .milliseconds(500),
      "the abandoned start returned \(abandonedLateness) after its deadline")
    #expect(stalled.acceptedConnections == 4, "the stall was not the rule-set download")
    #expect(closeFailure(of: interruptStalled) == abandonedFailure)

    // A stop whose close never returns stops waiting at the stop's bound.
    let stopStall = LinkedMonitorCloseStall()
    defer { stopStall.release() }
    let stopStalled = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { stopStall.hold() })
    try #require(
      boundedStart(
        stopStalled,
        try endpoints.configuration(
          ruleSets: [servedSet], cacheFile: root.appendingPathComponent("stop-stall.db")),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start whose close will stall never returned"
    ).get()
    let stopBegan = ContinuousClock.now
    let stalledStop = try #require(
      closeFailure(of: stopStalled), "a close that never returned reported success")
    let stopWait = stopBegan.duration(to: .now)
    #expect(stalledStop.cause == .closeDidNotReturn)
    #expect(stopWait >= EngineStopBudget.libboxClose)
    #expect(
      stopWait < EngineStopBudget.libboxClose + .milliseconds(500),
      "the stop waited \(stopWait) for a close that never returned")
    // A later stop reports the same failure at once, without libbox: one that
    // reached libbox again would wait out the bound again.
    let laterStopBegan = ContinuousClock.now
    #expect(closeFailure(of: stopStalled) == stalledStop)
    let laterStopWait = laterStopBegan.duration(to: .now)
    #expect(laterStopWait < .milliseconds(500), "a later stop waited \(laterStopWait)")
  }
#endif
