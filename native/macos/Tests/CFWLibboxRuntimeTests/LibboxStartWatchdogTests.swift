import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// The start watchdog: starts that return before or past their deadline,
// interrupts that run, fail or never return, and the limit that abandons them.
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
