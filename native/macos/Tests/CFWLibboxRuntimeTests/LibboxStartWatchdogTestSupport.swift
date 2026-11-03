import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// Shared by the start watchdog tests: test errors, a manual deadline, clock and
// interrupt recorder, a gate, a background run, and the watchdog they build.
enum WatchdogTestError: Error, Equatable {
  case start
}

struct CloseTestFailure: LocalizedError {
  static let text = "watchdog test: the close failed"
  var errorDescription: String? { Self.text }
}

let interruptFailure = LibboxInstanceUnclosable(closeFailure: CloseTestFailure.text)

/// A timer the watchdog armed: the deadline at an instant of the continuous
/// clock, or the interrupt limit after a duration of awake time.
enum ArmedTimer: Equatable {
  case at(ContinuousClock.Instant)
  case awake(Duration)
}

/// Records each timer the watchdog arms instead of arming it, so each test
/// decides when (and whether) each one fires: first the deadline, then the
/// interrupt limit that a fired deadline arms. `onArm` runs as each timer is
/// armed, with its index.
final class ManualStartDeadline: @unchecked Sendable {
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
final class ManualNow: @unchecked Sendable {
  private let lock = NSLock()
  private var instant: ContinuousClock.Instant

  init(_ instant: ContinuousClock.Instant) { self.instant = instant }

  var now: @Sendable () -> ContinuousClock.Instant { { self.lock.withLock { self.instant } } }
}

final class InterruptRecorder: @unchecked Sendable {
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
final class Gate: Sendable {
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
final class BackgroundRun<Value: Sendable>: @unchecked Sendable {
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

let now = ContinuousClock.now
let deadline = EngineStartDeadline(receivedAt: now)

func watchdog(
  _ manual: ManualStartDeadline, now clock: ManualNow = ManualNow(now)
) -> LibboxStartWatchdog {
  LibboxStartWatchdog(now: clock.now, schedule: manual.schedule, afterAwake: manual.afterAwake)
}

/// Runs the watchdog off the test's thread and returns its outcome, or nil
/// after recording an issue when it did not return within ten seconds.
func bounded<Value: Sendable>(
  _ run: @escaping @Sendable () -> LibboxStartWatchdog.Outcome<Value>,
  sourceLocation: SourceLocation = #_sourceLocation
) -> LibboxStartWatchdog.Outcome<Value>? {
  let outcome = BackgroundRun(run).awaitOutcome(within: .seconds(10))
  if outcome == nil {
    Issue.record("the watchdog run did not return", sourceLocation: sourceLocation)
  }
  return outcome
}
