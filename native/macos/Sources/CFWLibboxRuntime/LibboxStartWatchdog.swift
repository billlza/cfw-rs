import CFWSharedProtocol
import Dispatch
import Synchronization

/// Bounds one synchronous libbox start by its owner's deadline.
///
/// libbox cannot observe a caller deadline, so the start runs on its own
/// thread and at the deadline the watchdog runs `interrupt` (libbox
/// `CloseService`, which interrupts the start and returns once the start has
/// returned) on another. `run` returns once the start returned and, when the
/// deadline fired, the interrupt returned too, so the caller's cleanup never
/// races the interrupt. When either is still inside libbox once the Mac was
/// awake for `EngineStartBudget.interruptLimit` after the deadline fired, `run`
/// returns that the attempt was abandoned instead and leaves both threads
/// where they are: the caller must never reach libbox again.
struct LibboxStartWatchdog: Sendable {
  typealias Cancel = @Sendable () -> Void
  /// Runs an action at an instant of the continuous clock.
  typealias Schedule =
    @Sendable (ContinuousClock.Instant, @escaping @Sendable () -> Void) -> Cancel
  /// Runs an action once the Mac has been awake for a duration.
  typealias AwakeTimer = @Sendable (Duration, @escaping @Sendable () -> Void) -> Cancel

  enum Outcome<Value: Sendable>: Sendable {
    /// Less than `minimumStartWindow` was left, so the start was never called.
    case notStarted
    /// The start returned before the deadline fired.
    case completed(Result<Value, any Error>)
    /// The deadline fired while the start ran. `start` is what the start
    /// returned; `interruption` is how the interrupt, which ran to completion,
    /// ended.
    case interrupted(
      start: Result<Value, any Error>, interruption: Result<Void, LibboxInstanceUnclosable>)
    /// The deadline fired, and the start or its interrupt had not returned
    /// `EngineStartBudget.interruptLimit` later.
    case abandoned
  }

  /// libbox keeps an interrupt that lands while it still builds the instance
  /// and ends the start once the instance exists (CFM's libbox patch), so such a
  /// deadline costs the rest of the build. Building a configuration at the
  /// 4 MiB limit made of 46,000 domain rules took about 1.2 seconds on the
  /// development Mac (2026-10-15); costlier rules take longer. A start begins
  /// only while at least this much is left, so for any configuration that
  /// builds faster the deadline lands after the build, where interrupting a
  /// stalled rule-set download fits `EngineStartBudget.interruptAllowance` (see
  /// there for what the linked test holds).
  static let minimumStartWindow: Duration = .seconds(2)

  private let now: @Sendable () -> ContinuousClock.Instant
  private let schedule: Schedule
  private let afterAwake: AwakeTimer

  /// The deadline sleeps on the continuous clock, which keeps counting while
  /// the Mac sleeps. The Host's waits for the owner's report (the ProxyAgent
  /// start reply and Packet Tunnel readiness) count only awake time, so after
  /// a sleep the deadline still fires first. The interrupt limit sleeps on the
  /// suspending clock instead: like the first wait for a network path that it
  /// covers and like the Host's waits, it counts only awake time, so a sleep
  /// neither ends it before that wait nor lets it outlast the Host's.
  init() {
    let clock = ContinuousClock()
    self.init(
      now: { clock.now }, schedule: Self.sleeping(on: clock),
      afterAwake: Self.sleepingAwake(on: SuspendingClock()))
  }

  /// Arms each deadline by sleeping on `clock` with the budget's tolerance;
  /// cancelling ends the sleep.
  static func sleeping<C: Clock>(on clock: C) -> Schedule
  where C.Instant == ContinuousClock.Instant {
    { instant, action in arm(clock, until: instant, action) }
  }

  /// Arms each interrupt limit by sleeping on `clock`, which counts only
  /// awake time, with the budget's tolerance; cancelling ends the sleep.
  static func sleepingAwake<C: Clock>(on clock: C) -> AwakeTimer
  where C.Instant == SuspendingClock.Instant {
    { duration, action in arm(clock, until: clock.now.advanced(by: duration), action) }
  }

  private static func arm<C: Clock>(
    _ clock: C, until instant: C.Instant, _ action: @escaping @Sendable () -> Void
  ) -> Cancel where C.Duration == Duration {
    let sleeper = Task.detached(priority: .userInitiated) {
      let cancelled: Bool
      do {
        try await clock.sleep(until: instant, tolerance: EngineStartBudget.deadlineTolerance)
        cancelled = false
      } catch {
        // Only cancellation ends the sleep early: the attempt ended first.
        cancelled = error is CancellationError
      }
      guard !cancelled else { return }
      action()
    }
    return { sleeper.cancel() }
  }

  init(
    now: @escaping @Sendable () -> ContinuousClock.Instant, schedule: @escaping Schedule,
    afterAwake: @escaping AwakeTimer
  ) {
    self.now = now
    self.schedule = schedule
    self.afterAwake = afterAwake
  }

  func run<Value: Sendable>(
    deadline: EngineStartDeadline,
    interrupt: @escaping @Sendable () throws(LibboxInstanceUnclosable) -> Void,
    start: @escaping @Sendable () throws -> Value
  ) -> Outcome<Value> {
    guard now().duration(to: deadline.instant) >= Self.minimumStartWindow else {
      return .notStarted
    }
    let attempt = LibboxStartAttempt<Value>(interrupt: interrupt)
    let cancelDeadline = schedule(deadline.instant) { [afterAwake] in
      // The limit counts from when the deadline fired, so a deadline that
      // fires late, as after the Mac slept through it, still gives the
      // interrupt the whole limit.
      attempt.deadlineFired {
        afterAwake(EngineStartBudget.interruptLimit) { attempt.interruptLimitPassed() }
      }
    }
    // Each attempt has its own queues, so a start or interrupt that never
    // returns holds back no other attempt in the process.
    DispatchQueue(label: "com.bill.clashformac.libbox-start", qos: .userInitiated).async {
      attempt.startReturned(Result { try start() })
    }
    let outcome = attempt.awaitOutcome()
    cancelDeadline()
    return outcome
  }
}

/// What one bounded libbox start means for the runtime that ran it.
struct LibboxStartVerdict<Conflict> {
  /// The endpoint conflict libbox reported, or the error that fails the start.
  let start: Result<Conflict?, any Error>
  /// How the interrupt ended, or nil when the deadline never fired. The
  /// interrupt already closed the service, so a failed interrupt is the start's
  /// cleanup failure and the runtime must not close the service again.
  let interruption: Result<Void, LibboxInstanceUnclosable>?
}

extension LibboxStartWatchdog.Outcome {
  /// libbox reports an interrupted start as success, so an interrupted start
  /// that reported neither an error nor an endpoint conflict timed out. A start
  /// that failed or hit a conflict before the interrupt keeps its own cause. An
  /// abandoned start timed out, and its runtime cannot be closed because a
  /// thread may still be inside libbox.
  func verdict<Conflict>() -> LibboxStartVerdict<Conflict> where Value == Conflict? {
    switch self {
    case .notStarted:
      return LibboxStartVerdict(
        start: .failure(LibboxRuntimeError.serviceStartTimedOut), interruption: nil)
    case .completed(let start):
      return LibboxStartVerdict(start: start, interruption: nil)
    case .interrupted(start: .success(nil), let interruption):
      return LibboxStartVerdict(
        start: .failure(LibboxRuntimeError.serviceStartTimedOut), interruption: interruption)
    case .interrupted(let start, let interruption):
      return LibboxStartVerdict(start: start, interruption: interruption)
    case .abandoned:
      return LibboxStartVerdict(
        start: .failure(LibboxRuntimeError.serviceStartTimedOut),
        interruption: .failure(LibboxInstanceUnclosable(.interruptDidNotReturn)))
    }
  }
}

/// One armed start. The start's return, the deadline, the interrupt's return
/// and the interrupt limit race through one mutex, so the interrupt runs at
/// most once and never after the start won, and the attempt ends exactly once.
/// Returns that arrive after the attempt was abandoned change nothing.
private final class LibboxStartAttempt<Value: Sendable>: Sendable {
  private enum Phase {
    case running
    case interrupting(
      start: Result<Value, any Error>?, interruption: Result<Void, LibboxInstanceUnclosable>?)
    case ended(LibboxStartWatchdog.Outcome<Value>)
  }

  private struct State {
    var phase = Phase.running
    var cancelInterruptLimit: LibboxStartWatchdog.Cancel?
  }

  private let interrupt: @Sendable () throws(LibboxInstanceUnclosable) -> Void
  private let state = Mutex(State())
  private let ended = DispatchSemaphore(value: 0)

  init(interrupt: @escaping @Sendable () throws(LibboxInstanceUnclosable) -> Void) {
    self.interrupt = interrupt
  }

  /// Interrupts a start that is still running. The interrupt limit is armed
  /// before the interrupt runs, and an interrupt that has not begun once the
  /// limit passed and abandoned the attempt does not run: nothing it would
  /// call reaches libbox after an abandonment.
  func deadlineFired(armInterruptLimit: () -> LibboxStartWatchdog.Cancel) {
    let interrupts = state.withLock { state -> Bool in
      guard case .running = state.phase else { return false }
      state.phase = .interrupting(start: nil, interruption: nil)
      return true
    }
    guard interrupts else { return }
    let cancel = armInterruptLimit()
    state.withLock { $0.cancelInterruptLimit = cancel }
    let interrupt = interrupt
    DispatchQueue(label: "com.bill.clashformac.libbox-start-interrupt", qos: .userInitiated)
      .async { [self] in
        guard isInterrupting else { return }
        let interruption = Result { () throws(LibboxInstanceUnclosable) in try interrupt() }
        interruptReturned(interruption)
      }
  }

  private var isInterrupting: Bool {
    state.withLock { state in
      guard case .interrupting = state.phase else { return false }
      return true
    }
  }

  func startReturned(_ result: Result<Value, any Error>) {
    finish { phase in
      switch phase {
      case .running:
        return .completed(result)
      case .interrupting(start: nil, let interruption):
        guard let interruption else {
          phase = .interrupting(start: result, interruption: nil)
          return nil
        }
        return .interrupted(start: result, interruption: interruption)
      case .interrupting(start: .some(_), _):
        preconditionFailure("a libbox start attempt returned twice")
      case .ended:
        return nil
      }
    }
  }

  func interruptLimitPassed() {
    finish { phase in
      guard case .interrupting = phase else { return nil }
      return .abandoned
    }
  }

  /// Waits until the attempt ended, then cancels its interrupt limit.
  func awaitOutcome() -> LibboxStartWatchdog.Outcome<Value> {
    ended.wait()
    let (outcome, cancelInterruptLimit) = state.withLock {
      state -> (LibboxStartWatchdog.Outcome<Value>, LibboxStartWatchdog.Cancel?) in
      guard case .ended(let outcome) = state.phase else {
        preconditionFailure("a libbox start attempt signalled its end before it ended")
      }
      return (outcome, state.cancelInterruptLimit)
    }
    cancelInterruptLimit?()
    return outcome
  }

  private func interruptReturned(_ interruption: Result<Void, LibboxInstanceUnclosable>) {
    finish { phase in
      switch phase {
      case .interrupting(let start, interruption: nil):
        guard let start else {
          phase = .interrupting(start: nil, interruption: interruption)
          return nil
        }
        return .interrupted(start: start, interruption: interruption)
      case .interrupting(_, interruption: .some(_)):
        preconditionFailure("a libbox start interrupt returned twice")
      case .running:
        preconditionFailure("a libbox start interrupt ran before its deadline fired")
      case .ended:
        return nil
      }
    }
  }

  /// Applies `transition` and, when it ends the attempt, wakes `awaitOutcome`.
  private func finish(
    _ transition: (inout Phase) -> LibboxStartWatchdog.Outcome<Value>?
  ) {
    let endsAttempt = state.withLock { state -> Bool in
      guard let outcome = transition(&state.phase) else { return false }
      state.phase = .ended(outcome)
      return true
    }
    if endsAttempt {
      ended.signal()
    }
  }
}

/// Bounds one libbox `CloseService` at a stop, or after a start that failed on
/// its own, by `EngineStopBudget.libboxClose`.
///
/// `CloseService` returns once libbox closed every part of the instance. A part
/// that never finishes closing would hold the owner's serial queue, and every
/// later reply behind it, for good, so the close runs on its own thread and the
/// caller stops waiting at the bound. The thread stays inside libbox, so the
/// caller must never reach libbox again.
struct LibboxBoundedClose: Sendable {
  enum Outcome: Equatable, Sendable {
    case closed
    /// libbox's close reported this failure.
    case failed(LibboxDiagnostic)
    case didNotReturn
  }

  let bound: Duration

  init(bound: Duration = EngineStopBudget.libboxClose) {
    self.bound = bound
  }

  func run(_ close: @escaping @Sendable () throws -> Void) -> Outcome {
    let reported = LibboxCloseReport()
    DispatchQueue(label: "com.bill.clashformac.libbox-close", qos: .userInitiated).async {
      do {
        try close()
        reported.record(.closed)
      } catch {
        reported.record(.failed(LibboxDiagnostic(error.localizedDescription)))
      }
    }
    return reported.outcome(within: bound) ?? .didNotReturn
  }
}

/// What one bounded close reported, handed from its thread to the caller.
private final class LibboxCloseReport: Sendable {
  private let outcome = Mutex<LibboxBoundedClose.Outcome?>(nil)
  private let recorded = DispatchSemaphore(value: 0)

  func record(_ outcome: LibboxBoundedClose.Outcome) {
    self.outcome.withLock { $0 = outcome }
    recorded.signal()
  }

  /// The close's outcome, or nil when it had not returned within `bound`.
  func outcome(within bound: Duration) -> LibboxBoundedClose.Outcome? {
    guard recorded.wait(timeout: .now() + bound.dispatchTimeInterval) == .success else {
      return nil
    }
    return outcome.withLock { $0 }
  }
}

extension Duration {
  /// This duration as Dispatch counts it, to the nanosecond.
  var dispatchTimeInterval: DispatchTimeInterval {
    let (seconds, attoseconds) = components
    return .nanoseconds(Int(seconds) * 1_000_000_000 + Int(attoseconds / 1_000_000_000))
  }
}
