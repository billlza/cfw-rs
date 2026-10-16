import CFWSharedProtocol
import Dispatch
import Synchronization

/// Bounds one synchronous libbox start by its owner's deadline.
///
/// libbox starts on its owner's serial queue and cannot observe a caller
/// deadline, so at the deadline the watchdog runs `interrupt` (libbox
/// `CloseService`, which interrupts the start and returns once the start has
/// returned). `run` returns only after the start returned and, when the
/// deadline fired, after the interrupt returned too, so the caller's cleanup
/// never races the interrupt.
struct LibboxStartWatchdog: Sendable {
  typealias Cancel = @Sendable () -> Void
  typealias Schedule =
    @Sendable (ContinuousClock.Instant, @escaping @Sendable () -> Void) -> Cancel

  enum Outcome<Value> {
    /// Less than `minimumStartWindow` was left, so the start was never called.
    case notStarted
    /// The start returned before the deadline fired.
    case completed(Result<Value, any Error>)
    /// The deadline fired while the start ran. `start` is what the start
    /// returned; `interruption` is how the interrupt, which ran to completion,
    /// ended.
    case interrupted(start: Result<Value, any Error>, interruption: Result<Void, any Error>)
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

  private static let interruptQueue = DispatchQueue(
    label: "com.bill.clashformac.libbox-start-watchdog", qos: .userInitiated)

  private let now: @Sendable () -> ContinuousClock.Instant
  private let schedule: Schedule

  /// Sleeps on the continuous clock, which keeps counting while the Mac sleeps.
  /// The Host's waits for the owner's report (the ProxyAgent start reply and
  /// Packet Tunnel readiness) count only awake time, so after a sleep this
  /// deadline still fires first.
  init() {
    let clock = ContinuousClock()
    self.init(now: { clock.now }, schedule: Self.sleeping(on: clock))
  }

  /// Arms each deadline by sleeping on `clock` with the budget's tolerance;
  /// cancelling ends the sleep. The interrupt runs on a dedicated queue because
  /// `CloseService` blocks until the start returns.
  static func sleeping<C: Clock>(on clock: C) -> Schedule
  where C.Instant == ContinuousClock.Instant {
    { instant, action in
      let sleeper = Task.detached(priority: .userInitiated) {
        let cancelled: Bool
        do {
          try await clock.sleep(until: instant, tolerance: EngineStartBudget.deadlineTolerance)
          cancelled = false
        } catch {
          // Only cancellation ends the sleep early: the start returned first.
          cancelled = error is CancellationError
        }
        guard !cancelled else { return }
        Self.interruptQueue.async(execute: action)
      }
      return { sleeper.cancel() }
    }
  }

  init(now: @escaping @Sendable () -> ContinuousClock.Instant, schedule: @escaping Schedule) {
    self.now = now
    self.schedule = schedule
  }

  func run<Value>(
    deadline: EngineStartDeadline,
    interrupt: @escaping @Sendable () throws -> Void,
    start: () throws -> Value
  ) -> Outcome<Value> {
    guard now().duration(to: deadline.instant) >= Self.minimumStartWindow else {
      return .notStarted
    }
    let attempt = LibboxStartAttempt(interrupt: interrupt)
    let cancel = schedule(deadline.instant) { attempt.deadlineFired() }
    let result = Result { try start() }
    guard let interruption = attempt.startReturned() else {
      cancel()
      return .completed(result)
    }
    return .interrupted(start: result, interruption: interruption)
  }
}

/// What one bounded libbox start means for the runtime that ran it.
struct LibboxStartVerdict<Conflict> {
  /// The endpoint conflict libbox reported, or the error that fails the start.
  let start: Result<Conflict?, any Error>
  /// How the interrupt ended, or nil when the deadline never fired. The
  /// interrupt already closed the service, so a failed interrupt is the start's
  /// cleanup failure and the runtime must not close the service again.
  let interruption: Result<Void, any Error>?
}

extension LibboxStartWatchdog.Outcome {
  /// libbox reports an interrupted start as success, so an interrupted start
  /// that reported neither an error nor an endpoint conflict timed out. A start
  /// that failed or hit a conflict before the interrupt keeps its own cause.
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
    }
  }
}

/// One armed start. The deadline and the start's return race through one
/// mutex, so the interrupt runs at most once and never after the start won.
private final class LibboxStartAttempt: Sendable {
  private enum State {
    case armed(@Sendable () throws -> Void)
    case interrupting
    case interrupted(Result<Void, any Error>)
    case completedInTime
  }

  private let state: Mutex<State>
  private let interruptReturned = DispatchSemaphore(value: 0)

  init(interrupt: @escaping @Sendable () throws -> Void) {
    state = Mutex(.armed(interrupt))
  }

  func deadlineFired() {
    let interrupt = state.withLock { state -> (@Sendable () throws -> Void)? in
      guard case .armed(let interrupt) = state else { return nil }
      state = .interrupting
      return interrupt
    }
    guard let interrupt else { return }
    let result = Result { try interrupt() }
    state.withLock { $0 = .interrupted(result) }
    interruptReturned.signal()
  }

  /// Returns nil when the start won; otherwise waits for the interrupt to
  /// return and gives its result.
  func startReturned() -> Result<Void, any Error>? {
    let mustWait = state.withLock { state -> Bool in
      switch state {
      case .armed:
        state = .completedInTime
        return false
      case .interrupting:
        return true
      case .interrupted:
        return false
      case .completedInTime:
        preconditionFailure("a libbox start attempt returned twice")
      }
    }
    if mustWait {
      interruptReturned.wait()
    }
    return state.withLock { state -> Result<Void, any Error>? in
      switch state {
      case .completedInTime:
        return nil
      case .interrupted(let result):
        return result
      case .armed, .interrupting:
        preconditionFailure("a fired libbox interrupt did not record its result")
      }
    }
  }
}
