import Foundation

/// Schedules a callback deadline independently of the caller task. Production
/// arms a strict dispatch timer on the uptime clock, so a deadline counts only
/// time the Mac is awake; tests inject a manual scheduler so timeout and
/// late-callback races do not depend on wall-clock sleeps. A strict timer asks
/// the system to keep to its leeway instead of deferring it to batch wakeups,
/// so every wait cancels its deadline once its result arrived and only a
/// deadline that expires costs a CPU wakeup; the bridge budget's nesting
/// assumes that requested lateness.
package struct CallbackDeadlineScheduler: Sendable {
  /// Cancels a scheduled deadline. Cancelling after it fired does nothing.
  package typealias Cancel = @Sendable () -> Void

  /// How a production deadline arms its dispatch timer.
  struct TimerArming: Equatable, Sendable {
    /// Seconds from arming until the deadline.
    let delay: Double
    let leeway: DispatchTimeInterval

    /// Asks the system to keep to the leeway, on a best-effort basis, instead
    /// of applying its larger default to save power.
    var flags: DispatchSource.TimerFlags { .strict }
  }

  /// The largest leeway a production deadline requests, which the system keeps
  /// on a best-effort basis. Dispatch's default leeway is a tenth of the wait:
  /// an 18-second start reply could fire almost two seconds late, and a silent
  /// owner's rollback would overrun the bridge budget.
  package static let maximumLeeway: Duration = .milliseconds(100)

  private let scheduleBody: @Sendable (@escaping @Sendable () -> Void) -> Cancel

  package init(timeout: Duration) {
    let arming = Self.arming(for: timeout)
    scheduleBody = { action in
      let timer = DispatchSource.makeTimerSource(flags: arming.flags, queue: .global(qos: .utility))
      // The handler keeps its timer alive until the one firing; cancelling the
      // timer, there or through the returned handle, releases the handler and
      // with it the timer.
      timer.setEventHandler {
        timer.cancel()
        action()
      }
      // DispatchTime is the uptime clock, which stops while the Mac sleeps.
      let fireAt: DispatchTime = .now() + arming.delay
      timer.schedule(deadline: fireAt, leeway: arming.leeway)
      timer.resume()
      return { timer.cancel() }
    }
  }

  init(schedule: @escaping @Sendable (@escaping @Sendable () -> Void) -> Cancel) {
    scheduleBody = schedule
  }

  /// A strict timer that fires `timeout` after it is armed and requests a
  /// leeway of a tenth of the wait, never more than `maximumLeeway`.
  static func arming(for timeout: Duration) -> TimerArming {
    precondition(timeout > .zero, "Callback deadline must be positive")
    let components = timeout.components
    let delay =
      Double(components.seconds) + Double(components.attoseconds) / 1_000_000_000_000_000_000
    precondition(delay.isFinite && delay > 0, "Callback deadline must be finite")
    let leeway = min(timeout / 10, maximumLeeway).components
    return TimerArming(
      delay: delay,
      leeway: .nanoseconds(
        Int(leeway.seconds) * 1_000_000_000 + Int(leeway.attoseconds / 1_000_000_000)))
  }

  /// Arms the deadline. The caller cancels it once its wait has a result.
  func schedule(_ action: @escaping @Sendable () -> Void) -> Cancel {
    scheduleBody(action)
  }
}

/// First-terminal-result gate for callback APIs that cannot be canceled. The
/// callback, deadline, and task-cancellation paths race through one lock and
/// therefore resume the checked continuation exactly once.
final class CallbackContinuationGate<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Value, Error>?
  private var completedResult: Result<Value, Error>?
  private var operationStarted = false

  func install(_ continuation: CheckedContinuation<Value, Error>) {
    lock.lock()
    if let completedResult {
      lock.unlock()
      continuation.resume(with: completedResult)
      return
    }
    precondition(self.continuation == nil, "Provider response continuation installed twice")
    self.continuation = continuation
    lock.unlock()
  }

  /// Atomically claims the right to invoke the callback API. Cancellation or an
  /// injected synchronous deadline that wins first prevents the side effect.
  func beginOperation() -> Bool {
    lock.lock()
    guard completedResult == nil, !operationStarted else {
      lock.unlock()
      return false
    }
    operationStarted = true
    lock.unlock()
    return true
  }

  func finish(_ result: Result<Value, Error>) {
    lock.lock()
    guard completedResult == nil else {
      lock.unlock()
      return
    }
    completedResult = result
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(with: result)
  }
}

typealias ProviderResponseGate = CallbackContinuationGate<Data>

/// Adapts a single callback operation to async/await with an internal deadline.
/// The deadline is owned by the Swift boundary rather than a Rust waiter, so a
/// missing framework callback cannot retain a coordinator mutation forever.
package func awaitBoundedCallback<Value: Sendable>(
  deadline: CallbackDeadlineScheduler,
  timeoutError: any Error,
  operation:
    @escaping (
      @escaping @Sendable (Result<Value, Error>) -> Void
    ) -> Void
) async throws -> Value {
  let gate = CallbackContinuationGate<Value>()
  var cancelDeadline: CallbackDeadlineScheduler.Cancel?
  defer { cancelDeadline?() }
  return try await withTaskCancellationHandler {
    try await withCheckedThrowingContinuation { continuation in
      gate.install(continuation)
      guard !Task.isCancelled else {
        gate.finish(.failure(CancellationError()))
        return
      }
      cancelDeadline = deadline.schedule {
        gate.finish(.failure(timeoutError))
      }
      guard gate.beginOperation() else { return }
      operation { result in
        gate.finish(result)
      }
    }
  } onCancel: {
    gate.finish(.failure(CancellationError()))
  }
}

final class PreferenceSaveWait: @unchecked Sendable {
  let operationID: UUID
  let stageID: UUID
  private let operation: PreferenceMutationOperation
  private let journal: PreferenceMutationJournal
  private let timeoutError: AppleNetworkError
  private let failureError: @Sendable (NetworkExtensionOperationFailure) -> AppleNetworkError
  private let gate = CallbackContinuationGate<Void>()
  private let lock = NSLock()
  private var submitted = false

  init(
    operationID: UUID,
    stageID: UUID,
    operation: PreferenceMutationOperation,
    journal: PreferenceMutationJournal,
    timeoutError: AppleNetworkError,
    failureError: @escaping @Sendable (NetworkExtensionOperationFailure) -> AppleNetworkError
  ) {
    self.operationID = operationID
    self.stageID = stageID
    self.operation = operation
    self.journal = journal
    self.timeoutError = timeoutError
    self.failureError = failureError
  }

  var wasSubmitted: Bool { lock.withLock { submitted } }

  func install(_ continuation: CheckedContinuation<Void, Error>) {
    gate.install(continuation)
  }

  func beginSubmission() -> Bool {
    guard gate.beginOperation() else { return false }
    do {
      try journal.markSubmitted(
        operationID: operationID,
        stageID: stageID,
        operation: operation
      )
      lock.withLock { submitted = true }
      return true
    } catch {
      gate.finish(.failure(error))
      return false
    }
  }

  func timeout() {
    gate.finish(.failure(timeoutError))
  }

  func cancel() {
    gate.finish(.failure(CancellationError()))
  }

  func finish(_ error: Error?) {
    let outcome: PreferenceSaveCallbackOutcome
    if let error {
      outcome = .failed(NetworkExtensionOperationFailure(error))
    } else {
      outcome = .succeeded
    }
    do {
      let disposition = try journal.recordCallback(
        operationID: operationID,
        stageID: stageID,
        operation: operation,
        outcome: outcome
      )
      guard disposition == .recorded else {
        // A timeout/cancellation that already won the gate may safely ignore an
        // obsolete late callback. If this callback still owns the live waiter,
        // the gate accepts this failure instead of projecting an unjournaled
        // Network Extension success.
        gate.finish(.failure(AppleNetworkError.preferenceMutationUncertain))
        return
      }
      switch outcome {
      case .succeeded:
        gate.finish(.success(()))
      case .failed(let failure):
        gate.finish(.failure(failureError(failure)))
      }
    } catch {
      gate.finish(.failure(error))
    }
  }
}
