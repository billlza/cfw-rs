import Foundation

enum IdentityBoundInstallAction: Equatable, Sendable {
  case submit
  case reattach
  case completed
  case rejected
  case retirementCapacityExceeded
}

/// What a watch over the submitted request learned. Watching never takes the
/// request over and never consumes its terminal result.
enum IdentityBoundTerminalObservation: Equatable, Sendable {
  /// The request's terminal callback arrived; its result waits for the next
  /// install.
  case terminalArrived
  /// No submitted request awaits a terminal callback.
  case noActiveRequest
  /// The watch's own deadline or cancellation ended it first.
  case stillPending
  /// Another watch already waits for the same request.
  case alreadyObserved
}

final class IdentityBoundContinuation<Request: AnyObject, Value: Sendable>: @unchecked Sendable {
  private struct TerminalObserver {
    let id: UUID
    let continuation: CheckedContinuation<IdentityBoundTerminalObservation, Never>
  }

  private let lock = NSLock()
  private var activeRequest: Request?
  private var continuation: CheckedContinuation<Value, Error>?
  private var waitID: UUID?
  private var requestSubmitted = false
  private var completedResult: Result<Value, Error>?
  private var pendingWaitResult: Result<Value, Error>?
  private var intermediateResultDelivered = false
  private var terminalObserver: TerminalObserver?
  private var retiredRequests: [ObjectIdentifier: Request] = [:]
  private let maximumRetiredRequests = 1

  func install(
    request: Request,
    waitID: UUID,
    continuation: CheckedContinuation<Value, Error>
  ) -> IdentityBoundInstallAction {
    lock.lock()
    if let completedResult {
      self.completedResult = nil
      lock.unlock()
      continuation.resume(with: completedResult)
      return .completed
    }
    if let pendingWaitResult {
      self.pendingWaitResult = nil
      lock.unlock()
      continuation.resume(with: pendingWaitResult)
      return .completed
    }
    if activeRequest != nil {
      guard self.continuation == nil else {
        lock.unlock()
        return .rejected
      }
      self.waitID = waitID
      self.continuation = continuation
      lock.unlock()
      return .reattach
    }
    if retiredRequests.count >= maximumRetiredRequests {
      lock.unlock()
      return .retirementCapacityExceeded
    }
    activeRequest = request
    self.waitID = waitID
    self.continuation = continuation
    requestSubmitted = false
    intermediateResultDelivered = false
    lock.unlock()
    return .submit
  }

  func beginSubmission(request: Request, waitID: UUID) -> Bool {
    lock.lock()
    guard activeRequest === request, self.waitID == waitID,
      continuation != nil, !requestSubmitted
    else {
      lock.unlock()
      return false
    }
    requestSubmitted = true
    lock.unlock()
    return true
  }

  func finish(request: Request, result: Result<Value, Error>) {
    lock.lock()
    guard activeRequest === request else {
      retiredRequests.removeValue(forKey: ObjectIdentifier(request))
      lock.unlock()
      return
    }
    activeRequest = nil
    let continuation = continuation
    self.continuation = nil
    waitID = nil
    requestSubmitted = false
    pendingWaitResult = nil
    intermediateResultDelivered = false
    if continuation == nil {
      completedResult = result
    }
    let observer = terminalObserver
    terminalObserver = nil
    lock.unlock()
    continuation?.resume(with: result)
    observer?.continuation.resume(returning: .terminalArrived)
  }

  /// Watches the submitted request until its terminal callback arrives. The
  /// continuation is resumed exactly once: at once when that result is
  /// already stored, when no request is submitted, or when another watch
  /// waits; otherwise by the terminal callback, an explicit cancel, or
  /// `finishObservation`.
  func observeTerminal(
    observerID: UUID,
    continuation: CheckedContinuation<IdentityBoundTerminalObservation, Never>
  ) {
    lock.lock()
    let immediate: IdentityBoundTerminalObservation?
    if completedResult != nil {
      immediate = .terminalArrived
    } else if activeRequest == nil || !requestSubmitted {
      immediate = .noActiveRequest
    } else if terminalObserver != nil {
      immediate = .alreadyObserved
    } else {
      immediate = nil
      terminalObserver = TerminalObserver(id: observerID, continuation: continuation)
    }
    lock.unlock()
    if let immediate {
      continuation.resume(returning: immediate)
    }
  }

  /// Ends one watch for its deadline or its caller's cancellation.
  func finishObservation(observerID: UUID) {
    lock.lock()
    guard let observer = terminalObserver, observer.id == observerID else {
      lock.unlock()
      return
    }
    terminalObserver = nil
    lock.unlock()
    observer.continuation.resume(returning: .stillPending)
  }

  func finishWaitKeepingRequest(waitID: UUID, result: Result<Value, Error>) {
    lock.lock()
    guard self.waitID == waitID, continuation != nil else {
      lock.unlock()
      return
    }
    let continuation = continuation
    self.continuation = nil
    self.waitID = nil
    if !requestSubmitted {
      activeRequest = nil
    }
    lock.unlock()
    continuation?.resume(with: result)
  }

  /// Completes only the caller's wait while retaining the operating-system
  /// request identity until its terminal delegate callback arrives.
  @discardableResult
  func completeWaitKeepingRequest(request: Request, value: Value) -> Bool {
    lock.lock()
    guard activeRequest === request, !intermediateResultDelivered else {
      lock.unlock()
      return false
    }
    intermediateResultDelivered = true
    let continuation = continuation
    self.continuation = nil
    waitID = nil
    if continuation == nil {
      pendingWaitResult = .success(value)
    }
    lock.unlock()
    continuation?.resume(returning: value)
    return true
  }

  /// Retires one exact submitted request for an explicit cancel command. The OS
  /// request cannot be withdrawn; while it remains unresolved, the single-entry
  /// retirement bound rejects another submission instead of accumulating
  /// uncancellable requests. Its terminal callback releases the capacity only.
  func cancelActiveWait() {
    lock.lock()
    let continuation = continuation
    if let activeRequest, requestSubmitted {
      precondition(
        retiredRequests.count < maximumRetiredRequests,
        "System Extension retired-request capacity invariant"
      )
      retiredRequests[ObjectIdentifier(activeRequest)] = activeRequest
    }
    activeRequest = nil
    self.continuation = nil
    waitID = nil
    requestSubmitted = false
    completedResult = nil
    pendingWaitResult = nil
    intermediateResultDelivered = false
    let observer = terminalObserver
    terminalObserver = nil
    lock.unlock()
    continuation?.resume(throwing: CancellationError())
    observer?.continuation.resume(returning: .noActiveRequest)
  }

  var retiredRequestCount: Int { lock.withLock { retiredRequests.count } }

}
