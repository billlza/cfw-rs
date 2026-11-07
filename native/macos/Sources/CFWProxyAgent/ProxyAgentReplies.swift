import Foundation
import Synchronization

/// Counts the requests the agent received and has not answered yet. An agent
/// that ends waits for them, so no Host waits for an answer that never
/// comes; see `ProxyAgentProcessExit`.
final class ProxyAgentUnansweredRequests: Sendable {
  private struct State {
    var count = 0
    var whenNone: [@Sendable () -> Void] = []
  }

  private let state = Mutex(State())

  /// Runs `work` once no request is left unanswered: at once when none is.
  func whenNone(_ work: @escaping @Sendable () -> Void) {
    let now = state.withLock { state -> Bool in
      guard state.count > 0 else { return true }
      state.whenNone.append(work)
      return false
    }
    if now { work() }
  }

  /// Only `ProxyXPCReply` counts, once per request, so every answer has its
  /// request.
  fileprivate func received() {
    state.withLock { $0.count += 1 }
  }

  fileprivate func answered() {
    let ready = state.withLock { state -> [@Sendable () -> Void] in
      precondition(state.count > 0, "A ProxyAgent request was answered twice")
      state.count -= 1
      guard state.count == 0 else { return [] }
      defer { state.whenNone = [] }
      return state.whenNone
    }
    for work in ready { work() }
  }
}

/// Answers one request once, and counts it as unanswered until then.
final class ProxyXPCReply: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: ((Data?, NSError?) -> Void)?
  private let requests: ProxyAgentUnansweredRequests

  init(
    _ handler: @escaping (Data?, NSError?) -> Void, requests: ProxyAgentUnansweredRequests
  ) {
    self.handler = handler
    self.requests = requests
    requests.received()
  }

  func finish(data: Data?, error: NSError?) {
    lock.lock()
    let handler = handler
    self.handler = nil
    lock.unlock()
    guard let handler else { return }
    handler(data, error)
    requests.answered()
  }
}
