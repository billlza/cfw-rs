import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

// Shared by the continuation gate tests: the credential audience, a test error,
// a one-shot latch and a manual deadline scheduler.
func appleCredentialAudience() throws -> CredentialAudience {
  CredentialAudience(
    profileID: UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!,
    profileDigest: try SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

enum GateTestError: Error {
  case busy
}

final class OneShotLatch: @unchecked Sendable {
  private let lock = NSLock()
  private var signaled = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func signal() {
    let continuations = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
      guard !signaled else { return [] }
      signaled = true
      let continuations = waiters
      waiters.removeAll()
      return continuations
    }
    for continuation in continuations {
      continuation.resume()
    }
  }

  func wait() async {
    await withCheckedContinuation { continuation in
      let resumeImmediately = lock.withLock { () -> Bool in
        guard !signaled else { return true }
        waiters.append(continuation)
        return false
      }
      if resumeImmediately {
        continuation.resume()
      }
    }
  }
}

/// Shared by the transport tests: records deadlines instead of arming timers.
final class ManualDeadlineScheduler: @unchecked Sendable {
  private let lock = NSLock()
  private let scheduled = OneShotLatch()
  private var actions: [@Sendable () -> Void] = []
  private var cancelled: [Bool] = []

  var scheduler: CallbackDeadlineScheduler {
    CallbackDeadlineScheduler { action in
      let index = self.lock.withLock {
        self.actions.append(action)
        self.cancelled.append(false)
        return self.actions.count - 1
      }
      self.scheduled.signal()
      return { self.lock.withLock { self.cancelled[index] = true } }
    }
  }

  func waitUntilScheduled() async { await scheduled.wait() }

  /// Runs a deadline's action even after its wait cancelled it, as a timer
  /// that was already firing would, so tests can race a late deadline.
  func fire(at index: Int) {
    let action = lock.withLock { actions[index] }
    action()
  }

  func isCancelled(at index: Int) -> Bool { lock.withLock { cancelled[index] } }
}
