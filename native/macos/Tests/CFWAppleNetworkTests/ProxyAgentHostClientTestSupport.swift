import CFWSharedProtocol
import CryptoKit
import Foundation
import Security
import Testing

@testable import CFWAppleNetwork

// Shared by the ProxyAgent host client tests: a fixed and a fake service, a
// registration error, a counter and a latch, and the default transport.
struct FixedProxyAgentServiceController: ProxyAgentServiceControlling {
  let status: ProxyAgentRegistrationStatus

  func registrationStatus() -> ProxyAgentRegistrationStatus { status }

  func ensureRegistered() throws {}
}

final class FakeProxyAgentService: ProxyAgentServicing, @unchecked Sendable {
  private(set) var registerCalls = 0
  var statuses: [ProxyAgentRegistrationStatus]
  var registerError: (any Error)?

  init(
    _ statuses: [ProxyAgentRegistrationStatus],
    registerError: (any Error)? = nil
  ) {
    self.statuses = statuses
    self.registerError = registerError
  }

  var registrationStatus: ProxyAgentRegistrationStatus {
    statuses.count > 1 ? statuses.removeFirst() : statuses[0]
  }

  func requireRegistrationReady() throws {}

  func register() throws {
    registerCalls += 1
    if let registerError { throw registerError }
  }

  func unregister() throws {}
}

enum ProxyAgentRegistrationTestError: Error { case denied }

final class ProxyAgentTestCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func increment() { lock.withLock { value += 1 } }
  var count: Int { lock.withLock { value } }
}

final class ProxyAgentTestLatch: @unchecked Sendable {
  private let lock = NSLock()
  private var signaled = false
  private var waiters: [UUID: CheckedContinuation<Void, Never>] = [:]

  func signal() {
    let values = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
      guard !signaled else { return [] }
      signaled = true
      let values = Array(waiters.values)
      waiters.removeAll()
      return values
    }
    for value in values { value.resume() }
  }

  /// Returns once signalled, and throws `CancellationError` as soon as the
  /// waiting task is cancelled, so a test's time limit also ends a wait
  /// nothing will signal.
  func wait() async throws {
    let id = UUID()
    await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        let ready = lock.withLock {
          guard !signaled, !Task.isCancelled else { return true }
          waiters[id] = continuation
          return false
        }
        if ready { continuation.resume() }
      }
    } onCancel: {
      lock.withLock { waiters.removeValue(forKey: id) }?.resume()
    }
    try Task.checkCancellation()
  }
}

func transport(
  status: ProxyAgentRegistrationStatus
) throws -> AuthenticatedProxyAgentTransport {
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent",
    teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    currentCodeHash: try ServiceCodeHash(Data(repeating: 0x42, count: 20)),
    serviceController: FixedProxyAgentServiceController(status: status))
}
