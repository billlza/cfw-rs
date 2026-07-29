import Foundation
import Testing

@testable import CFWAppleNetwork

private struct FixedProxyAgentServiceController: ProxyAgentServiceControlling {
  let status: ProxyAgentRegistrationStatus

  func registrationStatus() -> ProxyAgentRegistrationStatus { status }

  func ensureRegistered() throws {}
}

private final class ProxyAgentTestCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func increment() { lock.withLock { value += 1 } }
  var count: Int { lock.withLock { value } }
}

private final class ProxyAgentTestLatch: @unchecked Sendable {
  private let lock = NSLock()
  private var signaled = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func signal() {
    let values = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
      guard !signaled else { return [] }
      signaled = true
      let values = waiters
      waiters.removeAll()
      return values
    }
    for value in values { value.resume() }
  }

  func wait() async {
    await withCheckedContinuation { continuation in
      let ready = lock.withLock {
        guard !signaled else { return true }
        waiters.append(continuation)
        return false
      }
      if ready { continuation.resume() }
    }
  }
}

private func transport(
  status: ProxyAgentRegistrationStatus
) throws -> AuthenticatedProxyAgentTransport {
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent",
    teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    serviceController: FixedProxyAgentServiceController(status: status))
}

@Suite(.serialized)
struct ProxyAgentHostClientTests {
  @Test func outstandingReplyRegistryAppliesExactBoundAndReleasesCapacity() throws {
    var registry = BoundedProxyAgentRequestRegistry(maximum: 2)
    let first = try registry.reserve()
    let second = try registry.reserve()
    #expect(registry.tokens.count == 2)
    #expect(throws: ProxyAgentHostError.transportCapacityExceeded) {
      _ = try registry.reserve()
    }

    registry.release(first)
    let replacement = try registry.reserve()
    #expect(registry.tokens == [second, replacement])
    registry.release(UUID())
    #expect(registry.tokens.count == 2)
  }

  @Test func timeoutCancellationTransportLossAndProtocolDriftRequireConnectionRotation() {
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportTimedOut))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportUnavailable("injected")))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: CancellationError()))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.malformedResponse))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.responseMismatch))
    #expect(
      !AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportCapacityExceeded))
  }

  @Test func retiringAConnectionFailsEveryConcurrentRequestAndInvalidatesExactlyOnce() {
    let invalidations = ProxyAgentTestCounter()
    let failures = ProxyAgentTestCounter()
    let lifecycle = ProxyAgentConnectionLifecycle {
      invalidations.increment()
    }
    let first = UUID()
    let second = UUID()
    #expect(lifecycle.register(token: first) { failures.increment() })
    #expect(lifecycle.register(token: second) { failures.increment() })
    #expect(lifecycle.pendingCount == 2)

    lifecycle.retire()
    lifecycle.retire()
    #expect(lifecycle.isRetired)
    #expect(lifecycle.pendingCount == 0)
    #expect(failures.count == 2)
    #expect(invalidations.count == 1)

    #expect(!lifecycle.register(token: UUID()) { failures.increment() })
    #expect(failures.count == 3)
  }

  @Test func lateReplyOnRetiredConnectionCannotCompleteReplacementGeneration() async throws {
    let oldLifecycle = ProxyAgentConnectionLifecycle {}
    let oldGate = CallbackContinuationGate<Int>()
    let oldInstalled = ProxyAgentTestLatch()
    let oldToken = UUID()
    let oldTask = Task<Int, Error> {
      try await withCheckedThrowingContinuation { continuation in
        oldGate.install(continuation)
        #expect(
          oldLifecycle.register(token: oldToken) {
            oldGate.finish(
              .failure(ProxyAgentHostError.transportUnavailable("connection-retired"))
            )
          }
        )
        oldInstalled.signal()
      }
    }
    await oldInstalled.wait()
    oldLifecycle.retire()
    await #expect(throws: ProxyAgentHostError.self) {
      _ = try await oldTask.value
    }

    let replacementGate = CallbackContinuationGate<Int>()
    let replacementInstalled = ProxyAgentTestLatch()
    let replacementTask = Task<Int, Error> {
      try await withCheckedThrowingContinuation { continuation in
        replacementGate.install(continuation)
        replacementInstalled.signal()
      }
    }
    await replacementInstalled.wait()
    oldGate.finish(.success(1))
    replacementGate.finish(.success(2))
    #expect(try await replacementTask.value == 2)
  }

  @Test func snapshotRequiresApprovedRegistrationInsteadOfProjectingFalseOff() async throws {
    let awaitingApproval = try transport(status: .requiresApproval)
    await #expect(throws: ProxyAgentHostError.registrationRequiresApproval) {
      _ = try await awaitingApproval.snapshot()
    }

    for status in [ProxyAgentRegistrationStatus.notRegistered, .notFound] {
      let unavailable = try transport(status: status)
      await #expect(throws: ProxyAgentHostError.registrationUnavailable) {
        _ = try await unavailable.snapshot()
      }
    }
  }
}
