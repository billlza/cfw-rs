import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

// Bounded callbacks: the first normal result, a timeout or a cancellation that
// wins, and late callbacks ignored.
private final class CallbackRecorder<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private let installed = OneShotLatch()
  private var callback: (@Sendable (Result<Value, Error>) -> Void)?

  func install(_ callback: @escaping @Sendable (Result<Value, Error>) -> Void) {
    lock.withLock { self.callback = callback }
    installed.signal()
  }

  func waitUntilInstalled() async { await installed.wait() }

  func finish(_ result: Result<Value, Error>) {
    let callback = lock.withLock { self.callback }
    callback?(result)
  }
}

@Test func boundedCallbackReturnsFirstNormalResult() async throws {
  let deadlines = ManualDeadlineScheduler()
  let callback = CallbackRecorder<Int>()
  let task = Task<Int, Error> {
    try await awaitBoundedCallback(
      deadline: deadlines.scheduler,
      timeoutError: AppleNetworkError.preferenceLoadTimedOut
    ) { callback.install($0) }
  }
  await deadlines.waitUntilScheduled()
  await callback.waitUntilInstalled()
  #expect(!deadlines.isCancelled(at: 0))
  callback.finish(.success(9))
  #expect(try await task.value == 9)
  #expect(deadlines.isCancelled(at: 0), "a wait that has its result must cancel its deadline")
  deadlines.fire(at: 0)
}

@Test func boundedCallbackTimesOutAndIgnoresLateCallback() async throws {
  let deadlines = ManualDeadlineScheduler()
  let callback = CallbackRecorder<Int>()
  let task = Task<Int, Error> {
    try await awaitBoundedCallback(
      deadline: deadlines.scheduler,
      timeoutError: AppleNetworkError.preferenceSaveTimedOut
    ) { callback.install($0) }
  }
  await deadlines.waitUntilScheduled()
  await callback.waitUntilInstalled()
  deadlines.fire(at: 0)
  await #expect(throws: AppleNetworkError.preferenceSaveTimedOut) {
    try await task.value
  }
  callback.finish(.success(10))
}

@Test func boundedCallbackCancellationWinsAndLateCallbackIsIgnored() async throws {
  let deadlines = ManualDeadlineScheduler()
  let callback = CallbackRecorder<Int>()
  let task = Task<Int, Error> {
    try await awaitBoundedCallback(
      deadline: deadlines.scheduler,
      timeoutError: AppleNetworkError.preferenceLoadTimedOut
    ) { callback.install($0) }
  }
  await deadlines.waitUntilScheduled()
  await callback.waitUntilInstalled()
  task.cancel()
  await #expect(throws: CancellationError.self) { try await task.value }
  #expect(deadlines.isCancelled(at: 0), "a cancelled wait must cancel its deadline")
  callback.finish(.success(11))
  deadlines.fire(at: 0)
}
