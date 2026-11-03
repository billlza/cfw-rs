import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Synchronization for the start command tests: bounded promises, the
// handshake that holds a native fixture at a chosen point, and the log of
// cleanup events.
enum NativeFixtureWaitError: Error, Equatable { case deadlineExceeded, injectedFailure }
enum NativeFixtureBlockPoint: CaseIterable { case snapshot, authorization, installation }
enum NativeFixtureReadinessFailure: CaseIterable { case deadline, cancellation }

/// A bounded single-wait promise using the production callback gate's existing
/// first-terminal-result, early-completion and cancellation semantics.
final class NativeFixturePromise<Value: Sendable>: Sendable {
  private let gate = CallbackContinuationGate<Value>()

  func finish(_ result: Result<Value, Error>) { gate.finish(result) }

  func wait(
    deadline: CallbackDeadlineScheduler = .init(timeout: .seconds(5))
  ) async throws -> Value {
    try Task.checkCancellation()
    var cancelDeadline: CallbackDeadlineScheduler.Cancel?
    defer { cancelDeadline?() }
    let value = try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        gate.install(continuation)
        guard !Task.isCancelled else {
          gate.finish(.failure(CancellationError()))
          return
        }
        guard gate.beginOperation() else { return }
        cancelDeadline = deadline.schedule { [weak gate] in
          gate?.finish(.failure(NativeFixtureWaitError.deadlineExceeded))
        }
      }
    } onCancel: {
      gate.finish(.failure(CancellationError()))
    }
    try Task.checkCancellation()
    return value
  }
}

/// Each fixture pauses once. Entry is observable, release is remembered even
/// before entry, and cancellation/deadlines use the same single-resume gate.
final class NativeFixtureHandshake: Sendable {
  private let entered = NativeFixturePromise<Void>()
  private let released = NativeFixturePromise<Void>()

  func enter() async throws {
    try Task.checkCancellation()
    entered.finish(.success(()))
    try await released.wait()
  }

  func waitUntilEntered(
    deadline: CallbackDeadlineScheduler = .init(timeout: .seconds(5))
  ) async throws {
    try await entered.wait(deadline: deadline)
  }

  func release() { released.finish(.success(())) }

  func cancel() {
    entered.finish(.failure(CancellationError()))
    released.finish(.failure(CancellationError()))
  }
}

/// Readiness is a prerequisite, not an expectation after which execution may
/// continue. Any prerequisite/body failure cancels and drains the exact task.
func whileNativeFixtureBlocked<Value: Sendable>(
  at handshake: NativeFixtureHandshake,
  readinessDeadline: CallbackDeadlineScheduler = .init(timeout: .seconds(5)),
  operation: @escaping @Sendable () async throws -> Value,
  body: () async throws -> Void
) async throws -> Value {
  let task = Task { try await operation() }
  do {
    try await handshake.waitUntilEntered(deadline: readinessDeadline)
    try await body()
    handshake.release()
    return try await task.value
  } catch {
    task.cancel()
    handshake.cancel()
    _ = await task.result
    throw error
  }
}

final class NativeCleanupEventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [String] = []
  func append(_ value: String) { lock.withLock { values.append(value) } }
  func removeAll() { lock.withLock { values.removeAll() } }
  var events: [String] { lock.withLock { values } }
}

// MARK: - Fakes
