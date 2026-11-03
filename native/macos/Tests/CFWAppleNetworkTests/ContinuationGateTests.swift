import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

// The identity-bound continuation gate: the first terminal result, old
// cancellations and late callbacks ignored, callbacks and approvals cached for
// the exact retry, and watches of a pending approval.
private final class TestRequest: @unchecked Sendable {}

@Test func providerResponseGatePreservesFirstTerminalResultBeforeInstall() async throws {
  let gate = ProviderResponseGate()
  let expected = Data("first".utf8)
  gate.finish(.success(expected))
  gate.finish(.success(Data("late".utf8)))

  let received = try await withCheckedThrowingContinuation { continuation in
    gate.install(continuation)
  }

  #expect(received == expected)
}

@Test func identityBoundGateIgnoresOldCancellationAndLateCallback() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let firstRequest = TestRequest()
  let retryCandidate = TestRequest()
  let nextRequest = TestRequest()
  let firstWaitID = UUID()
  let retryWaitID = UUID()
  let nextWaitID = UUID()
  let firstInstalled = OneShotLatch()
  let retryInstalled = OneShotLatch()
  let nextInstalled = OneShotLatch()

  let firstTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: firstRequest,
          waitID: firstWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: firstRequest, waitID: firstWaitID))
      firstInstalled.signal()
    }
  }
  await firstInstalled.wait()
  gate.finishWaitKeepingRequest(
    waitID: firstWaitID,
    result: .failure(CancellationError()))
  do {
    _ = try await firstTask.value
    Issue.record("Canceled continuation unexpectedly succeeded")
  } catch is CancellationError {
    // Expected: cancellation resumes the waiter but retains the in-flight
    // request identity until the operating system reports its terminal result.
  }

  let retryTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: retryCandidate,
          waitID: retryWaitID,
          continuation: continuation) == .reattach)
      retryInstalled.signal()
    }
  }
  await retryInstalled.wait()

  // A stale cancellation/deadline from the first waiter cannot finish its retry.
  gate.finishWaitKeepingRequest(
    waitID: firstWaitID,
    result: .failure(AppleNetworkError.systemExtensionInstallationTimedOut))
  gate.finish(request: firstRequest, result: .success(2))
  #expect(try await retryTask.value == 2)

  let nextTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: nextRequest,
          waitID: nextWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: nextRequest, waitID: nextWaitID))
      nextInstalled.signal()
    }
  }
  await nextInstalled.wait()
  // A duplicate late callback from the old request cannot complete the new wait.
  gate.finish(request: firstRequest, result: .success(3))
  gate.finish(request: nextRequest, result: .success(4))
  #expect(try await nextTask.value == 4)
}

@Test func identityBoundGateRejectsConcurrentOperationUntilCallbackArrives() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let firstRequest = TestRequest()
  let secondRequest = TestRequest()
  let firstWaitID = UUID()
  let secondWaitID = UUID()
  let firstInstalled = OneShotLatch()

  let firstTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: firstRequest,
          waitID: firstWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: firstRequest, waitID: firstWaitID))
      firstInstalled.signal()
    }
  }
  await firstInstalled.wait()

  do {
    let _: Int = try await withCheckedThrowingContinuation { continuation in
      if gate.install(
        request: secondRequest,
        waitID: secondWaitID,
        continuation: continuation) == .rejected
      {
        continuation.resume(throwing: GateTestError.busy)
      }
    }
    Issue.record("Concurrent continuation was unexpectedly installed")
  } catch GateTestError.busy {
    // Expected.
  }

  gate.finish(request: firstRequest, result: .success(1))
  #expect(try await firstTask.value == 1)
}

@Test func identityBoundGateExplicitCancelBoundsRetiredRequestUntilTerminalCallback() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let oldRequest = TestRequest()
  let newRequest = TestRequest()
  let oldWaitID = UUID()
  let newWaitID = UUID()
  let oldInstalled = OneShotLatch()
  let newInstalled = OneShotLatch()

  let oldTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: oldRequest,
          waitID: oldWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: oldRequest, waitID: oldWaitID))
      oldInstalled.signal()
    }
  }
  await oldInstalled.wait()
  gate.cancelActiveWait()
  await #expect(throws: CancellationError.self) { try await oldTask.value }
  #expect(gate.retiredRequestCount == 1)

  do {
    let _: Int = try await withCheckedThrowingContinuation { continuation in
      let action = gate.install(
        request: newRequest,
        waitID: newWaitID,
        continuation: continuation
      )
      #expect(action == .retirementCapacityExceeded)
      continuation.resume(throwing: GateTestError.busy)
    }
    Issue.record("A second unresolved System Extension request was accepted")
  } catch GateTestError.busy {
    // The exact retired request owns the sole unresolved-request capacity.
  }

  gate.finish(request: oldRequest, result: .success(1))
  #expect(gate.retiredRequestCount == 0)

  let replacementTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: newRequest,
          waitID: newWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: newRequest, waitID: newWaitID))
      newInstalled.signal()
    }
  }
  await newInstalled.wait()
  gate.finish(request: newRequest, result: .success(2))
  #expect(try await replacementTask.value == 2)
}

@Test func identityBoundGateCachesTerminalCallbackForRetry() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let request = TestRequest()
  let firstWaitID = UUID()
  let firstInstalled = OneShotLatch()

  let firstTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: request,
          waitID: firstWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: request, waitID: firstWaitID))
      firstInstalled.signal()
    }
  }
  await firstInstalled.wait()
  gate.finishWaitKeepingRequest(
    waitID: firstWaitID,
    result: .failure(AppleNetworkError.systemExtensionInstallationTimedOut))
  await #expect(throws: AppleNetworkError.systemExtensionInstallationTimedOut) {
    try await firstTask.value
  }
  gate.finish(request: request, result: .success(7))

  let retryCandidate = TestRequest()
  let result: Int = try await withCheckedThrowingContinuation { continuation in
    #expect(
      gate.install(
        request: retryCandidate,
        waitID: UUID(),
        continuation: continuation) == .completed)
  }
  #expect(result == 7)
}

@Test func identityBoundGateCachesLateApprovalForExactRetry() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let request = TestRequest()
  let firstWaitID = UUID()
  let firstInstalled = OneShotLatch()

  let firstTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(
        gate.install(
          request: request,
          waitID: firstWaitID,
          continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: request, waitID: firstWaitID))
      firstInstalled.signal()
    }
  }
  await firstInstalled.wait()
  gate.finishWaitKeepingRequest(
    waitID: firstWaitID,
    result: .failure(AppleNetworkError.systemExtensionInstallationTimedOut))
  await #expect(throws: AppleNetworkError.systemExtensionInstallationTimedOut) {
    try await firstTask.value
  }

  #expect(gate.completeWaitKeepingRequest(request: request, value: 12))
  let retryResult: Int = try await withCheckedThrowingContinuation { continuation in
    #expect(
      gate.install(
        request: TestRequest(),
        waitID: UUID(),
        continuation: continuation) == .completed)
  }
  #expect(retryResult == 12)
}

/// Submits `request` and completes the caller's wait with the intermediate
/// value, as `requestNeedsUserApproval` does, keeping the request.
private func awaitingApproval(
  _ gate: IdentityBoundContinuation<TestRequest, Int>, request: TestRequest
) async throws {
  let waitID = UUID()
  let installed = OneShotLatch()
  let wait = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(gate.install(request: request, waitID: waitID, continuation: continuation) == .submit)
      #expect(gate.beginSubmission(request: request, waitID: waitID))
      installed.signal()
    }
  }
  await installed.wait()
  #expect(gate.completeWaitKeepingRequest(request: request, value: 1))
  #expect(try await wait.value == 1)
}

/// Starts a watch and returns once it is registered with the gate.
private func watch(
  _ gate: IdentityBoundContinuation<TestRequest, Int>, observerID: UUID = UUID()
) async -> Task<IdentityBoundTerminalObservation, Never> {
  let registered = OneShotLatch()
  let task = Task<IdentityBoundTerminalObservation, Never> {
    await withCheckedContinuation { continuation in
      gate.observeTerminal(observerID: observerID, continuation: continuation)
      registered.signal()
    }
  }
  await registered.wait()
  return task
}

@Test func identityBoundGateWatchSeesTheApprovalAndLeavesItsResultForTheRetry() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let request = TestRequest()
  try await awaitingApproval(gate, request: request)

  let watching = await watch(gate)
  gate.finish(request: request, result: .success(7))
  #expect(await watching.value == .terminalArrived)

  let retryResult: Int = try await withCheckedThrowingContinuation { continuation in
    #expect(
      gate.install(request: TestRequest(), waitID: UUID(), continuation: continuation)
        == .completed)
  }
  #expect(retryResult == 7)
}

@Test func identityBoundGateWatchEndsAtOnceForAStoredResultOrNoRequest() async throws {
  let empty = IdentityBoundContinuation<TestRequest, Int>()
  #expect(await watch(empty).value == .noActiveRequest)

  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let request = TestRequest()
  try await awaitingApproval(gate, request: request)
  gate.finish(request: request, result: .success(7))
  #expect(await watch(gate).value == .terminalArrived)
  #expect(await watch(gate).value == .terminalArrived, "a watch never consumes the result")
}

@Test func identityBoundGateWatchEndsByItsDeadlineAnExplicitCancelOrAnotherWatch() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  try await awaitingApproval(gate, request: TestRequest())

  let observerID = UUID()
  let first = await watch(gate, observerID: observerID)
  #expect(await watch(gate).value == .alreadyObserved)
  gate.finishObservation(observerID: observerID)
  #expect(await first.value == .stillPending)

  let second = await watch(gate)
  gate.cancelActiveWait()
  #expect(await second.value == .noActiveRequest)
  #expect(await watch(gate).value == .noActiveRequest)
}
