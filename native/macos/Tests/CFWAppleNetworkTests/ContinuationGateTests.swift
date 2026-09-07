import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

func appleCredentialAudience() throws -> CredentialAudience {
  CredentialAudience(
    profileID: UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!,
    profileDigest: try SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

private enum GateTestError: Error {
  case busy
}

private final class TestRequest: @unchecked Sendable {}

private final class OneShotLatch: @unchecked Sendable {
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

@Test func systemExtensionReplacementCancelsEqualBundleVersion() {
  #expect(
    OSSystemExtensionInstaller.replacementAction(
      existingBundleVersion: "40002",
      candidateBundleVersion: "40002"
    ) == .cancel
  )
}

@Test func systemExtensionReplacementCancelsOlderBundleVersion() {
  #expect(
    OSSystemExtensionInstaller.replacementAction(
      existingBundleVersion: "40002",
      candidateBundleVersion: "40001"
    ) == .cancel
  )
}

@Test func systemExtensionReplacementAcceptsOnlyNewerBundleVersion() {
  for (existing, candidate) in [
    ("40001", "40002"),
    ("9223372036854775806", "9223372036854775807"),
  ] {
    #expect(
      OSSystemExtensionInstaller.replacementAction(
        existingBundleVersion: existing,
        candidateBundleVersion: candidate
      ) == .replace
    )
  }
}

@Test func systemExtensionReplacementCancelsMalformedOrNonCanonicalVersions() {
  for (existing, candidate) in [
    ("abc", "40002"),
    ("40001", "abc"),
    ("40001", "040002"),
    ("40001", "0"),
    ("40001", "40002.0"),
    ("40001", "40002b1"),
    ("40001", "9223372036854775808"),
    ("40001", "10000000000000000000"),
    ("40001", ""),
  ] {
    #expect(
      OSSystemExtensionInstaller.replacementAction(
        existingBundleVersion: existing,
        candidateBundleVersion: candidate
      ) == .cancel
    )
  }
}

private final class ManualDeadlineScheduler: @unchecked Sendable {
  private let lock = NSLock()
  private let scheduled = OneShotLatch()
  private var actions: [@Sendable () -> Void] = []

  var scheduler: CallbackDeadlineScheduler {
    CallbackDeadlineScheduler { action in
      self.lock.withLock { self.actions.append(action) }
      self.scheduled.signal()
    }
  }

  func waitUntilScheduled() async { await scheduled.wait() }

  func fire(at index: Int) {
    let action = lock.withLock { actions[index] }
    action()
  }
}

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

private final class MemoryPreferenceMutationStore:
  TunnelPreferenceMutationJournalStoring, @unchecked Sendable
{
  private let lock = NSLock()
  private var state: TunnelPreferenceMutationState?
  private var compareExchangeFailure = false

  func load() -> TunnelPreferenceMutationState? { lock.withLock { state } }

  func create(_ state: TunnelPreferenceMutationState) -> Bool {
    lock.withLock {
      guard self.state == nil else { return false }
      self.state = state
      return true
    }
  }

  func compareExchange(
    expected: TunnelPreferenceMutationState,
    desired: TunnelPreferenceMutationState
  ) throws -> Bool {
    try lock.withLock {
      if compareExchangeFailure { throw GateTestError.busy }
      guard state == expected else { return false }
      state = desired
      return true
    }
  }

  func compareDelete(expected: TunnelPreferenceMutationState) -> Bool {
    lock.withLock {
      guard state == expected else { return false }
      state = nil
      return true
    }
  }

  func forceState(_ replacement: TunnelPreferenceMutationState?) {
    lock.withLock { state = replacement }
  }

  func failCompareExchange(_ enabled: Bool) {
    lock.withLock { compareExchangeFailure = enabled }
  }
}

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  let tunnelOptions = try TunnelNetworkOptions(
    ipv6Enabled: true,
    bypassPrivateNetworks: true,
    mtu: 1_500
  )
  return try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: tunnelOptions,
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

private func preferenceValues(
  _ descriptor: ConfigurationDescriptor,
  description: String
) -> ManagedTunnelPreferenceValues {
  ManagedTunnelPreferenceValues(
    descriptor: descriptor,
    isEnabled: true,
    localizedDescription: description
  )
}

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
  callback.finish(.success(9))
  #expect(try await task.value == 9)
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
  callback.finish(.success(11))
  deadlines.fire(at: 0)
}

@Test func uncertainPreferenceWriteBlocksNextGenerationUntilExactReconciliation() async throws {
  let store = MemoryPreferenceMutationStore()
  let journal = try PreferenceMutationJournal(store: store)
  let descriptorA = try tunnelDescriptor()
  let descriptorB = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: descriptorA.tunnelOptions,
    credentialAudience: descriptorA.credentialAudience,
    installationID: descriptorA.installationID,
    epoch: descriptorA.epoch,
    generation: descriptorA.generation + 1,
    byteCount: descriptorA.byteCount,
    sha256: descriptorA.sha256
  )
  let receiptA = TunnelPreferenceMutationReceipt(
    operationID: UUID(),
    createdManager: true,
    priorValues: nil,
    writtenValues: preferenceValues(descriptorA, description: "generation-a")
  )
  let receiptB = TunnelPreferenceMutationReceipt(
    operationID: UUID(),
    createdManager: false,
    priorValues: receiptA.writtenValues,
    writtenValues: preferenceValues(descriptorB, description: "generation-b")
  )

  let stageA = try journal.begin(receiptA)
  let waitA = PreferenceSaveWait(
    operationID: receiptA.operationID,
    stageID: stageA,
    operation: .originalSave,
    journal: journal,
    timeoutError: .preferenceSaveTimedOut,
    failureError: AppleNetworkError.preferenceSaveFailed
  )
  let submittedA = OneShotLatch()
  let waiterA = Task<Void, Error> {
    try await withCheckedThrowingContinuation { continuation in
      waitA.install(continuation)
      #expect(waitA.beginSubmission())
      submittedA.signal()
    }
  }
  await submittedA.wait()
  waitA.timeout()
  await #expect(throws: AppleNetworkError.preferenceSaveTimedOut) {
    try await waiterA.value
  }
  #expect(throws: AppleNetworkError.self) {
    try journal.begin(receiptB)
  }

  // A's late callback advances only A. B remains blocked until an explicit
  // reload proves A's exact descriptor and the OS-facing connection is Off.
  waitA.finish(nil)
  #expect(throws: AppleNetworkError.preferenceMutationUncertain) {
    try journal.begin(receiptB)
  }
  let pendingA = try journal.pendingReceipt(
    expectedDescriptor: descriptorA,
    requireSettledCurrentProcessMutation: true
  )
  let readyA = try #require(pendingA)
  try journal.clear(operationID: readyA.operationID)

  let stageB = try journal.begin(receiptB)
  try journal.markSubmitted(
    operationID: receiptB.operationID,
    stageID: stageB,
    operation: .originalSave
  )
  #expect(
    try journal.recordCallback(
      operationID: receiptA.operationID,
      stageID: stageA,
      operation: .originalSave,
      outcome: .succeeded
    ) == .obsolete)
  #expect(throws: AppleNetworkError.preferenceMutationUncertain) {
    try journal.begin(receiptA)
  }
  #expect(
    try journal.recordCallback(
      operationID: receiptB.operationID,
      stageID: stageB,
      operation: .originalSave,
      outcome: .succeeded
    ) == .recorded)
  let pendingB = try journal.pendingReceipt(
    expectedDescriptor: descriptorB,
    requireSettledCurrentProcessMutation: true
  )
  let readyB = try #require(pendingB)
  try journal.clear(operationID: readyB.operationID)
}

@Test func livePreferenceCallbackFailsClosedWhenJournalIsMissingOrReplaced() async throws {
  for replaceWithAnotherGeneration in [false, true] {
    let store = MemoryPreferenceMutationStore()
    let journal = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
    let descriptor = try tunnelDescriptor()
    let receipt = TunnelPreferenceMutationReceipt(
      operationID: UUID(),
      createdManager: true,
      priorValues: nil,
      writtenValues: preferenceValues(descriptor, description: "live-write")
    )
    let stageID = try journal.begin(receipt)
    let wait = PreferenceSaveWait(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .originalSave,
      journal: journal,
      timeoutError: .preferenceSaveTimedOut,
      failureError: AppleNetworkError.preferenceSaveFailed
    )
    let submitted = OneShotLatch()
    let waiter = Task<Void, Error> {
      try await withCheckedThrowingContinuation { continuation in
        wait.install(continuation)
        #expect(wait.beginSubmission())
        submitted.signal()
      }
    }
    await submitted.wait()

    let replacement: TunnelPreferenceMutationState?
    if replaceWithAnotherGeneration {
      let replacementReceipt = TunnelPreferenceMutationReceipt(
        operationID: UUID(),
        createdManager: true,
        priorValues: nil,
        writtenValues: preferenceValues(descriptor, description: "replacement")
      )
      replacement = TunnelPreferenceMutationState(
        revision: 1,
        receipt: replacementReceipt,
        stageID: UUID(),
        operation: .originalSave,
        phase: .prepared,
        bootSessionID: nil,
        callbackOutcome: nil
      )
    } else {
      replacement = nil
    }
    store.forceState(replacement)

    wait.finish(nil)
    await #expect(throws: AppleNetworkError.preferenceMutationUncertain) {
      try await waiter.value
    }
    #expect(store.load() == replacement)
  }
}

@Test func livePreferenceCallbackNeverProjectsSuccessWhenTerminalPersistenceFails() async throws {
  let store = MemoryPreferenceMutationStore()
  let journal = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
  let descriptor = try tunnelDescriptor()
  let receipt = TunnelPreferenceMutationReceipt(
    operationID: UUID(),
    createdManager: true,
    priorValues: nil,
    writtenValues: preferenceValues(descriptor, description: "terminal-write-failure")
  )
  let stageID = try journal.begin(receipt)
  let wait = PreferenceSaveWait(
    operationID: receipt.operationID,
    stageID: stageID,
    operation: .originalSave,
    journal: journal,
    timeoutError: .preferenceSaveTimedOut,
    failureError: AppleNetworkError.preferenceSaveFailed
  )
  let submitted = OneShotLatch()
  let waiter = Task<Void, Error> {
    try await withCheckedThrowingContinuation { continuation in
      wait.install(continuation)
      #expect(wait.beginSubmission())
      submitted.signal()
    }
  }
  await submitted.wait()

  store.failCompareExchange(true)
  wait.finish(nil)

  await #expect(throws: AppleNetworkError.self) { try await waiter.value }
  let retained = try journal.currentState(operationID: receipt.operationID)
  #expect(retained.phase == .submitted)
  #expect(retained.callbackOutcome == nil)
  #expect(throws: AppleNetworkError.self) {
    _ = try journal.pendingReceipt(
      expectedDescriptor: descriptor,
      requireSettledCurrentProcessMutation: true
    )
  }
}

@Test func timedOutPreferenceWaitIgnoresObsoleteLateCallback() async throws {
  let store = MemoryPreferenceMutationStore()
  let journal = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
  let descriptor = try tunnelDescriptor()
  let receipt = TunnelPreferenceMutationReceipt(
    operationID: UUID(),
    createdManager: true,
    priorValues: nil,
    writtenValues: preferenceValues(descriptor, description: "timed-out-write")
  )
  let stageID = try journal.begin(receipt)
  let wait = PreferenceSaveWait(
    operationID: receipt.operationID,
    stageID: stageID,
    operation: .originalSave,
    journal: journal,
    timeoutError: .preferenceSaveTimedOut,
    failureError: AppleNetworkError.preferenceSaveFailed
  )
  let submitted = OneShotLatch()
  let waiter = Task<Void, Error> {
    try await withCheckedThrowingContinuation { continuation in
      wait.install(continuation)
      #expect(wait.beginSubmission())
      submitted.signal()
    }
  }
  await submitted.wait()
  wait.timeout()
  await #expect(throws: AppleNetworkError.preferenceSaveTimedOut) {
    try await waiter.value
  }

  store.forceState(nil)
  wait.finish(nil)
  #expect(store.load() == nil)
}

@Test func preferenceNSErrorClassificationUsesOnlyOfficialDomainAndCode() {
  let posixPermission = NetworkExtensionOperationFailure(
    NSError(
      domain: NSPOSIXErrorDomain,
      code: Int(POSIXErrorCode.EACCES.rawValue),
      userInfo: [NSLocalizedDescriptionKey: "access denied"]
    )
  )
  #expect(posixPermission.domain == NSPOSIXErrorDomain)
  #expect(posixPermission.code == Int(POSIXErrorCode.EACCES.rawValue))
  #expect(posixPermission.disposition == .permissionDenied)

  let cocoaPermission = NetworkExtensionOperationFailure(
    NSError(
      domain: NSCocoaErrorDomain,
      code: CocoaError.Code.fileWriteNoPermission.rawValue,
      userInfo: [NSLocalizedDescriptionKey: "write denied"]
    )
  )
  #expect(cocoaPermission.disposition == .permissionDenied)

  let readWriteFailure = NetworkExtensionOperationFailure(
    NSError(
      domain: NEVPNErrorDomain,
      code: NEVPNError.configurationReadWriteFailed.rawValue,
      userInfo: [NSLocalizedDescriptionKey: "permission denied text is not policy"]
    )
  )
  #expect(readWriteFailure.domain == NEVPNErrorDomain)
  #expect(readWriteFailure.code == NEVPNError.configurationReadWriteFailed.rawValue)
  #expect(readWriteFailure.disposition == .unavailable)

  let unknownConfiguration = NetworkExtensionOperationFailure(
    NSError(
      domain: NEVPNErrorDomain,
      code: NEVPNError.configurationUnknown.rawValue,
      userInfo: [NSLocalizedDescriptionKey: "authorization wording is not a code"]
    )
  )
  #expect(unknownConfiguration.disposition == .unavailable)

  let unknown = NetworkExtensionOperationFailure(
    domain: "example.domain\nignored",
    code: 9_999,
    diagnostic: String(repeating: "x", count: 300) + "\npermission denied"
  )
  #expect(unknown.disposition == .unavailable)
  #expect(!unknown.domain.contains("\n"))
  #expect(unknown.domain.utf8.count <= NetworkExtensionOperationFailure.maximumDomainLength)
  #expect(
    unknown.diagnostic.utf8.count
      <= NetworkExtensionOperationFailure.maximumDiagnosticLength)

  let multiByte = NetworkExtensionOperationFailure(
    domain: String(repeating: "🧭", count: 100),
    code: 10_000,
    diagnostic: String(repeating: "👩🏽‍💻", count: 100)
  )
  #expect(multiByte.domain.utf8.count <= NetworkExtensionOperationFailure.maximumDomainLength)
  #expect(
    multiByte.diagnostic.utf8.count
      <= NetworkExtensionOperationFailure.maximumDiagnosticLength)
}
