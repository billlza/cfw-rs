import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

// Tunnel preference writes: an uncertain write blocks the next generation until
// it is reconciled, live callbacks fail closed without their journal, timed-out
// waits ignore late callbacks, and NSErrors are classified by domain and code.
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
