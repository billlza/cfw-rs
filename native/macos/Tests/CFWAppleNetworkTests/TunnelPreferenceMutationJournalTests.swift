import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Security
import Testing

@testable import CFWAppleNetwork

private final class MemoryTunnelJournalDataStore: VersionedJournalDataStoring,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var value: VersionedJournalDataRecord?
  private var loadFailure: JournalAuthenticationError?
  private var writeFailure: JournalAuthenticationError?

  func load() throws(JournalAuthenticationError) -> VersionedJournalDataRecord? {
    lock.lock()
    defer { lock.unlock() }
    if let loadFailure { throw loadFailure }
    return value
  }

  func create(
    _ record: VersionedJournalDataRecord
  ) throws(JournalAuthenticationError) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    if let writeFailure { throw writeFailure }
    guard value == nil else { return false }
    value = record
    return true
  }

  func compareExchange(
    expectedAccountToken: String,
    desired: VersionedJournalDataRecord
  ) throws(JournalAuthenticationError) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    if let writeFailure { throw writeFailure }
    guard value?.accountToken == expectedAccountToken else { return false }
    value = desired
    return true
  }

  func compareDelete(
    expectedAccountToken: String
  ) throws(JournalAuthenticationError) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    if let writeFailure { throw writeFailure }
    guard value?.accountToken == expectedAccountToken else { return false }
    value = nil
    return true
  }

  func replaceData(_ data: Data?) {
    lock.withLock {
      value = data.map {
        VersionedJournalDataRecord(
          accountToken: "canonical-journal-v2.genesis",
          data: $0
        )
      }
    }
  }
  func snapshot() -> Data? { lock.withLock { value?.data } }
  func failLoad(_ error: JournalAuthenticationError?) {
    lock.withLock { loadFailure = error }
  }
  func failWrite(_ error: JournalAuthenticationError?) {
    lock.withLock { writeFailure = error }
  }
}

private func journalDescriptor(generation: UInt64) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
    epoch: 1,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

private func journalValues(
  generation: UInt64,
  description: String
) throws -> ManagedTunnelPreferenceValues {
  ManagedTunnelPreferenceValues(
    descriptor: try journalDescriptor(generation: generation),
    providerBundleIdentifier: "com.bill.clashformac.packet-tunnel",
    serverAddress: "Clash for Mac",
    isEnabled: true,
    localizedDescription: description
  )
}

private func journalReceipt(
  operationID: UUID = UUID(),
  generation: UInt64 = 2,
  createdManager: Bool = false
) throws -> TunnelPreferenceMutationReceipt {
  let prior =
    createdManager
    ? nil
    : try journalValues(generation: generation - 1, description: "prior")
  return TunnelPreferenceMutationReceipt(
    operationID: operationID,
    createdManager: createdManager,
    priorValues: prior,
    writtenValues: try journalValues(generation: generation, description: "written")
  )
}

private func preparedState(
  _ receipt: TunnelPreferenceMutationReceipt,
  revision: UInt64 = 1,
  stageID: UUID = UUID(),
  operation: PreferenceMutationOperation = .originalSave
) -> TunnelPreferenceMutationState {
  TunnelPreferenceMutationState(
    revision: revision,
    receipt: receipt,
    stageID: stageID,
    operation: operation,
    phase: .prepared,
    bootSessionID: nil,
    callbackOutcome: nil
  )
}

@Suite(.serialized)
struct TunnelPreferenceMutationJournalTests {
  @Test func canonicalStateRoundTripsAndEveryWriteUsesExactCAS() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let state = preparedState(try journalReceipt())

    #expect(try store.create(state))
    #expect(!(try store.create(state)))
    #expect(try store.load() == state)
    let canonicalJSON = try #require(
      dataStore.snapshot().flatMap { String(data: $0, encoding: .utf8) }
    )
    #expect(canonicalJSON.contains("\"isOnDemandEnabled\":false"))
    #expect(canonicalJSON.contains("\"hasOnDemandRules\":false"))

    let submitted = state.submitted(in: "boot-a")
    #expect(try store.compareExchange(expected: state, desired: submitted))
    #expect(!(try store.compareDelete(expected: state)))
    #expect(try store.compareDelete(expected: submitted))
    #expect(try store.load() == nil)
  }

  @Test func sameBootSubmittedRequestQuarantinesEveryJournalUntilLateTerminalCallback() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let receipt = try journalReceipt()
    let firstHost = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
    let secondHost = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
    let stageID = try firstHost.begin(receipt)
    try firstHost.markSubmitted(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .originalSave
    )

    #expect(throws: AppleNetworkError.self) {
      _ = try secondHost.pendingReceipt(
        expectedDescriptor: receipt.writtenValues.descriptor,
        requireSettledCurrentProcessMutation: true
      )
    }
    #expect(throws: AppleNetworkError.self) {
      try secondHost.clear(operationID: receipt.operationID)
    }

    #expect(
      try firstHost.recordCallback(
        operationID: receipt.operationID,
        stageID: stageID,
        operation: .originalSave,
        outcome: .succeeded
      ) == .recorded)
    #expect(
      try secondHost.pendingReceipt(
        expectedDescriptor: receipt.writtenValues.descriptor,
        requireSettledCurrentProcessMutation: true
      ) == receipt
    )
    try secondHost.clear(operationID: receipt.operationID)
  }

  @Test func changedBootMayReconcileSubmittedStateFromFreshOSReality() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let receipt = try journalReceipt()
    let oldBoot = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
    let stageID = try oldBoot.begin(receipt)
    try oldBoot.markSubmitted(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .originalSave
    )

    let newBoot = try PreferenceMutationJournal(store: store, bootSessionID: "boot-b")
    #expect(
      try newBoot.pendingReceipt(
        expectedDescriptor: receipt.writtenValues.descriptor,
        requireSettledCurrentProcessMutation: true
      ) == receipt
    )
  }

  @Test func callbackSuccessAndFailureAreBothDurableTerminalStates() throws {
    for outcome in [
      PreferenceSaveCallbackOutcome.succeeded,
      .failed(
        NetworkExtensionOperationFailure(
          domain: NEVPNErrorDomain,
          code: NEVPNError.configurationReadWriteFailed.rawValue,
          diagnostic: "injected")),
    ] {
      let dataStore = MemoryTunnelJournalDataStore()
      let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
      let receipt = try journalReceipt()
      let journal = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
      let stageID = try journal.begin(receipt)
      try journal.markSubmitted(
        operationID: receipt.operationID,
        stageID: stageID,
        operation: .originalSave
      )
      #expect(
        try journal.recordCallback(
          operationID: receipt.operationID,
          stageID: stageID,
          operation: .originalSave,
          outcome: outcome
        ) == .recorded)

      let restarted = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
      let state = try restarted.currentState(operationID: receipt.operationID)
      #expect(state.phase == .terminal)
      #expect(state.callbackOutcome == outcome)
      #expect(state.revision == 3)
    }
  }

  @Test func twoJournalInterleavingCannotOverwriteOrDeleteANewerRevision() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let receiptA = try journalReceipt(generation: 2)
    let receiptB = try journalReceipt(generation: 3)
    let journalA = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
    let journalB = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")

    let stageA = try journalA.begin(receiptA)
    let stalePrepared = try #require(try store.load())
    #expect(throws: AppleNetworkError.preferenceMutationUncertain) {
      _ = try journalB.begin(receiptB)
    }
    try journalA.markSubmitted(
      operationID: receiptA.operationID,
      stageID: stageA,
      operation: .originalSave
    )
    #expect(!(try store.compareDelete(expected: stalePrepared)))

    #expect(
      try journalA.recordCallback(
        operationID: receiptA.operationID,
        stageID: stageA,
        operation: .originalSave,
        outcome: .succeeded
      ) == .recorded)
    let staleTerminal = try #require(try store.load())
    try journalA.clear(operationID: receiptA.operationID)
    let stageB = try journalB.begin(receiptB)
    #expect(!(try store.compareDelete(expected: staleTerminal)))

    #expect(
      try journalA.recordCallback(
        operationID: receiptA.operationID,
        stageID: stageA,
        operation: .originalSave,
        outcome: .succeeded
      ) == .obsolete)
    #expect(try journalB.currentState(operationID: receiptB.operationID).stageID == stageB)
  }

  @Test func originalSaveAndBothCompensationMutationsPersistAllPhases() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let receipt = try journalReceipt()
    let journal = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")
    let originalStage = try journal.begin(receipt)
    try journal.markSubmitted(
      operationID: receipt.operationID,
      stageID: originalStage,
      operation: .originalSave
    )
    #expect(
      try journal.recordCallback(
        operationID: receipt.operationID,
        stageID: originalStage,
        operation: .originalSave,
        outcome: .succeeded
      ) == .recorded)

    let saveStage = try journal.prepareCompensation(
      operationID: receipt.operationID,
      operation: .compensationSave
    )
    #expect(try journal.currentState(operationID: receipt.operationID).phase == .prepared)
    try journal.markSubmitted(
      operationID: receipt.operationID,
      stageID: saveStage,
      operation: .compensationSave
    )
    #expect(
      try journal.recordCallback(
        operationID: receipt.operationID,
        stageID: saveStage,
        operation: .compensationSave,
        outcome: .failed(
          NetworkExtensionOperationFailure(
            domain: NEVPNErrorDomain,
            code: NEVPNError.configurationReadWriteFailed.rawValue,
            diagnostic: "save-failed"))
      ) == .recorded)

    let removeStage = try journal.prepareCompensation(
      operationID: receipt.operationID,
      operation: .compensationRemove
    )
    try journal.markSubmitted(
      operationID: receipt.operationID,
      stageID: removeStage,
      operation: .compensationRemove
    )
    #expect(
      try journal.recordCallback(
        operationID: receipt.operationID,
        stageID: removeStage,
        operation: .compensationRemove,
        outcome: .succeeded
      ) == .recorded)
    let terminal = try journal.currentState(operationID: receipt.operationID)
    #expect(terminal.operation == .compensationRemove)
    #expect(terminal.phase == .terminal)
    #expect(terminal.callbackOutcome == .succeeded)
  }

  @Test func nonCanonicalAndStructurallyInvalidStatesFailClosed() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let state = preparedState(try journalReceipt())
    #expect(try store.create(state))
    var nonCanonical = try #require(dataStore.snapshot())
    nonCanonical.append(0x20)
    dataStore.replaceData(nonCanonical)
    #expect(throws: TunnelPreferenceMutationJournalError.nonCanonicalPayload) {
      _ = try store.load()
    }

    dataStore.replaceData(nil)
    let invalid = preparedState(try journalReceipt(), revision: 0)
    #expect(throws: TunnelPreferenceMutationJournalError.invalidJournal) {
      _ = try store.create(invalid)
    }

    dataStore.replaceData(Data(repeating: 0x20, count: 64 * 1_024 + 1))
    #expect(throws: TunnelPreferenceMutationJournalError.self) {
      _ = try store.load()
    }
  }

  @Test func readAndCASFailuresNeverProjectSuccess() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let receipt = try journalReceipt()
    let journal = try PreferenceMutationJournal(store: store, bootSessionID: "boot-a")

    dataStore.failWrite(.keychainWriteFailed(errSecInteractionNotAllowed))
    #expect(throws: AppleNetworkError.self) {
      _ = try journal.begin(receipt)
    }
    dataStore.failWrite(nil)
    let stageID = try journal.begin(receipt)

    dataStore.failLoad(.keychainReadFailed(errSecInteractionNotAllowed))
    #expect(throws: AppleNetworkError.self) {
      _ = try journal.pendingDescriptor()
    }
    dataStore.failLoad(nil)

    dataStore.failWrite(.keychainWriteFailed(errSecInteractionNotAllowed))
    #expect(throws: AppleNetworkError.self) {
      try journal.markSubmitted(
        operationID: receipt.operationID,
        stageID: stageID,
        operation: .originalSave
      )
    }
    dataStore.failWrite(nil)
    #expect(try journal.currentState(operationID: receipt.operationID).phase == .prepared)
  }

  @Test func storeRejectsRevisionJumpsBeforeTouchingDurableBytes() throws {
    let dataStore = MemoryTunnelJournalDataStore()
    let store = KeychainTunnelPreferenceMutationJournalStore(testingDataStore: dataStore)
    let state = preparedState(try journalReceipt())
    #expect(try store.create(state))
    let jumped = preparedState(
      state.receipt,
      revision: state.revision + 2,
      stageID: state.stageID
    )
    #expect(throws: TunnelPreferenceMutationJournalError.invalidJournal) {
      _ = try store.compareExchange(expected: state, desired: jumped)
    }
    #expect(try store.load() == state)
  }
}
