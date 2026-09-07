import CFWSharedProtocol
import CryptoKit
import Darwin
import Foundation

enum PreferenceMutationCallbackRecordDisposition: Equatable, Sendable {
  case recorded
  case obsolete
}

enum PreferenceSaveCallbackOutcome: Codable, Equatable, Sendable {
  case succeeded
  case failed(NetworkExtensionOperationFailure)

  private enum CodingKeys: String, CodingKey {
    case failure
    case kind
  }

  private enum Kind: String, Codable {
    case failed
    case succeeded
  }

  init(from decoder: any Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    switch try values.decode(Kind.self, forKey: .kind) {
    case .succeeded:
      guard !values.contains(.failure) else {
        throw DecodingError.dataCorruptedError(
          forKey: .failure,
          in: values,
          debugDescription: "A successful callback cannot contain a failure."
        )
      }
      self = .succeeded
    case .failed:
      self = .failed(
        try values.decode(NetworkExtensionOperationFailure.self, forKey: .failure)
      )
    }
  }

  func encode(to encoder: any Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .succeeded:
      try values.encode(Kind.succeeded, forKey: .kind)
    case .failed(let failure):
      try values.encode(Kind.failed, forKey: .kind)
      try values.encode(failure, forKey: .failure)
    }
  }
}

enum PreferenceMutationOperation: String, Codable, Equatable, Sendable {
  case compensationRemove = "compensation_remove"
  case compensationSave = "compensation_save"
  case originalSave = "original_save"
}

enum PreferenceMutationPhase: String, Codable, Equatable, Sendable {
  case prepared
  case submitted
  case terminal
}

struct TunnelPreferenceMutationState: Codable, Equatable, Sendable {
  let revision: UInt64
  let receipt: TunnelPreferenceMutationReceipt
  let stageID: UUID
  let operation: PreferenceMutationOperation
  let phase: PreferenceMutationPhase
  let bootSessionID: String?
  let callbackOutcome: PreferenceSaveCallbackOutcome?

  var isStructurallyValid: Bool {
    guard revision > 0, receipt.isStructurallyValid else { return false }
    switch phase {
    case .prepared:
      return bootSessionID == nil && callbackOutcome == nil
    case .submitted:
      return bootSessionID?.isEmpty == false && callbackOutcome == nil
    case .terminal:
      return bootSessionID?.isEmpty == false && callbackOutcome != nil
    }
  }

  func submitted(in bootSessionID: String) -> Self {
    Self(
      revision: revision + 1,
      receipt: receipt,
      stageID: stageID,
      operation: operation,
      phase: .submitted,
      bootSessionID: bootSessionID,
      callbackOutcome: nil
    )
  }

  func terminated(with outcome: PreferenceSaveCallbackOutcome) -> Self {
    Self(
      revision: revision + 1,
      receipt: receipt,
      stageID: stageID,
      operation: operation,
      phase: .terminal,
      bootSessionID: bootSessionID,
      callbackOutcome: outcome
    )
  }
}

enum TunnelPreferenceMutationJournalError: Error, Equatable, Sendable {
  case authenticationUnavailable(JournalAuthenticationError)
  case bootSessionUnavailable(Int32)
  case invalidJournal
  case nonCanonicalPayload
  case journalTooLarge(actual: Int, maximum: Int)
}

extension TunnelPreferenceMutationJournalError: LocalizedError {
  var errorDescription: String? {
    switch self {
    case .authenticationUnavailable(let error):
      "Tunnel preference mutation journal is unavailable: \(error.localizedDescription)"
    case .bootSessionUnavailable(let code):
      "The Host boot-session identity is unavailable with errno \(code)."
    case .invalidJournal:
      "Tunnel preference mutation journal is invalid."
    case .nonCanonicalPayload:
      "Tunnel preference mutation journal is not canonical."
    case .journalTooLarge(let actual, let maximum):
      "Tunnel preference mutation journal has \(actual) bytes; maximum is \(maximum)."
    }
  }
}

protocol TunnelPreferenceMutationJournalStoring: Sendable {
  func load() throws -> TunnelPreferenceMutationState?
  func create(_ state: TunnelPreferenceMutationState) throws -> Bool
  func compareExchange(
    expected: TunnelPreferenceMutationState,
    desired: TunnelPreferenceMutationState
  ) throws -> Bool
  func compareDelete(expected: TunnelPreferenceMutationState) throws -> Bool
}

/// One authoritative Data Protection Keychain item stores the complete bounded
/// state machine. Every transition is revision-bound to the exact canonical bytes
/// read from the item; no process-local cache can overwrite or delete a newer WAL.
struct KeychainTunnelPreferenceMutationJournalStore:
  TunnelPreferenceMutationJournalStoring
{
  private struct Payload: Codable, Equatable, Sendable {
    let schemaVersion: UInt16
    let state: TunnelPreferenceMutationState

    init(state: TunnelPreferenceMutationState) {
      schemaVersion = 2
      self.state = state
    }

    enum CodingKeys: String, CodingKey {
      case schemaVersion = "schema_version"
      case state
    }
  }

  private static let maximumBytes = 64 * 1_024
  private static let genesisAccountToken = "canonical-journal-v2.genesis"
  private static let revisionAccountPrefix = "canonical-journal-v2."
  private let dataStore: any VersionedJournalDataStoring

  init(keychainAccessGroup: String) throws {
    do {
      dataStore = try KeychainVersionedJournalDataStore(
        keychainAccessGroup: keychainAccessGroup,
        service: "com.bill.clashformac.tunnel-preference-mutation",
        label: "Clash for Mac tunnel preference mutation journal",
        accountTokenPrefix: Self.revisionAccountPrefix,
        maximumDataBytes: Self.maximumBytes
      )
    } catch {
      throw TunnelPreferenceMutationJournalError.authenticationUnavailable(error)
    }
  }

  init(testingDataStore: any VersionedJournalDataStoring) {
    dataStore = testingDataStore
  }

  func load() throws -> TunnelPreferenceMutationState? {
    let record: VersionedJournalDataRecord?
    do {
      record = try dataStore.load()
    } catch {
      throw TunnelPreferenceMutationJournalError.authenticationUnavailable(error)
    }
    guard let record else { return nil }
    let state = try Self.decode(record.data)
    guard record.accountToken == Self.accountToken(for: state, data: record.data) else {
      throw TunnelPreferenceMutationJournalError.nonCanonicalPayload
    }
    return state
  }

  func create(_ state: TunnelPreferenceMutationState) throws -> Bool {
    guard state.revision == 1 else {
      throw TunnelPreferenceMutationJournalError.invalidJournal
    }
    let data = try Self.encode(state)
    let record = VersionedJournalDataRecord(
      accountToken: Self.accountToken(for: state, data: data),
      data: data
    )
    do {
      return try dataStore.create(record)
    } catch {
      throw TunnelPreferenceMutationJournalError.authenticationUnavailable(error)
    }
  }

  func compareExchange(
    expected: TunnelPreferenceMutationState,
    desired: TunnelPreferenceMutationState
  ) throws -> Bool {
    guard desired.revision == expected.revision + 1 else {
      throw TunnelPreferenceMutationJournalError.invalidJournal
    }
    let expectedData = try Self.encode(expected)
    let desiredData = try Self.encode(desired)
    let expectedToken = Self.accountToken(for: expected, data: expectedData)
    let desiredRecord = VersionedJournalDataRecord(
      accountToken: Self.accountToken(for: desired, data: desiredData),
      data: desiredData
    )
    do {
      return try dataStore.compareExchange(
        expectedAccountToken: expectedToken,
        desired: desiredRecord
      )
    } catch {
      throw TunnelPreferenceMutationJournalError.authenticationUnavailable(error)
    }
  }

  func compareDelete(expected: TunnelPreferenceMutationState) throws -> Bool {
    let expectedData = try Self.encode(expected)
    let expectedToken = Self.accountToken(for: expected, data: expectedData)
    do {
      return try dataStore.compareDelete(expectedAccountToken: expectedToken)
    } catch {
      throw TunnelPreferenceMutationJournalError.authenticationUnavailable(error)
    }
  }

  private static func decode(_ data: Data) throws -> TunnelPreferenceMutationState {
    guard !data.isEmpty else {
      throw TunnelPreferenceMutationJournalError.invalidJournal
    }
    try checkSize(data)
    let payload: Payload
    do {
      payload = try JSONDecoder().decode(Payload.self, from: data)
    } catch {
      throw TunnelPreferenceMutationJournalError.invalidJournal
    }
    guard payload.schemaVersion == 2,
      payload.state.isStructurallyValid,
      try canonicalData(payload) == data
    else {
      throw TunnelPreferenceMutationJournalError.nonCanonicalPayload
    }
    return payload.state
  }

  private static func encode(_ state: TunnelPreferenceMutationState) throws -> Data {
    guard state.isStructurallyValid else {
      throw TunnelPreferenceMutationJournalError.invalidJournal
    }
    let data = try canonicalData(Payload(state: state))
    try checkSize(data)
    return data
  }

  private static func checkSize(_ data: Data) throws {
    guard data.count <= maximumBytes else {
      throw TunnelPreferenceMutationJournalError.journalTooLarge(
        actual: data.count,
        maximum: maximumBytes
      )
    }
  }

  private static func canonicalData(_ payload: Payload) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(payload)
  }

  private static func accountToken(
    for state: TunnelPreferenceMutationState,
    data: Data
  ) -> String {
    guard state.revision > 1 else { return genesisAccountToken }
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return revisionAccountPrefix + digest
  }
}

/// Durable WAL coordinator. `store.load()` is performed for every operation and
/// every transition uses exact compare-and-swap; the object intentionally has no
/// cached receipt or callback authority.
final class PreferenceMutationJournal: @unchecked Sendable {
  private let store: any TunnelPreferenceMutationJournalStoring
  private let bootSessionID: String

  init(
    store: any TunnelPreferenceMutationJournalStoring,
    bootSessionID: String? = nil
  ) throws {
    self.store = store
    self.bootSessionID = try bootSessionID ?? Self.currentBootSessionID()
    guard !self.bootSessionID.isEmpty else {
      throw TunnelPreferenceMutationJournalError.invalidJournal
    }
    _ = try store.load()
  }

  @discardableResult
  func begin(_ receipt: TunnelPreferenceMutationReceipt) throws -> UUID {
    let stageID = UUID()
    let state = TunnelPreferenceMutationState(
      revision: 1,
      receipt: receipt,
      stageID: stageID,
      operation: .originalSave,
      phase: .prepared,
      bootSessionID: nil,
      callbackOutcome: nil
    )
    do {
      guard try store.create(state) else {
        throw AppleNetworkError.preferenceMutationUncertain
      }
    } catch let error as AppleNetworkError {
      throw error
    } catch {
      throw journalUnavailable(error)
    }
    return stageID
  }

  func prepareCompensation(
    operationID: UUID,
    operation: PreferenceMutationOperation
  ) throws -> UUID {
    precondition(operation != .originalSave)
    let current = try requiredState(operationID: operationID)
    if current.operation == operation, current.phase == .prepared {
      return current.stageID
    }
    try requireNoSameBootPendingSubmission(current)
    let desired = TunnelPreferenceMutationState(
      revision: current.revision + 1,
      receipt: current.receipt,
      stageID: UUID(),
      operation: operation,
      phase: .prepared,
      bootSessionID: nil,
      callbackOutcome: nil
    )
    do {
      guard try store.compareExchange(expected: current, desired: desired) else {
        throw AppleNetworkError.preferenceMutationUncertain
      }
    } catch let error as AppleNetworkError {
      throw error
    } catch {
      throw journalUnavailable(error)
    }
    return desired.stageID
  }

  func markSubmitted(
    operationID: UUID,
    stageID: UUID,
    operation: PreferenceMutationOperation
  ) throws {
    let current = try requiredState(
      operationID: operationID,
      stageID: stageID,
      operation: operation
    )
    guard current.phase == .prepared else {
      throw AppleNetworkError.preferenceMutationUncertain
    }
    let desired = current.submitted(in: bootSessionID)
    do {
      guard try store.compareExchange(expected: current, desired: desired) else {
        throw AppleNetworkError.preferenceMutationUncertain
      }
    } catch let error as AppleNetworkError {
      throw error
    } catch {
      throw journalUnavailable(error)
    }
  }

  func recordCallback(
    operationID: UUID,
    stageID: UUID,
    operation: PreferenceMutationOperation,
    outcome: PreferenceSaveCallbackOutcome
  ) throws -> PreferenceMutationCallbackRecordDisposition {
    guard let current = try loadState() else { return .obsolete }
    guard current.receipt.operationID == operationID,
      current.stageID == stageID,
      current.operation == operation
    else {
      return .obsolete
    }
    if current.phase == .terminal {
      guard current.callbackOutcome == outcome else {
        throw AppleNetworkError.preferenceMutationUncertain
      }
      return .recorded
    }
    guard current.phase == .submitted,
      current.bootSessionID == bootSessionID
    else {
      throw AppleNetworkError.preferenceMutationUncertain
    }
    let desired = current.terminated(with: outcome)
    do {
      if try store.compareExchange(expected: current, desired: desired) { return .recorded }
      guard let reread = try store.load() else { return .obsolete }
      if reread.receipt.operationID != operationID
        || reread.stageID != stageID
        || reread.operation != operation
      {
        return .obsolete
      }
      guard reread.phase == .terminal, reread.callbackOutcome == outcome else {
        throw AppleNetworkError.preferenceMutationUncertain
      }
      return .recorded
    } catch let error as AppleNetworkError {
      throw error
    } catch {
      throw journalUnavailable(error)
    }
  }

  func abandonUnsubmitted(
    operationID: UUID,
    stageID: UUID
  ) throws {
    let current = try requiredState(
      operationID: operationID,
      stageID: stageID,
      operation: .originalSave
    )
    guard current.phase == .prepared else {
      throw AppleNetworkError.preferenceMutationUncertain
    }
    try compareDelete(current)
  }

  func pendingReceipt(
    expectedDescriptor: ConfigurationDescriptor,
    requireSettledCurrentProcessMutation _: Bool
  ) throws -> TunnelPreferenceMutationReceipt? {
    guard let current = try loadState() else { return nil }
    guard current.receipt.writtenValues.descriptor == expectedDescriptor else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "Preference reconciliation does not match the durable generation."
      )
    }
    try requireNoSameBootPendingSubmission(current)
    return current.receipt
  }

  func pendingDescriptor() throws -> ConfigurationDescriptor? {
    try loadState()?.receipt.writtenValues.descriptor
  }

  func currentState(operationID: UUID) throws -> TunnelPreferenceMutationState {
    try requiredState(operationID: operationID)
  }

  func clear(operationID: UUID) throws {
    let current = try requiredState(operationID: operationID)
    try requireNoSameBootPendingSubmission(current)
    try compareDelete(current)
  }

  private func requiredState(
    operationID: UUID,
    stageID: UUID? = nil,
    operation: PreferenceMutationOperation? = nil
  ) throws -> TunnelPreferenceMutationState {
    guard let current = try loadState(), current.receipt.operationID == operationID else {
      throw AppleNetworkError.preferenceMutationUncertain
    }
    guard stageID == nil || current.stageID == stageID,
      operation == nil || current.operation == operation
    else {
      throw AppleNetworkError.preferenceMutationUncertain
    }
    return current
  }

  private func loadState() throws -> TunnelPreferenceMutationState? {
    do {
      return try store.load()
    } catch {
      throw journalUnavailable(error)
    }
  }

  private func compareDelete(_ current: TunnelPreferenceMutationState) throws {
    do {
      guard try store.compareDelete(expected: current) else {
        throw AppleNetworkError.preferenceMutationUncertain
      }
    } catch let error as AppleNetworkError {
      throw error
    } catch {
      throw journalUnavailable(error)
    }
  }

  private func requireNoSameBootPendingSubmission(
    _ current: TunnelPreferenceMutationState
  ) throws {
    if current.phase == .submitted, current.bootSessionID == bootSessionID {
      throw AppleNetworkError.cleanupUnproven(
        "A submitted Network Extension preference request has no terminal callback in this boot session."
      )
    }
  }

  private func journalUnavailable(_ error: Error) -> AppleNetworkError {
    AppleNetworkError.preferenceMutationJournalUnavailable(
      Self.boundedDiagnostic(error.localizedDescription)
    )
  }

  private static func currentBootSessionID() throws -> String {
    var bootTime = timeval()
    var size = MemoryLayout<timeval>.size
    guard sysctlbyname("kern.boottime", &bootTime, &size, nil, 0) == 0,
      size == MemoryLayout<timeval>.size
    else {
      throw TunnelPreferenceMutationJournalError.bootSessionUnavailable(errno)
    }
    return "\(bootTime.tv_sec).\(bootTime.tv_usec)"
  }

  private static func boundedDiagnostic(_ value: String) -> String {
    var result = ""
    var byteCount = 0
    for scalar in value.unicodeScalars {
      let output: Unicode.Scalar =
        CharacterSet.controlCharacters.contains(scalar) ? " " : scalar
      let bytes = String(output).utf8.count
      guard byteCount + bytes <= 256 else { break }
      result.unicodeScalars.append(output)
      byteCount += bytes
    }
    return result
  }
}
