import CFWSharedProtocol
import Foundation
import Security
import Testing

@testable import CFWProxyAgentCore

private enum JournalTestError: Error {
  case invalidIdentifier
}

private enum JournalDataOperation: Hashable {
  case load
  case save
  case remove
}

private final class MemoryJournalDataStore: JournalDataStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var data: Data?
  private var failures: [JournalDataOperation: JournalAuthenticationError] = [:]

  func load() throws(JournalAuthenticationError) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    if let error = failures[.load] {
      throw error
    }
    return data
  }

  func save(_ data: Data) throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let error = failures[.save] {
      throw error
    }
    self.data = data
  }

  func remove() throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let error = failures[.remove] {
      throw error
    }
    data = nil
  }

  func replace(with data: Data?) {
    lock.withLock {
      self.data = data
    }
  }

  func setFailure(
    _ error: JournalAuthenticationError?,
    for operation: JournalDataOperation
  ) {
    lock.withLock {
      failures[operation] = error
    }
  }
}

private func journalDescriptor() throws -> ConfigurationDescriptor {
  guard
    let installationID = UUID(
      uuidString: "22222222-2222-2222-2222-222222222222"
    )
  else {
    throw JournalTestError.invalidIdentifier
  }
  return try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: CredentialAudience(
      profileID: installationID,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: installationID,
    epoch: 1,
    generation: 7,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

private func ownershipJournal(
  phase: ProxyOwnershipJournalPhase = .applied
) throws -> ProxyOwnershipJournal {
  let applied: [SystemProxyField: ProxyPreferenceValue] = [
    .httpEnabled: .integer(1),
    .httpHost: .string("127.0.0.1"),
    .httpPort: .integer(7_890),
    .httpsEnabled: .integer(1),
    .httpsHost: .string("127.0.0.1"),
    .httpsPort: .integer(7_890),
    .socksEnabled: .integer(1),
    .socksHost: .string("127.0.0.1"),
    .socksPort: .integer(7_890),
    .proxyAutoConfigEnabled: .integer(0),
    .proxyAutoDiscoveryEnabled: .integer(0),
  ]
  let fields = try SystemProxyField.allCases.map { field in
    guard let appliedValue = applied[field] else {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    return OwnedSystemProxyField(
      field: field,
      originalValue: nil,
      appliedValue: appliedValue
    )
  }
  return try ProxyOwnershipJournal(
    phase: phase,
    configuration: journalDescriptor(),
    services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)]
  )
}

@Test func keychainOwnershipJournalRoundTripsAndRemovesAtomically() throws {
  let dataStore = MemoryJournalDataStore()
  let store = KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
  let journal = try ownershipJournal()

  try store.save(journal)

  #expect(try store.load() == journal)
  try store.remove()
  #expect(try store.load() == nil)
  try store.remove()
}

@Test func keychainOwnershipJournalRejectsNonCanonicalPayload() throws {
  let dataStore = MemoryJournalDataStore()
  let store = KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
  try store.save(ownershipJournal())
  let canonical = try #require(try dataStore.load())
  let object = try JSONSerialization.jsonObject(with: canonical)
  let nonCanonical = try JSONSerialization.data(
    withJSONObject: object,
    options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
  )
  dataStore.replace(with: nonCanonical)

  #expect(throws: ProxyOwnershipJournalError.nonCanonicalPayload) {
    try store.load()
  }
}

@Test func keychainOwnershipJournalRejectsMalformedAndOversizedValues() throws {
  let dataStore = MemoryJournalDataStore()
  let store = KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)

  dataStore.replace(with: Data("{}".utf8))
  #expect(throws: ProxyOwnershipJournalError.invalidJournal) {
    try store.load()
  }

  let oversized = Data(repeating: 0x41, count: 128 * 1_024 + 1)
  dataStore.replace(with: oversized)
  #expect(
    throws: ProxyOwnershipJournalError.journalTooLarge(
      actual: oversized.count,
      maximum: 128 * 1_024
    )
  ) {
    try store.load()
  }
}

@Test func failedAppliedUpdateRetainsPreparedRecoveryJournal() throws {
  let dataStore = MemoryJournalDataStore()
  let store = KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
  let prepared = try ownershipJournal(phase: .prepared)
  try store.save(prepared)
  let error = JournalAuthenticationError.keychainWriteFailed(errSecInteractionNotAllowed)
  dataStore.setFailure(error, for: .save)

  #expect(throws: ProxyOwnershipJournalError.authenticationUnavailable(error)) {
    try store.save(prepared.markingApplied())
  }

  dataStore.setFailure(nil, for: .save)
  #expect(try store.load() == prepared)
}

@Test func failedRemovalRetainsRecoveryJournalForRetry() throws {
  let dataStore = MemoryJournalDataStore()
  let store = KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
  let journal = try ownershipJournal()
  try store.save(journal)
  let error = JournalAuthenticationError.keychainWriteFailed(errSecInteractionNotAllowed)
  dataStore.setFailure(error, for: .remove)

  #expect(throws: ProxyOwnershipJournalError.authenticationUnavailable(error)) {
    try store.remove()
  }

  dataStore.setFailure(nil, for: .remove)
  #expect(try store.load() == journal)
  try store.remove()
  #expect(try store.load() == nil)
}

@Test func keychainReadFailureBlocksRecovery() throws {
  let dataStore = MemoryJournalDataStore()
  let store = KeychainProxyOwnershipJournalStore(testingDataStore: dataStore)
  try store.save(ownershipJournal())
  let error = JournalAuthenticationError.keychainReadFailed(errSecInteractionNotAllowed)
  dataStore.setFailure(error, for: .load)

  #expect(throws: ProxyOwnershipJournalError.authenticationUnavailable(error)) {
    try store.load()
  }
}
