import Foundation
import Security
import Testing

@testable import CFWSharedProtocol

private func versionedStore() throws -> KeychainVersionedJournalDataStore {
  try KeychainVersionedJournalDataStore(
    keychainAccessGroup: "TESTTEAM.com.bill.clashformac.tests",
    service: "com.bill.clashformac.tests.versioned-journal",
    label: "Versioned journal query contract",
    accountTokenPrefix: "canonical-journal-v2.",
    maximumDataBytes: 64 * 1_024
  )
}

@Test func versionedJournalComparisonQueryUsesOnlyTheSearchableAccountToken() throws {
  let query = try versionedStore().exactQuery(
    accountToken: "canonical-journal-v2.genesis"
  )
  #expect(query[kSecAttrAccount] as? String == "canonical-journal-v2.genesis")
  #expect(query[kSecValueData] == nil)
  #expect(query[kSecClass] as? String == kSecClassGenericPassword as String)
}

@Test func versionedJournalRejectsInvalidTokensBeforeCallingSecurityFramework() throws {
  let store = try versionedStore()
  #expect(throws: JournalAuthenticationError.invalidIdentifier) {
    _ = try store.compareDelete(expectedAccountToken: "wrong-prefix.genesis")
  }
  #expect(throws: JournalAuthenticationError.invalidIdentifier) {
    _ = try store.compareExchange(
      expectedAccountToken: "canonical-journal-v2.genesis",
      desired: VersionedJournalDataRecord(
        accountToken: "canonical-journal-v2.not-a-digest",
        data: Data([1])
      )
    )
  }
  #expect(throws: JournalAuthenticationError.invalidIdentifier) {
    _ = try store.create(
      VersionedJournalDataRecord(
        accountToken: "canonical-journal-v2." + String(repeating: "a", count: 64),
        data: Data([1])
      )
    )
  }
  #expect(throws: JournalAuthenticationError.invalidIdentifier) {
    _ = try store.compareExchange(
      expectedAccountToken: "canonical-journal-v2.genesis",
      desired: VersionedJournalDataRecord(
        accountToken: "canonical-journal-v2.genesis",
        data: Data([1])
      )
    )
  }
}

@Test func versionedJournalLoadValidationAcceptsGenesisAndDigestVersions() throws {
  let store = try versionedStore()
  #expect(
    store.isValidRecord(
      VersionedJournalDataRecord(
        accountToken: "canonical-journal-v2.genesis",
        data: Data([1])
      )))
  #expect(
    store.isValidRecord(
      VersionedJournalDataRecord(
        accountToken: "canonical-journal-v2." + String(repeating: "a", count: 64),
        data: Data([1])
      )))
}
