import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// The journal's anchor: the system keychain query, an unavailable or missing
// anchor, and generation state no anchor vouches for.
@Test func systemDaemonAnchorQueryStaysInTheFileBasedSystemKeychain() {
  let identity = SystemKeychainAuthorityJournalAnchorStore.itemIdentity
  #expect(identity[kSecUseDataProtectionKeychain] == nil)
  #expect(identity[kSecAttrAccessGroup] == nil)
  #expect(identity[kSecAttrSynchronizable] == nil)
}

@Test func unavailableAnchorKeepsAuthorityRecoveringUntilAccessReturns() throws {
  try withTemporaryJournalDirectory { root in
    let anchor = InMemoryAuthorityJournalAnchorStore()
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: anchor)
    _ = try store.appendCommitted(enrollmentState())

    anchor.setUnavailableStatusForTesting(errSecNotAvailable)
    let unavailable = store.recover()
    #expect(unavailable.posture == .recovering(.restoreAnchorAccess))
    #expect(unavailable.committedState == nil)
    #expect(
      try GlobalAuthorityReducer.reconciled(from: unavailable).state
        == .recovering)

    anchor.setUnavailableStatusForTesting(nil)
    let restored = store.recover()
    #expect(restored.committedState == (try enrollmentState()))
    #expect(
      try GlobalAuthorityReducer.reconciled(from: restored).state == .off)
  }
}

@Test func missingAnchorAndDiskRollbackAlwaysQuarantine() throws {
  try withTemporaryJournalDirectory { root in
    let anchor = InMemoryAuthorityJournalAnchorStore()
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: anchor)
    _ = try store.appendCommitted(enrollmentState())
    let journalURL = root.appendingPathComponent(
      "authority.v2.00000000000000000001.journal")
    let headURL = root.appendingPathComponent(
      "authority.v2.00000000000000000001.head")
    let enrolledJournal = try Data(contentsOf: journalURL)
    let enrolledHead = try Data(contentsOf: headURL)

    _ = try store.appendCommitted(committedState(revision: 2, generation: 2))
    try enrolledJournal.write(to: journalURL)
    try enrolledHead.write(to: headURL)
    guard chmod(journalURL.path, 0o600) == 0,
      chmod(headURL.path, 0o600) == 0
    else { throw JournalFixtureError.setup }
    #expect(isQuarantined(store.recover(), reason: .anchorMismatch))

    anchor.replaceForTesting(nil)
    #expect(isQuarantined(store.recover(), reason: .anchorMissing))
  }
}

@Test func unanchoredGenerationStateCannotBeTreatedAsAFreshStore() throws {
  try withTemporaryJournalDirectory { root in
    let orphanedJournal = root.appendingPathComponent(
      "authority.v2.00000000000000000001.journal")
    try writeSecuredJournalFixture(Data(), to: orphanedJournal)

    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: InMemoryAuthorityJournalAnchorStore())
    #expect(
      isQuarantined(
        store.recover(), reason: .orphanedGenerationState))
    #expect(throws: AuthorityJournalValidationError.orphanedGenerationState) {
      try store.appendCommitted(enrollmentState())
    }
  }
}

@Test func malformedV2GenerationNamespaceIsQuarantined() throws {
  try withTemporaryJournalDirectory { root in
    let malformed = root.appendingPathComponent("authority.v2.latest.journal")
    try writeSecuredJournalFixture(Data(), to: malformed)

    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: InMemoryAuthorityJournalAnchorStore())
    #expect(
      isQuarantined(
        store.recover(), reason: .invalidGenerationEntry))
  }
}

@Test func nonemptyLegacyV1StateRequiresExplicitMigration() throws {
  try withTemporaryJournalDirectory { root in
    let legacy = root.appendingPathComponent("authority.journal")
    try Data("legacy-v1".utf8).write(to: legacy)
    guard chmod(legacy.path, 0o600) == 0 else {
      throw JournalFixtureError.setup
    }
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: InMemoryAuthorityJournalAnchorStore())
    #expect(
      isQuarantined(
        store.recover(), reason: .legacyStateRequiresMigration))
  }
}
