import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// The descriptor-relative journal store: its secure creation and reopening, its
// production path, and the symlinks, metadata and concurrent creators it
// rejects.
@Test func descriptorRelativeStoreRejectsModeSymlinkAndConcurrentProcessLock() throws {
  try withTemporaryJournalDirectory { root in
    guard chmod(root.path, 0o755) == 0 else { throw JournalFixtureError.setup }
    #expect(throws: AuthorityJournalStorageError.insecureDirectory) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: root.path, expectedOwnerUID: getuid())
    }
    guard chmod(root.path, 0o700) == 0 else { throw JournalFixtureError.setup }

    let first = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path, expectedOwnerUID: getuid())
    #expect(throws: AuthorityJournalStorageError.storeLocked) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: root.path, expectedOwnerUID: getuid())
    }
    _fixLifetime(first)

    let real = root.appendingPathComponent("real", isDirectory: true)
    try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false)
    guard chmod(real.path, 0o700) == 0 else { throw JournalFixtureError.setup }
    let link = root.appendingPathComponent("link", isDirectory: true)
    guard symlink(real.path, link.path) == 0 else { throw JournalFixtureError.setup }
    #expect(throws: AuthorityJournalStorageError.self) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: link.path, expectedOwnerUID: getuid())
    }
  }
}

@Test func descriptorRelativeStoreSecurelyCreatesAndReopensMissingLeaf() throws {
  try withTemporaryJournalDirectory { parent in
    let leaf = parent.appendingPathComponent("authority", isDirectory: true)
    let anchor = InMemoryAuthorityJournalAnchorStore()
    #expect(!FileManager.default.fileExists(atPath: leaf.path))

    var first: DescriptorRelativeAuthorityJournalStore? =
      try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: leaf.path,
        expectedOwnerUID: getuid(),
        anchorStore: anchor)
    let state = try enrollmentState()
    try first?.appendCommitted(state)

    var status = stat()
    guard lstat(leaf.path, &status) == 0 else { throw JournalFixtureError.setup }
    #expect((status.st_mode & S_IFMT) == S_IFDIR)
    #expect(status.st_uid == getuid())
    #expect((status.st_mode & 0o777) == 0o700)

    first = nil
    let reopened = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: leaf.path,
      expectedOwnerUID: getuid(),
      anchorStore: anchor)
    #expect(reopened.recover().committedState == state)
  }
}

@Test func productionJournalPathUsesADedicatedSystemOwnedLeaf() {
  #expect(
    DescriptorRelativeAuthorityJournalStore.productionRootPath
      == "/Library/Application Support/com.bill.clashformac.global-authority")
  #expect(
    !DescriptorRelativeAuthorityJournalStore.productionRootPath.contains(
      "/com.bill.clashformac/"))
}

@Test func descriptorRelativeStoreNeverCreatesMissingIntermediateDirectories() throws {
  try withTemporaryJournalDirectory { parent in
    let nestedLeaf =
      parent
      .appendingPathComponent("missing-parent", isDirectory: true)
      .appendingPathComponent("authority", isDirectory: true)
    #expect(throws: AuthorityJournalStorageError.self) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: nestedLeaf.path,
        expectedOwnerUID: getuid())
    }
    #expect(
      !FileManager.default.fileExists(
        atPath: parent.appendingPathComponent("missing-parent").path))
  }
}

@Test func concurrentRootCreatorEEXISTIsReopenedAndVerified() throws {
  try withTemporaryJournalDirectory { parent in
    let leaf = parent.appendingPathComponent("authority", isDirectory: true)
    var injected = false
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: leaf.path,
      expectedOwnerUID: getuid(),
      faultInjector: { point in
        guard point == .beforeStoreLeafCreation else { return }
        injected = true
        try FileManager.default.createDirectory(
          at: leaf, withIntermediateDirectories: false)
        guard chmod(leaf.path, 0o700) == 0 else { throw JournalFixtureError.setup }
      })

    #expect(injected)
    let state = try enrollmentState()
    try store.appendCommitted(state)
    #expect(store.recover().committedState == state)
  }
}

@Test func concurrentUntrustedLeafIsRejectedWithoutPermissionRepair() throws {
  try withTemporaryJournalDirectory { parent in
    let leaf = parent.appendingPathComponent("authority", isDirectory: true)
    #expect(throws: AuthorityJournalStorageError.insecureDirectory) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: leaf.path,
        expectedOwnerUID: getuid(),
        faultInjector: { point in
          guard point == .beforeStoreLeafCreation else { return }
          try FileManager.default.createDirectory(
            at: leaf, withIntermediateDirectories: false)
          guard chmod(leaf.path, 0o755) == 0 else {
            throw JournalFixtureError.setup
          }
        })
    }

    var status = stat()
    guard lstat(leaf.path, &status) == 0 else { throw JournalFixtureError.setup }
    #expect((status.st_mode & 0o7777) == 0o755)
  }
}

@Test func descriptorRelativeStoreRejectsUnsafeAncestorAndLeafMetadata() throws {
  try withTemporaryJournalDirectory { root in
    let unsafeAncestor = root.appendingPathComponent("unsafe", isDirectory: true)
    try FileManager.default.createDirectory(
      at: unsafeAncestor, withIntermediateDirectories: false)
    guard chmod(unsafeAncestor.path, 0o770) == 0 else {
      throw JournalFixtureError.setup
    }
    let descendant = unsafeAncestor.appendingPathComponent("authority", isDirectory: true)
    #expect(throws: AuthorityJournalStorageError.insecureDirectory) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: descendant.path,
        expectedOwnerUID: getuid())
    }

    let wrongMode = root.appendingPathComponent("wrong-mode", isDirectory: true)
    try FileManager.default.createDirectory(at: wrongMode, withIntermediateDirectories: false)
    guard chmod(wrongMode.path, 0o755) == 0 else { throw JournalFixtureError.setup }
    #expect(throws: AuthorityJournalStorageError.insecureDirectory) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: wrongMode.path,
        expectedOwnerUID: getuid())
    }

    let specialMode = root.appendingPathComponent("special-mode", isDirectory: true)
    try FileManager.default.createDirectory(at: specialMode, withIntermediateDirectories: false)
    guard chmod(specialMode.path, 0o1700) == 0 else { throw JournalFixtureError.setup }
    #expect(throws: AuthorityJournalStorageError.insecureDirectory) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: specialMode.path,
        expectedOwnerUID: getuid())
    }

    let wrongOwner = root.appendingPathComponent("wrong-owner", isDirectory: true)
    try FileManager.default.createDirectory(at: wrongOwner, withIntermediateDirectories: false)
    guard chmod(wrongOwner.path, 0o700) == 0 else { throw JournalFixtureError.setup }
    #expect(throws: AuthorityJournalStorageError.insecureDirectory) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: wrongOwner.path,
        expectedOwnerUID: getuid() &+ 1,
        allowedAncestorOwnerUIDs: [0, getuid()])
    }
  }
}

@Test func descriptorRelativeStoreRejectsAncestorAndLeafSymlinks() throws {
  try withTemporaryJournalDirectory { root in
    let realAncestor = root.appendingPathComponent("real", isDirectory: true)
    try FileManager.default.createDirectory(
      at: realAncestor, withIntermediateDirectories: false)
    guard chmod(realAncestor.path, 0o700) == 0 else { throw JournalFixtureError.setup }

    let ancestorLink = root.appendingPathComponent("ancestor-link", isDirectory: true)
    guard symlink(realAncestor.path, ancestorLink.path) == 0 else {
      throw JournalFixtureError.setup
    }
    #expect(throws: AuthorityJournalStorageError.self) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: ancestorLink.appendingPathComponent("authority").path,
        expectedOwnerUID: getuid())
    }

    let realLeaf = root.appendingPathComponent("real-leaf", isDirectory: true)
    try FileManager.default.createDirectory(at: realLeaf, withIntermediateDirectories: false)
    guard chmod(realLeaf.path, 0o700) == 0 else { throw JournalFixtureError.setup }
    let leafLink = root.appendingPathComponent("leaf-link", isDirectory: true)
    guard symlink(realLeaf.path, leafLink.path) == 0 else {
      throw JournalFixtureError.setup
    }
    #expect(throws: AuthorityJournalStorageError.self) {
      _ = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: leafLink.path,
        expectedOwnerUID: getuid())
    }
  }
}

@Test func concurrentMissingLeafCreationProducesOneLockedDurableStore() throws {
  try withTemporaryJournalDirectory { parent in
    let leaf = parent.appendingPathComponent("authority", isDirectory: true)
    let results = ConcurrentJournalStoreResults()

    DispatchQueue.concurrentPerform(iterations: 2) { _ in
      results.record(
        Result {
          try DescriptorRelativeAuthorityJournalStore(
            testingRootPath: leaf.path,
            expectedOwnerUID: getuid())
        })
    }

    #expect(results.stores.count == 1)
    #expect(results.errors.count == 1)
    #expect(results.errors.first as? AuthorityJournalStorageError == .storeLocked)

    let store = try #require(results.stores.first)
    let state = try enrollmentState()
    try store.appendCommitted(state)
    #expect(store.recover().committedState == state)
  }
}
