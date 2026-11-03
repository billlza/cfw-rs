import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// Crash boundaries: every anchor commit, compaction commit and cleanup crash
// point recovers, and cleanup failures stay observable and safe.
@Test func everyAnchorCommitCrashBoundaryRecoversDeterministically() throws {
  let cases: [(AuthorityJournalFaultPoint, UInt64)] = [
    (.anchorPendingSynchronized, 1),
    (.recordSynchronized, 2),
    (.temporaryHeadSynchronized, 2),
    (.headRenamed, 2),
    (.anchorCommittedSynchronized, 2),
  ]
  for (point, expectedRevision) in cases {
    try withTemporaryJournalDirectory { root in
      let anchor = InMemoryAuthorityJournalAnchorStore()
      var failAt: AuthorityJournalFaultPoint?
      let store = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: root.path,
        expectedOwnerUID: getuid(),
        anchorStore: anchor,
        faultInjector: { observed in
          if observed == failAt { throw JournalFixtureError.injected }
        })
      _ = try store.appendCommitted(enrollmentState())
      failAt = point
      #expect(throws: JournalFixtureError.injected) {
        try store.appendCommitted(committedState(revision: 2, generation: 2))
      }
      failAt = nil
      let recovery = store.recover()
      #expect(recovery.committedState?.revision == expectedRevision)
      #expect(recovery.posture == .recovering(.verifyOff))
      #expect(try anchor.load()?.pending == nil)
    }
  }
}

@Test func everyCompactionCommitCrashBoundaryRecoversAndRetries() throws {
  let points: [AuthorityJournalFaultPoint] = [
    .anchorPendingSynchronized,
    .recordSynchronized,
    .temporaryHeadSynchronized,
    .headRenamed,
    .anchorCommittedSynchronized,
  ]
  for point in points {
    try withTemporaryJournalDirectory { root in
      let anchor = InMemoryAuthorityJournalAnchorStore()
      var failAt: AuthorityJournalFaultPoint?
      let store = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: root.path,
        expectedOwnerUID: getuid(),
        anchorStore: anchor,
        recordCapacity: 10,
        faultInjector: { observed in
          if observed == failAt { throw JournalFixtureError.injected }
        })
      _ = try store.appendCommitted(enrollmentState())
      _ = try store.appendCommitted(committedState(revision: 2))
      _ = try store.appendCommitted(committedState(revision: 3))

      failAt = point
      #expect(throws: JournalFixtureError.injected) {
        try store.appendCommitted(
          committedState(
            revision: 4, state: .preparing, transition: .prepare))
      }
      failAt = nil

      let recoveredCheckpoint = store.recover()
      #expect(recoveredCheckpoint.committedState?.revision == 3)
      #expect(try anchor.load()?.pending == nil)
      _ = try store.appendCommitted(
        committedState(
          revision: 4, state: .preparing, transition: .prepare))
      #expect(store.recover().committedState?.revision == 4)
      #expect(try journalGenerations(in: root) == [1, 2])
    }
  }
}

@Test func everyCompactionCleanupCrashBoundaryRecoversAndRetries() throws {
  let points: [AuthorityJournalFaultPoint] = [
    .generationCleanupStarted,
    .generationEntryUnlinked,
    .generationCleanupDirectorySynchronized,
  ]
  for point in points {
    try withTemporaryJournalDirectory { root in
      let anchor = InMemoryAuthorityJournalAnchorStore()
      var failAt: AuthorityJournalFaultPoint?
      let store = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: root.path,
        expectedOwnerUID: getuid(),
        anchorStore: anchor,
        recordCapacity: 10,
        faultInjector: { observed in
          if observed == failAt { throw JournalFixtureError.injected }
        })
      _ = try store.appendCommitted(enrollmentState())
      _ = try store.appendCommitted(committedState(revision: 2))
      _ = try store.appendCommitted(committedState(revision: 3))
      _ = try store.appendCommitted(
        committedState(
          revision: 4, state: .preparing, transition: .prepare))
      _ = try store.appendCommitted(committedState(revision: 5))

      failAt = point
      #expect(throws: JournalFixtureError.injected) {
        try store.appendCommitted(
          committedState(
            revision: 6, state: .preparing, transition: .prepare))
      }
      failAt = nil

      let recoveredCheckpoint = store.recover()
      #expect(recoveredCheckpoint.committedState?.revision == 5)
      #expect(try anchor.load()?.pending == nil)
      _ = try store.appendCommitted(
        committedState(
          revision: 6, state: .preparing, transition: .prepare))
      #expect(store.recover().committedState?.revision == 6)
      #expect(try journalGenerations(in: root) == [2, 3])
    }
  }
}

@Test func cleanupFailureIsObservableAndBlocksRecoveryAndMutation() throws {
  try withTemporaryJournalDirectory { root in
    let failure = AuthorityJournalStorageError.generationCleanupFailed(
      operation: "injected cleanup", code: EIO)
    var cleanupFailureEnabled = false
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: InMemoryAuthorityJournalAnchorStore(),
      recordCapacity: 10,
      faultInjector: { point in
        if cleanupFailureEnabled, point == .generationCleanupStarted {
          throw failure
        }
      })
    _ = try store.appendCommitted(enrollmentState())
    _ = try store.appendCommitted(committedState(revision: 2))
    _ = try store.appendCommitted(committedState(revision: 3))
    _ = try store.appendCommitted(
      committedState(
        revision: 4, state: .preparing, transition: .prepare))
    _ = try store.appendCommitted(committedState(revision: 5))

    cleanupFailureEnabled = true
    #expect(throws: failure) {
      try store.appendCommitted(
        committedState(
          revision: 6, state: .preparing, transition: .prepare))
    }
    let failedRecovery = store.recover()
    #expect(
      isQuarantined(
        failedRecovery, reason: .generationCleanupFailed))
    #expect(!failedRecovery.permitsStart)
    #expect(throws: failure) {
      try store.appendCommitted(
        committedState(
          revision: 6, state: .preparing, transition: .prepare))
    }

    cleanupFailureEnabled = false
    _ = try store.appendCommitted(
      committedState(
        revision: 6, state: .preparing, transition: .prepare))
    #expect(store.recover().committedState?.revision == 6)
    #expect(try journalGenerations(in: root) == [2, 3])
  }
}

@Test func insecureObsoleteGenerationIsNeverUnlinked() throws {
  try withTemporaryJournalDirectory { root in
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      recordCapacity: 10)
    _ = try store.appendCommitted(enrollmentState())
    _ = try store.appendCommitted(committedState(revision: 2))
    _ = try store.appendCommitted(committedState(revision: 3))
    _ = try store.appendCommitted(
      committedState(
        revision: 4, state: .preparing, transition: .prepare))
    _ = try store.appendCommitted(committedState(revision: 5))

    let obsoleteJournal = root.appendingPathComponent(
      "authority.v2.00000000000000000001.journal")
    let secondLink = root.appendingPathComponent("obsolete-journal-second-link")
    guard link(obsoleteJournal.path, secondLink.path) == 0 else {
      throw JournalFixtureError.setup
    }
    #expect(throws: AuthorityJournalValidationError.invalidGenerationEntry) {
      try store.appendCommitted(
        committedState(
          revision: 6, state: .preparing, transition: .prepare))
    }
    #expect(
      isQuarantined(
        store.recover(), reason: .invalidGenerationEntry))
    #expect(FileManager.default.fileExists(atPath: obsoleteJournal.path))
    #expect(FileManager.default.fileExists(atPath: secondLink.path))
  }
}

@Test func synchronizedTemporaryHeadCompletesThePendingCAS() throws {
  try withTemporaryJournalDirectory { root in
    let anchor = InMemoryAuthorityJournalAnchorStore()
    var failAt: AuthorityJournalFaultPoint?
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: anchor,
      faultInjector: { point in
        if point == failAt { throw JournalFixtureError.injected }
      })
    _ = try store.appendCommitted(enrollmentState())
    failAt = .recordSynchronized
    #expect(throws: JournalFixtureError.injected) {
      try store.appendCommitted(committedState(revision: 2, generation: 2))
    }
    failAt = nil
    let pending = try #require(anchor.load()?.pending)
    let pendingHead = try AuthorityJournalHead(
      sequence: pending.sequence,
      committedLength: pending.committedLength,
      recordSHA256: pending.recordSHA256)
    let temporaryHead = root.appendingPathComponent(
      ".authority.v2.00000000000000000001.head.tmp")
    try AuthorityJournalCodec.encodeHead(pendingHead).write(to: temporaryHead)
    guard chmod(temporaryHead.path, 0o600) == 0 else {
      throw JournalFixtureError.setup
    }

    let recovery = store.recover()
    #expect(recovery.committedState?.revision == 2)
    #expect(try anchor.load()?.pending == nil)
    #expect(!FileManager.default.fileExists(atPath: temporaryHead.path))
  }
}
