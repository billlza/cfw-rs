import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// Appends and compaction: durability order, finish slots kept at capacity,
// retained generations, rollback detection, and crash recovery around a commit.
@Test func appendUsesRecordHeadDirectoryDurabilityOrder() throws {
  try withTemporaryJournalDirectory { root in
    var observed: [AuthorityJournalFaultPoint] = []
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      faultInjector: { observed.append($0) }
    )
    let state = try enrollmentState()
    let head = try store.appendCommitted(state)

    #expect(
      observed == [
        .anchorPendingSynchronized, .recordSynchronized,
        .temporaryHeadSynchronized, .headRenamed,
        .anchorCommittedSynchronized,
      ])
    #expect(head.sequence == 1)
    let recovery = store.recover()
    #expect(recovery.committedState == state)
    #expect(recovery.posture == .recovering(.verifyOff))
  }
}

@Test func prepareAtCapacityCompactsAndPreservesSevenFinishSlots() throws {
  try withTemporaryJournalDirectory { root in
    let anchor = InMemoryAuthorityJournalAnchorStore()
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: anchor,
      recordCapacity: 10)
    _ = try store.appendCommitted(enrollmentState())
    _ = try store.appendCommitted(committedState(revision: 2, generation: 2))
    _ = try store.appendCommitted(committedState(revision: 3, generation: 3))
    let generationOneAnchor = try #require(try anchor.load())
    let prepared = try store.appendCommitted(
      committedState(
        revision: 4, generation: 4,
        state: .preparing, transition: .prepare))

    #expect(prepared.sequence == 2)
    #expect(try anchor.load()?.committed?.generation == 2)
    #expect(
      10 - prepared.sequence
        >= UInt64(AuthorityJournalLimits.minimumLifecycleFinishRecords))
    let recovery = store.recover()
    #expect(recovery.head == prepared)
    #expect(recovery.committedState?.revision == 4)
    #expect(recovery.posture == .recovering(.stopOwner))

    anchor.replaceForTesting(generationOneAnchor)
    #expect(isQuarantined(store.recover(), reason: .rollback))
  }
}

@Test func quarantinedCleanupReconciliationCanCrossACompactionBoundary() throws {
  try withTemporaryJournalDirectory { root in
    let anchor = InMemoryAuthorityJournalAnchorStore()
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path, expectedOwnerUID: getuid(),
      anchorStore: anchor, recordCapacity: 10)
    try store.appendCommitted(enrollmentState())
    for revision in UInt64(2)...9 {
      try store.appendCommitted(committedState(revision: revision))
    }
    try store.appendCommitted(
      committedState(revision: 10, state: .quarantined, transition: .reconcileOff))
    #expect(store.recover().posture == .recovering(.stopOwner))
    let head = try store.appendCommitted(
      committedState(revision: 11, transition: .reconcileOff))
    let recovered = store.recover()
    #expect(head.sequence == 2)
    #expect(try anchor.load()?.committed?.generation == 2)
    #expect(recovered.committedState?.revision == 11)
    #expect(recovered.committedState?.state == .off)
    #expect(recovered.posture == .recovering(.verifyOff))
  }
}

@Test func repeatedCompactionRetainsOnlyActiveAndPreviousGenerations() throws {
  try withTemporaryJournalDirectory { root in
    let anchor = InMemoryAuthorityJournalAnchorStore()
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      anchorStore: anchor,
      recordCapacity: 10)

    _ = try store.appendCommitted(enrollmentState())
    _ = try store.appendCommitted(committedState(revision: 2))
    _ = try store.appendCommitted(committedState(revision: 3))
    _ = try store.appendCommitted(
      committedState(
        revision: 4, state: .preparing, transition: .prepare))
    let generationTwoAnchor = try #require(try anchor.load())
    #expect(try journalGenerations(in: root) == [1, 2])

    _ = try store.appendCommitted(committedState(revision: 5))
    _ = try store.appendCommitted(
      committedState(
        revision: 6, state: .preparing, transition: .prepare))
    #expect(try journalGenerations(in: root) == [2, 3])

    _ = try store.appendCommitted(committedState(revision: 7))
    let generationThreeFinalAnchor = try #require(try anchor.load())
    _ = try store.appendCommitted(
      committedState(
        revision: 8, state: .preparing, transition: .prepare))
    let generationFourAnchor = try #require(try anchor.load())
    #expect(try journalGenerations(in: root) == [3, 4])
    #expect(store.recover().committedState?.revision == 8)

    anchor.replaceForTesting(generationThreeFinalAnchor)
    #expect(isQuarantined(store.recover(), reason: .rollback))

    anchor.replaceForTesting(generationTwoAnchor)
    #expect(isQuarantined(store.recover(), reason: .anchorMismatch))

    anchor.replaceForTesting(generationFourAnchor)
    #expect(store.recover().committedState?.revision == 8)
  }
}

@Test func nonAdjacentFutureGenerationDetectsAnchorRollback() throws {
  try withTemporaryJournalDirectory { root in
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path, expectedOwnerUID: getuid())
    _ = try store.appendCommitted(enrollmentState())

    let nonAdjacentFuture = root.appendingPathComponent(
      "authority.v2.00000000000000000003.journal")
    try writeSecuredJournalFixture(Data(), to: nonAdjacentFuture)

    #expect(isQuarantined(store.recover(), reason: .rollback))
  }
}

@Test func crashAfterRecordSyncRollsForwardTheAnchoredPendingCommit() throws {
  try withTemporaryJournalDirectory { root in
    var failAt: AuthorityJournalFaultPoint?
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      faultInjector: { point in
        if point == failAt { throw JournalFixtureError.injected }
      }
    )
    let first = try enrollmentState()
    try store.appendCommitted(first)
    failAt = .recordSynchronized

    #expect(throws: JournalFixtureError.injected) {
      try store.appendCommitted(committedState(revision: 2, generation: 2))
    }
    let recovery = store.recover()
    #expect(recovery.committedState == (try committedState(revision: 2, generation: 2)))
    #expect(recovery.posture == .recovering(.verifyOff))
    #expect(!recovery.permitsStart)
  }
}

@Test func headRenameFaultRecoversOnlyTheDurableCanonicalCommit() throws {
  try withTemporaryJournalDirectory { root in
    var failAt: AuthorityJournalFaultPoint?
    let state = try committedState(revision: 2, generation: 2)
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      faultInjector: { point in
        if point == failAt { throw JournalFixtureError.injected }
      }
    )
    _ = try store.appendCommitted(enrollmentState())
    failAt = .headRenamed
    #expect(throws: JournalFixtureError.injected) {
      try store.appendCommitted(state)
    }
    let recovery = store.recover()
    #expect(recovery.committedState == state)
    #expect(recovery.posture == .recovering(.verifyOff))
    #expect(!recovery.permitsStart)
  }
}

@Test func appendRejectsRevisionAndGenerationRegression() throws {
  try withTemporaryJournalDirectory { root in
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path, expectedOwnerUID: getuid())
    try store.appendCommitted(enrollmentState())
    try store.appendCommitted(committedState(revision: 2, generation: 7))

    #expect(throws: AuthorityJournalStorageError.nonMonotonicCommit) {
      try store.appendCommitted(committedState(revision: 4, generation: 8))
    }
    #expect(throws: AuthorityJournalStorageError.nonMonotonicCommit) {
      try store.appendCommitted(committedState(revision: 3, generation: 6))
    }
    #expect(store.recover().committedState?.revision == 2)
  }
}
