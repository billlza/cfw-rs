import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

private enum JournalFixtureError: Error {
  case injected
  case setup
}

private final class ConcurrentJournalStoreResults: @unchecked Sendable {
  private let lock = NSLock()
  private var retainedStores: [DescriptorRelativeAuthorityJournalStore] = []
  private var retainedErrors: [Error] = []

  func record(_ result: Result<DescriptorRelativeAuthorityJournalStore, Error>) {
    lock.withLock {
      switch result {
      case .success(let store): retainedStores.append(store)
      case .failure(let error): retainedErrors.append(error)
      }
    }
  }

  var stores: [DescriptorRelativeAuthorityJournalStore] {
    lock.withLock { retainedStores }
  }

  var errors: [Error] {
    lock.withLock { retainedErrors }
  }
}

private func identifier(_ value: String) throws -> AuthorityIdentifier {
  guard let uuid = UUID(uuidString: value) else { throw JournalFixtureError.setup }
  return AuthorityIdentifier(uuid)
}

private func digest(_ byte: String) throws -> SHA256Digest {
  try SHA256Digest(hex: String(repeating: byte, count: 64))
}

private func committedState(
  revision: UInt64,
  generation: UInt64? = nil,
  state: AuthorityState = .off,
  transition: AuthorityJournalTransition = .globalOff
) throws -> AuthorityCommittedState {
  let hasOwner = state != .off
  return try AuthorityCommittedState(
    installationID: identifier("11111111-1111-1111-1111-111111111111"),
    epoch: 4,
    generation: generation ?? revision,
    revision: revision,
    transition: transition,
    state: state,
    operationID: hasOwner
      ? identifier("22222222-2222-2222-2222-222222222222") : nil,
    mode: hasOwner ? .tunnel : nil,
    configSHA256: hasOwner ? digest("a") : nil,
    leaseID: hasOwner
      ? identifier("33333333-3333-3333-3333-333333333333") : nil,
    ownerUID: hasOwner ? 501 : nil
  )
}

private func enrollmentState(
  revision: UInt64 = 1
) throws -> AuthorityCommittedState {
  try AuthorityCommittedState(
    installationID: identifier("11111111-1111-1111-1111-111111111111"),
    epoch: 0,
    generation: 0,
    revision: revision,
    transition: .enrollOff,
    state: .off,
    operationID: nil,
    mode: nil,
    configSHA256: nil,
    leaseID: nil,
    ownerUID: nil)
}

private func journalImage(
  _ states: [AuthorityCommittedState]
) throws -> AuthorityJournalImage {
  var journal = Data()
  var previous = AuthorityJournalCodec.zeroDigest
  var head: AuthorityJournalHead?
  for (index, state) in states.enumerated() {
    let record = try AuthorityJournalCodec.encodeRecord(
      state: state,
      sequence: UInt64(index + 1),
      previousSHA256: previous
    )
    journal.append(record.frame)
    previous = record.digest
    head = try AuthorityJournalHead(
      sequence: UInt64(index + 1),
      committedLength: UInt64(journal.count),
      recordSHA256: record.digest
    )
  }
  return AuthorityJournalImage(
    journal: journal,
    head: try head.map(AuthorityJournalCodec.encodeHead)
  )
}

private func temporaryJournalDirectory() throws -> URL {
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("cfw-authority-journal-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  guard chmod(root.path, 0o700) == 0 else { throw JournalFixtureError.setup }
  guard let canonicalPath = realpath(root.path, nil) else {
    throw JournalFixtureError.setup
  }
  defer { free(canonicalPath) }
  return URL(fileURLWithPath: String(cString: canonicalPath), isDirectory: true)
}

private func withTemporaryJournalDirectory<T>(
  _ body: (URL) throws -> T
) throws -> T {
  let root = try temporaryJournalDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  return try body(root)
}

private func writeSecuredJournalFixture(_ data: Data, to url: URL) throws {
  try data.write(to: url)
  guard chmod(url.path, 0o600) == 0 else { throw JournalFixtureError.setup }
}

private func journalGenerations(in root: URL) throws -> Set<UInt64> {
  let names = try FileManager.default.contentsOfDirectory(atPath: root.path)
  return Set(
    names.compactMap { name in
      let components = name.split(separator: ".")
      guard components.count >= 4,
        components[0] == "authority", components[1] == "v2"
      else { return nil }
      return UInt64(components[2])
    })
}

private func isQuarantined(
  _ recovery: AuthorityJournalRecovery,
  reason: AuthorityJournalValidationError? = nil
) -> Bool {
  guard case .quarantined(let actual) = recovery.posture else { return false }
  return reason == nil || actual == reason
}

@Test func recoveryReconstructsOnlyCommittedHighWaterAndStartsRecovering() throws {
  let first = try committedState(revision: 1)
  let active = try committedState(
    revision: 2, state: .active, transition: .ready)
  let recovery = AuthorityJournalRecoveryReducer.recover(
    try journalImage([first, active]))

  #expect(recovery.committedState == active)
  #expect(recovery.head?.sequence == 2)
  #expect(recovery.posture == .recovering(.reattestOwner))
  #expect(!recovery.permitsStart)
}

@Test func emptyStoreDoesNotInventReplayStateOrPermitStart() {
  let recovery = AuthorityJournalRecoveryReducer.recover(
    AuthorityJournalImage(journal: nil, head: nil))
  #expect(recovery.committedState == nil)
  #expect(recovery.posture == .recovering(.verifyOff))
  #expect(!recovery.permitsStart)
}

@Test func truncationCorruptionAndReorderingAlwaysQuarantine() throws {
  let first = try committedState(revision: 1)
  let second = try committedState(revision: 2)
  let image = try journalImage([first, second])
  let journal = try #require(image.journal)

  let truncated = AuthorityJournalImage(
    journal: journal.dropLast(), head: image.head)
  #expect(
    isQuarantined(
      AuthorityJournalRecoveryReducer.recover(truncated), reason: .truncated))

  var corrupted = journal
  corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0xff
  #expect(
    isQuarantined(
      AuthorityJournalRecoveryReducer.recover(
        AuthorityJournalImage(journal: corrupted, head: image.head))))

  let decoded = try AuthorityJournalCodec.decodeRecords(journal)
  let firstEnd = try #require(decoded.first?.endOffset)
  let reorderedData =
    journal.subdata(in: firstEnd..<journal.count)
    + journal.subdata(in: 0..<firstEnd)
  #expect(
    isQuarantined(
      AuthorityJournalRecoveryReducer.recover(
        AuthorityJournalImage(journal: reorderedData, head: image.head))))
}

@Test func rolledBackOrTrailingHeadNeverResetsPermissively() throws {
  let firstImage = try journalImage([committedState(revision: 1)])
  let firstHead = try AuthorityJournalCodec.decodeHead(try #require(firstImage.head))
  let secondImage = try journalImage([
    committedState(revision: 1), committedState(revision: 2),
  ])
  let secondHead = try AuthorityJournalCodec.decodeHead(try #require(secondImage.head))

  let rolledBack = AuthorityJournalRecoveryReducer.recover(
    firstImage, minimumHead: secondHead)
  #expect(isQuarantined(rolledBack, reason: .rollback))
  #expect(rolledBack.committedState == nil)

  let trailing = AuthorityJournalRecoveryReducer.recover(
    AuthorityJournalImage(
      journal: secondImage.journal,
      head: try AuthorityJournalCodec.encodeHead(firstHead)
    ))
  #expect(isQuarantined(trailing, reason: .trailingData))
  #expect(!trailing.permitsStart)
}

@Test func unknownCanonicalRecordFieldIsRejected() throws {
  let state = try committedState(revision: 1)
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let canonical = try encoder.encode(state)
  var object = try #require(
    JSONSerialization.jsonObject(with: canonical) as? [String: Any])
  object["future_field"] = 1
  let unknownPayload = try JSONSerialization.data(
    withJSONObject: object,
    options: [.sortedKeys, .withoutEscapingSlashes]
  )
  let framed = try frameForTesting(
    payload: unknownPayload,
    sequence: 1,
    previous: AuthorityJournalCodec.zeroDigest
  )
  let head = try AuthorityJournalHead(
    sequence: 1,
    committedLength: UInt64(framed.frame.count),
    recordSHA256: framed.digest
  )
  let recovery = AuthorityJournalRecoveryReducer.recover(
    AuthorityJournalImage(
      journal: framed.frame,
      head: try AuthorityJournalCodec.encodeHead(head)
    ))
  #expect(isQuarantined(recovery, reason: .noncanonicalRecord))
}

@Test func journalSchemaCannotSerializeTicketsSecretsOrConfigurationBytes() throws {
  let image = try journalImage([
    committedState(revision: 1, state: .preparing, transition: .prepare)
  ])
  let bytes = try #require(image.journal)
  let text = String(decoding: bytes, as: UTF8.self)
  #expect(!text.contains("ticket"))
  #expect(!text.contains("secret"))
  #expect(!text.contains("credential"))
  #expect(!text.contains("configuration_bytes"))
}

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

private func frameForTesting(
  payload: Data,
  sequence: UInt64,
  previous: SHA256Digest
) throws -> (frame: Data, digest: SHA256Digest) {
  var prefix = Data("CFWAJR02".utf8)
  prefix.appendInteger(UInt32(payload.count))
  prefix.appendInteger(sequence)
  prefix.append(try #require(Data(testHex: previous.hex)))
  prefix.append(Data(SHA256.hash(data: payload)))
  var frame = prefix
  frame.appendInteger(testCRC32(prefix + payload))
  frame.append(payload)
  return (
    frame,
    try SHA256Digest(hex: Data(SHA256.hash(data: frame)).testHex)
  )
}

private func testCRC32(_ data: Data) -> UInt32 {
  var crc: UInt32 = 0xffff_ffff
  for byte in data {
    crc ^= UInt32(byte)
    for _ in 0..<8 {
      let mask = UInt32(bitPattern: -Int32(crc & 1))
      crc = (crc >> 1) ^ (0xedb8_8320 & mask)
    }
  }
  return ~crc
}

extension Data {
  fileprivate mutating func appendInteger<T: FixedWidthInteger>(_ value: T) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
  }

  fileprivate var testHex: String { map { String(format: "%02x", $0) }.joined() }

  fileprivate init?(testHex: String) {
    guard testHex.count.isMultiple(of: 2) else { return nil }
    var bytes: [UInt8] = []
    var index = testHex.startIndex
    while index < testHex.endIndex {
      let next = testHex.index(index, offsetBy: 2)
      guard let byte = UInt8(testHex[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }
}
