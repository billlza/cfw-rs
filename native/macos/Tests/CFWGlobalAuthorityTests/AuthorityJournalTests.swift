import CFWSharedProtocol
import Darwin
import Foundation
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

private enum JournalFixtureError: Error {
  case injected
  case setup
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

@Test func appendUsesRecordHeadDirectoryDurabilityOrder() throws {
  try withTemporaryJournalDirectory { root in
    var observed: [AuthorityJournalFaultPoint] = []
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      faultInjector: { observed.append($0) }
    )
    let state = try committedState(revision: 1)
    let head = try store.appendCommitted(state)

    #expect(
      observed == [
        .recordSynchronized, .temporaryHeadSynchronized, .headRenamed,
      ])
    #expect(head.sequence == 1)
    let recovery = store.recover()
    #expect(recovery.committedState == state)
    #expect(recovery.posture == .recovering(.verifyOff))
  }
}

@Test func crashAfterRecordSyncQuarantinesUncommittedTail() throws {
  try withTemporaryJournalDirectory { root in
    var failAt: AuthorityJournalFaultPoint?
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      faultInjector: { point in
        if point == failAt { throw JournalFixtureError.injected }
      }
    )
    let first = try committedState(revision: 1)
    try store.appendCommitted(first)
    failAt = .recordSynchronized

    #expect(throws: JournalFixtureError.injected) {
      try store.appendCommitted(committedState(revision: 2))
    }
    let recovery = store.recover()
    #expect(isQuarantined(recovery, reason: .trailingData))
    #expect(recovery.committedState == first)
    #expect(!recovery.permitsStart)
  }
}

@Test func headRenameFaultRecoversOnlyTheDurableCanonicalCommit() throws {
  try withTemporaryJournalDirectory { root in
    let state = try committedState(revision: 1)
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path,
      expectedOwnerUID: getuid(),
      faultInjector: { point in
        if point == .headRenamed { throw JournalFixtureError.injected }
      }
    )
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
    try store.appendCommitted(committedState(revision: 1, generation: 7))

    #expect(throws: AuthorityJournalStorageError.nonMonotonicCommit) {
      try store.appendCommitted(committedState(revision: 3, generation: 8))
    }
    #expect(throws: AuthorityJournalStorageError.nonMonotonicCommit) {
      try store.appendCommitted(committedState(revision: 2, generation: 6))
    }
    #expect(store.recover().committedState?.revision == 1)
  }
}

private func frameForTesting(
  payload: Data,
  sequence: UInt64,
  previous: SHA256Digest
) throws -> (frame: Data, digest: SHA256Digest) {
  var prefix = Data("CFWAJR01".utf8)
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
