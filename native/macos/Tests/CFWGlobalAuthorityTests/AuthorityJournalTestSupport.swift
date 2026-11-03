import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// Shared by the journal tests: committed and enrollment states, journal images
// and frames, temporary journal directories, and generation and quarantine
// probes.
enum JournalFixtureError: Error {
  case injected
  case setup
}

final class ConcurrentJournalStoreResults: @unchecked Sendable {
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

func digest(_ byte: String) throws -> SHA256Digest {
  try SHA256Digest(hex: String(repeating: byte, count: 64))
}

func committedState(
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

func enrollmentState(
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

func journalImage(
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

func withTemporaryJournalDirectory<T>(
  _ body: (URL) throws -> T
) throws -> T {
  let root = try temporaryJournalDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  return try body(root)
}

func writeSecuredJournalFixture(_ data: Data, to url: URL) throws {
  try data.write(to: url)
  guard chmod(url.path, 0o600) == 0 else { throw JournalFixtureError.setup }
}

func journalGenerations(in root: URL) throws -> Set<UInt64> {
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

func isQuarantined(
  _ recovery: AuthorityJournalRecovery,
  reason: AuthorityJournalValidationError? = nil
) -> Bool {
  guard case .quarantined(let actual) = recovery.posture else { return false }
  return reason == nil || actual == reason
}

func frameForTesting(
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
