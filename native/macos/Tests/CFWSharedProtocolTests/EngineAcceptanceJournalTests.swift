import CryptoKit
import Darwin
import Foundation
import Security
import Testing

@testable import CFWSharedProtocol

// The acceptance journal: replays refused and monotonic generations accepted,
// over an in-memory cursor store.
private final class MemoryAcceptanceCursorStore:
  JournalDataStoring, @unchecked Sendable
{
  private let lock = NSLock()
  private var data: Data?
  private var failure: JournalAuthenticationError?

  func load() throws(JournalAuthenticationError) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    if let failure {
      throw failure
    }
    return data
  }

  func save(_ data: Data) throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let failure {
      throw failure
    }
    self.data = data
  }

  func remove() throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let failure {
      throw failure
    }
    data = nil
  }

  func replace(with data: Data) {
    lock.withLock {
      self.data = data
    }
  }

  func setFailure(_ failure: JournalAuthenticationError?) {
    lock.withLock {
      self.failure = failure
    }
  }
}

@Test func acceptanceJournalRejectsReplayAndAcceptsMonotonicGeneration() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }

  let cursorStore = MemoryAcceptanceCursorStore()
  let journal = ConfigurationAcceptanceStore(
    testingRootURL: root,
    allowedSlot: .tunnel,
    cursorStore: cursorStore
  )
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  let first = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 3,
    generation: 7,
    byteCount: 128,
    sha256: digest
  )
  try journal.accept(first)

  #expect(throws: ConfigurationStoreError.self) {
    try journal.accept(first)
  }

  let next = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 3,
    generation: 8,
    byteCount: 128,
    sha256: digest
  )
  try journal.accept(next)

  let differentInstallation = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: UUID(),
    epoch: 4,
    generation: 1,
    byteCount: 128,
    sha256: digest
  )
  #expect(throws: ConfigurationStoreError.self) {
    try journal.accept(differentInstallation)
  }

  let wrongSlot = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 4,
    generation: 9,
    byteCount: 128,
    sha256: digest
  )
  #expect(
    throws: ConfigurationStoreError.unexpectedAcceptanceSlot(
      expected: .tunnel,
      actual: .systemProxy
    )
  ) {
    try journal.accept(wrongSlot)
  }

  cursorStore.replace(with: Data("{}".utf8))
  #expect(throws: ConfigurationStoreError.malformedAcceptanceJournal) {
    try journal.accept(next)
  }

  cursorStore.setFailure(.keychainReadFailed(errSecInteractionNotAllowed))
  #expect(
    throws: ConfigurationStoreError.acceptanceStateUnavailable(
      .keychainReadFailed(errSecInteractionNotAllowed)
    )
  ) {
    try journal.accept(next)
  }

  #expect(
    !FileManager.default.fileExists(
      atPath: root.appendingPathComponent("tunnel-accepted.json").path
    )
  )
}
