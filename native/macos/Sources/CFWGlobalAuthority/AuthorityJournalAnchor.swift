import CFWSharedProtocol
import Foundation
import Security

public enum AuthorityJournalAnchorError: Error, Equatable, Sendable {
  case unavailable(OSStatus)
  case invalidData
  case compareAndSwapFailed
}

public struct AuthorityJournalAnchorCursor: Codable, Equatable, Sendable {
  public let generation: UInt64
  public let sequence: UInt64
  public let committedLength: UInt64
  public let recordSHA256: SHA256Digest
  public let stateRevision: UInt64

  public init(
    generation: UInt64, sequence: UInt64, committedLength: UInt64,
    recordSHA256: SHA256Digest, stateRevision: UInt64
  ) throws {
    guard generation > 0, sequence > 0, committedLength > 0, stateRevision > 0 else {
      throw AuthorityJournalAnchorError.invalidData
    }
    self.generation = generation
    self.sequence = sequence
    self.committedLength = committedLength
    self.recordSHA256 = recordSHA256
    self.stateRevision = stateRevision
  }

  enum CodingKeys: String, CodingKey {
    case generation, sequence
    case committedLength = "committed_length"
    case recordSHA256 = "record_sha256"
    case stateRevision = "state_revision"
  }

  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      generation: values.decode(UInt64.self, forKey: .generation),
      sequence: values.decode(UInt64.self, forKey: .sequence),
      committedLength: values.decode(UInt64.self, forKey: .committedLength),
      recordSHA256: values.decode(SHA256Digest.self, forKey: .recordSHA256),
      stateRevision: values.decode(UInt64.self, forKey: .stateRevision))
  }
}

public struct AuthorityJournalAnchor: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let storeID: AuthorityIdentifier
  public let committed: AuthorityJournalAnchorCursor?
  public let pending: AuthorityJournalAnchorCursor?

  public init(
    storeID: AuthorityIdentifier,
    committed: AuthorityJournalAnchorCursor?,
    pending: AuthorityJournalAnchorCursor?
  ) throws {
    if committed == nil, let pending {
      guard pending.generation == 1, pending.sequence == 1 else {
        throw AuthorityJournalAnchorError.invalidData
      }
    }
    if let committed, let pending {
      let (nextGeneration, overflow) =
        committed.generation.addingReportingOverflow(1)
      guard
        pending.generation == committed.generation
          || (!overflow && pending.generation == nextGeneration)
      else { throw AuthorityJournalAnchorError.invalidData }
      if pending.generation == committed.generation {
        let (nextSequence, sequenceOverflow) =
          committed.sequence.addingReportingOverflow(1)
        let (nextRevision, revisionOverflow) =
          committed.stateRevision.addingReportingOverflow(1)
        guard !sequenceOverflow, pending.sequence == nextSequence,
          !revisionOverflow, pending.stateRevision == nextRevision,
          pending.committedLength > committed.committedLength
        else { throw AuthorityJournalAnchorError.invalidData }
      } else {
        guard pending.sequence == 1,
          pending.stateRevision == committed.stateRevision
        else { throw AuthorityJournalAnchorError.invalidData }
      }
    }
    schemaVersion = 2
    self.storeID = storeID
    self.committed = committed
    self.pending = pending
  }

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case storeID = "store_id"
    case committed, pending
  }

  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    guard try values.decode(UInt16.self, forKey: .schemaVersion) == 2 else {
      throw AuthorityJournalAnchorError.invalidData
    }
    try self.init(
      storeID: values.decode(AuthorityIdentifier.self, forKey: .storeID),
      committed: values.decodeIfPresent(
        AuthorityJournalAnchorCursor.self, forKey: .committed),
      pending: values.decodeIfPresent(
        AuthorityJournalAnchorCursor.self, forKey: .pending))
  }
}

public protocol AuthorityJournalAnchorStoring: Sendable {
  func load() throws -> AuthorityJournalAnchor?
  func compareAndSwap(
    expected: AuthorityJournalAnchor?, replacement: AuthorityJournalAnchor
  ) throws
}

enum AuthorityJournalAnchorCodec {
  static func encode(_ value: AuthorityJournalAnchor) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do { return try encoder.encode(value) } catch {
      throw AuthorityJournalAnchorError.invalidData
    }
  }

  static func decode(_ data: Data) throws -> AuthorityJournalAnchor {
    let value: AuthorityJournalAnchor
    do { value = try JSONDecoder().decode(AuthorityJournalAnchor.self, from: data) } catch {
      throw AuthorityJournalAnchorError.invalidData
    }
    guard try encode(value) == data else {
      throw AuthorityJournalAnchorError.invalidData
    }
    return value
  }
}

/// Production anchor for the root launchd daemon. The daemon intentionally uses
/// the file-based System keychain selected by its system execution context. The
/// query has no data-protection-keychain selector, access group, or synchronizable
/// attribute, so this item cannot drift into a per-user or iCloud keychain.
public final class SystemKeychainAuthorityJournalAnchorStore:
  AuthorityJournalAnchorStoring, @unchecked Sendable
{
  private static let service = "com.bill.clashformac.global-authority.journal-anchor"
  private static let account = "machine-v2"
  private let lock = NSLock()

  public init() {}

  public func load() throws -> AuthorityJournalAnchor? {
    try lock.withLock { try loadUnlocked() }
  }

  public func compareAndSwap(
    expected: AuthorityJournalAnchor?, replacement: AuthorityJournalAnchor
  ) throws {
    try lock.withLock {
      guard try loadUnlocked() == expected else {
        throw AuthorityJournalAnchorError.compareAndSwapFailed
      }
      let encoded = try AuthorityJournalAnchorCodec.encode(replacement)
      if expected == nil {
        var attributes = Self.itemIdentity
        attributes[kSecValueData] = encoded
        attributes[kSecAttrLabel] = "Clash for Mac machine authority journal anchor"
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
          throw AuthorityJournalAnchorError.compareAndSwapFailed
        }
        guard status == errSecSuccess else { throw Self.map(status) }
      } else {
        let status = SecItemUpdate(
          Self.itemIdentity as CFDictionary,
          [kSecValueData: encoded] as CFDictionary)
        if status == errSecItemNotFound {
          throw AuthorityJournalAnchorError.compareAndSwapFailed
        }
        guard status == errSecSuccess else { throw Self.map(status) }
      }
    }
  }

  static var itemIdentity: [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: account,
    ]
  }

  private func loadUnlocked() throws -> AuthorityJournalAnchor? {
    var query = Self.itemIdentity
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw Self.map(status) }
    guard let data = result as? Data else {
      throw AuthorityJournalAnchorError.invalidData
    }
    return try AuthorityJournalAnchorCodec.decode(data)
  }

  private static func map(_ status: OSStatus) -> AuthorityJournalAnchorError {
    switch status {
    case errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed:
      .unavailable(status)
    default:
      .unavailable(status)
    }
  }
}

/// Deterministic test seam. Production never constructs this store.
public final class InMemoryAuthorityJournalAnchorStore:
  AuthorityJournalAnchorStoring, @unchecked Sendable
{
  private let lock = NSLock()
  private var value: AuthorityJournalAnchor?
  private var unavailableStatus: OSStatus?

  public init(_ value: AuthorityJournalAnchor? = nil) {
    self.value = value
  }

  public func load() throws -> AuthorityJournalAnchor? {
    try lock.withLock {
      if let unavailableStatus {
        throw AuthorityJournalAnchorError.unavailable(unavailableStatus)
      }
      return value
    }
  }

  public func compareAndSwap(
    expected: AuthorityJournalAnchor?, replacement: AuthorityJournalAnchor
  ) throws {
    try lock.withLock {
      if let unavailableStatus {
        throw AuthorityJournalAnchorError.unavailable(unavailableStatus)
      }
      guard value == expected else {
        throw AuthorityJournalAnchorError.compareAndSwapFailed
      }
      value = replacement
    }
  }

  public func setUnavailableStatusForTesting(_ status: OSStatus?) {
    lock.withLock { unavailableStatus = status }
  }

  public func replaceForTesting(_ replacement: AuthorityJournalAnchor?) {
    lock.withLock { value = replacement }
  }
}
