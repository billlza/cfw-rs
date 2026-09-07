import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security

public enum CredentialVaultConstants {
  public static let schemaVersion: UInt16 = 2
  public static let maximumEntries = 512
  public static let maximumDocumentBytes = 1_048_576
}

public enum CredentialVaultError: Error, Equatable, Sendable {
  case invalidAccessGroup
  case invalidProfileIdentifier
  case invalidProfileDigest
  case immutableConflict(UUID)
  case missingCredential(UUID)
  case kindMismatch(UUID)
  case duplicateReference(UUID)
  case unexpectedCredential(UUID)
  case corrupt
  case unsupportedSchemaVersion(UInt16)
  case missingVault
  case capacityExceeded
  case compareAndSwapConflict
  case garbageCollectionConfirmationExpired
  case keychain(OSStatus)
}

public struct CredentialPresence: Codable, Equatable, Sendable {
  public let reference: CredentialReference
  public let present: Bool

  public init(reference: CredentialReference, present: Bool) {
    self.reference = reference
    self.present = present
  }
}

public struct CredentialVaultReceipt: Codable, Equatable, Sendable {
  public let profileID: UUID
  public let profileDigest: SHA256Digest

  public init(audience: CredentialAudience) {
    profileID = audience.profileID
    profileDigest = audience.profileDigest
  }
}

struct StoredCredentialVaultBlob: Equatable, Sendable {
  var data: Data
  let revision: UUID

  mutating func erase() {
    data.resetBytes(in: data.startIndex..<data.endIndex)
    data.removeAll(keepingCapacity: false)
  }
}

protocol CredentialVaultBlobStoring: Sendable {
  func load() throws -> StoredCredentialVaultBlob?
  func compareAndSwap(
    expectedRevision: UUID?,
    newRevision: UUID,
    data: Data
  ) throws
}

struct DataProtectionKeychainCredentialVaultStore: CredentialVaultBlobStoring, Sendable {
  private static let service = "com.bill.clashformac.credential-vault"
  private static let account = "credential-vault-v1"
  private let accessGroup: String

  init(accessGroup: String) throws {
    let pattern = /^[A-Z0-9]{10}\.[A-Za-z0-9][A-Za-z0-9.-]{2,254}$/
    guard accessGroup.wholeMatch(of: pattern) != nil else {
      throw CredentialVaultError.invalidAccessGroup
    }
    self.accessGroup = accessGroup
  }

  func load() throws -> StoredCredentialVaultBlob? {
    var query = baseQuery
    query[kSecReturnAttributes] = true
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess,
      let values = result as? [CFString: Any],
      let data = values[kSecValueData] as? Data,
      let revisionText = values[kSecAttrLabel] as? String,
      let revision = UUID(uuidString: revisionText),
      revision.uuidString.lowercased() == revisionText
    else {
      if status != errSecSuccess {
        throw CredentialVaultError.keychain(status)
      }
      throw CredentialVaultError.corrupt
    }
    return StoredCredentialVaultBlob(data: data, revision: revision)
  }

  func compareAndSwap(
    expectedRevision: UUID?,
    newRevision: UUID,
    data: Data
  ) throws {
    let newRevisionText = newRevision.uuidString.lowercased()
    if let expectedRevision {
      var query = baseQuery
      query[kSecAttrLabel] = expectedRevision.uuidString.lowercased()
      let attributes: [CFString: Any] = [
        kSecValueData: data,
        kSecAttrLabel: newRevisionText,
      ]
      let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
      if status == errSecItemNotFound {
        throw CredentialVaultError.compareAndSwapConflict
      }
      guard status == errSecSuccess else {
        throw CredentialVaultError.keychain(status)
      }
      return
    }

    var attributes = baseQuery
    attributes[kSecValueData] = data
    attributes[kSecAttrLabel] = newRevisionText
    attributes[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(attributes as CFDictionary, nil)
    if status == errSecDuplicateItem {
      throw CredentialVaultError.compareAndSwapConflict
    }
    guard status == errSecSuccess else {
      throw CredentialVaultError.keychain(status)
    }
  }

  private var baseQuery: [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrAccount: Self.account,
      kSecAttrAccessGroup: accessGroup,
      kSecAttrSynchronizable: false,
      kSecUseDataProtectionKeychain: true,
    ]
  }
}

struct CredentialVaultDocument: Codable, Equatable {
  let schemaVersion: UInt16
  let revision: UUID
  var entries: [CredentialVaultEntry]
}

struct CredentialVaultEntry: Codable, Equatable {
  let audience: CredentialAudience
  let reference: CredentialReference
  var secret: Data

  mutating func erase() {
    secret.resetBytes(in: secret.startIndex..<secret.endIndex)
    secret.removeAll(keepingCapacity: false)
  }
}
