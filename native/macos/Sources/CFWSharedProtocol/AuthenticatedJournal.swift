import Foundation
import Security

public enum JournalAuthenticationError: Error, Equatable, Sendable {
  case invalidIdentifier
  case keychainReadFailed(OSStatus)
  case keychainWriteFailed(OSStatus)
  case unexpectedKeychainValue
}

extension JournalAuthenticationError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .invalidIdentifier:
      return "Journal Keychain identifiers must not be empty."
    case .keychainReadFailed(let status):
      return "Journal Keychain read failed with Security status \(status)."
    case .keychainWriteFailed(let status):
      return "Journal Keychain persistence failed with Security status \(status)."
    case .unexpectedKeychainValue:
      return "Journal Keychain item did not contain data."
    }
  }
}

public protocol JournalDataStoring: Sendable {
  func load() throws(JournalAuthenticationError) -> Data?
  func save(_ data: Data) throws(JournalAuthenticationError)
  func remove() throws(JournalAuthenticationError)
}

/// Stores one authoritative value in the Data Protection Keychain. Each
/// `SecItemUpdate`, `SecItemAdd`, or `SecItemDelete` operation is the complete
/// persistence transaction; callers must not mirror the value into a second
/// store that would reintroduce cross-store commit windows.
public struct KeychainJournalDataStore: JournalDataStoring {
  private let accessGroup: String
  private let service: String
  private let account: String
  private let label: String

  public init(
    keychainAccessGroup: String,
    service: String,
    account: String,
    label: String
  ) throws(JournalAuthenticationError) {
    guard
      !keychainAccessGroup.isEmpty,
      !service.isEmpty,
      !account.isEmpty,
      !label.isEmpty
    else {
      throw .invalidIdentifier
    }
    accessGroup = keychainAccessGroup
    self.service = service
    self.account = account
    self.label = label
  }

  public func load() throws(JournalAuthenticationError) -> Data? {
    var query = baseQuery
    query[kSecMatchLimit] = kSecMatchLimitOne
    query[kSecReturnData] = true
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess:
      guard let data = result as? Data else {
        throw .unexpectedKeychainValue
      }
      return data
    case errSecItemNotFound:
      return nil
    default:
      throw .keychainReadFailed(status)
    }
  }

  public func save(_ data: Data) throws(JournalAuthenticationError) {
    let updateStatus = SecItemUpdate(
      baseQuery as CFDictionary,
      updateAttributes(data) as CFDictionary
    )
    switch updateStatus {
    case errSecSuccess:
      return
    case errSecItemNotFound:
      break
    default:
      throw .keychainWriteFailed(updateStatus)
    }

    var attributes = baseQuery
    attributes[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    attributes[kSecAttrLabel] = label
    attributes[kSecValueData] = data
    let addStatus = SecItemAdd(attributes as CFDictionary, nil)
    switch addStatus {
    case errSecSuccess:
      return
    case errSecDuplicateItem:
      let retryStatus = SecItemUpdate(
        baseQuery as CFDictionary,
        updateAttributes(data) as CFDictionary
      )
      guard retryStatus == errSecSuccess else {
        throw .keychainWriteFailed(retryStatus)
      }
    default:
      throw .keychainWriteFailed(addStatus)
    }
  }

  public func remove() throws(JournalAuthenticationError) {
    let status = SecItemDelete(baseQuery as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw .keychainWriteFailed(status)
    }
  }

  private var baseQuery: [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: account,
      kSecAttrAccessGroup: accessGroup,
      kSecAttrSynchronizable: false,
      kSecUseDataProtectionKeychain: true,
    ]
  }

  private func updateAttributes(_ data: Data) -> [CFString: Any] {
    [
      kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecAttrLabel: label,
      kSecValueData: data,
    ]
  }
}

public struct VersionedJournalDataRecord: Equatable, Sendable {
  public let accountToken: String
  public let data: Data

  public init(accountToken: String, data: Data) {
    self.accountToken = accountToken
    self.data = data
  }
}

/// Compare-and-swap storage whose version token is a searchable Keychain
/// attribute. `kSecValueData` is deliberately not used as a query predicate:
/// Security.framework treats it as value bytes, not a match attribute.
public protocol VersionedJournalDataStoring: Sendable {
  func load() throws(JournalAuthenticationError) -> VersionedJournalDataRecord?
  func create(_ record: VersionedJournalDataRecord) throws(JournalAuthenticationError) -> Bool
  func compareExchange(
    expectedAccountToken: String,
    desired: VersionedJournalDataRecord
  ) throws(JournalAuthenticationError) -> Bool
  func compareDelete(
    expectedAccountToken: String
  ) throws(JournalAuthenticationError) -> Bool
}

/// Stores exactly zero or one versioned record under one service. The account is
/// the atomic revision token: update/delete queries match the exact prior account,
/// and an update changes both account and value in one Security.framework call.
public struct KeychainVersionedJournalDataStore: VersionedJournalDataStoring {
  private let accessGroup: String
  private let service: String
  private let label: String
  private let accountTokenPrefix: String
  private let maximumDataBytes: Int

  public init(
    keychainAccessGroup: String,
    service: String,
    label: String,
    accountTokenPrefix: String,
    maximumDataBytes: Int
  ) throws(JournalAuthenticationError) {
    guard !keychainAccessGroup.isEmpty, !service.isEmpty, !label.isEmpty,
      !accountTokenPrefix.isEmpty, accountTokenPrefix.utf8.count <= 64,
      accountTokenPrefix.last == ".",
      accountTokenPrefix.utf8.allSatisfy({ byte in
        (48...57).contains(byte) || (97...122).contains(byte) || byte == 45 || byte == 46
      }),
      maximumDataBytes > 0
    else {
      throw .invalidIdentifier
    }
    accessGroup = keychainAccessGroup
    self.service = service
    self.label = label
    self.accountTokenPrefix = accountTokenPrefix
    self.maximumDataBytes = maximumDataBytes
  }

  public func load() throws(JournalAuthenticationError) -> VersionedJournalDataRecord? {
    var query = serviceQuery
    query[kSecMatchLimit] = kSecMatchLimitAll
    query[kSecReturnAttributes] = true
    query[kSecReturnData] = true
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecItemNotFound:
      return nil
    case errSecSuccess:
      break
    default:
      throw .keychainReadFailed(status)
    }
    guard let values = result as? [[String: Any]], values.count == 1,
      let accountToken = values[0][kSecAttrAccount as String] as? String,
      let data = values[0][kSecValueData as String] as? Data
    else {
      throw .unexpectedKeychainValue
    }
    let record = VersionedJournalDataRecord(accountToken: accountToken, data: data)
    guard isValidRecord(record) else {
      throw .unexpectedKeychainValue
    }
    return record
  }

  public func create(
    _ record: VersionedJournalDataRecord
  ) throws(JournalAuthenticationError) -> Bool {
    guard isValidRecord(record), record.accountToken == genesisAccountToken else {
      throw .invalidIdentifier
    }
    // The caller's kernel lease serializes the empty/delete/create lifecycle.
    // The post-add load still detects an invariant breach instead of accepting
    // multiple service items as a successful creation.
    guard try load() == nil else { return false }
    var attributes = serviceQuery
    attributes[kSecAttrAccount] = record.accountToken
    attributes[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    attributes[kSecAttrLabel] = label
    attributes[kSecValueData] = record.data
    let status = SecItemAdd(attributes as CFDictionary, nil)
    switch status {
    case errSecSuccess:
      guard try load() == record else {
        throw .unexpectedKeychainValue
      }
      return true
    case errSecDuplicateItem:
      return false
    default:
      throw .keychainWriteFailed(status)
    }
  }

  public func compareExchange(
    expectedAccountToken: String,
    desired: VersionedJournalDataRecord
  ) throws(JournalAuthenticationError) -> Bool {
    guard isValidAccountToken(expectedAccountToken), isValidRecord(desired),
      isVersionedAccountToken(desired.accountToken)
    else {
      throw .invalidIdentifier
    }
    let status = SecItemUpdate(
      exactQuery(accountToken: expectedAccountToken) as CFDictionary,
      updateAttributes(desired) as CFDictionary
    )
    switch status {
    case errSecSuccess:
      return true
    case errSecItemNotFound:
      return false
    default:
      throw .keychainWriteFailed(status)
    }
  }

  public func compareDelete(
    expectedAccountToken: String
  ) throws(JournalAuthenticationError) -> Bool {
    guard isValidAccountToken(expectedAccountToken) else {
      throw .invalidIdentifier
    }
    let status = SecItemDelete(
      exactQuery(accountToken: expectedAccountToken) as CFDictionary
    )
    switch status {
    case errSecSuccess:
      return true
    case errSecItemNotFound:
      return false
    default:
      throw .keychainWriteFailed(status)
    }
  }

  private var serviceQuery: [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccessGroup: accessGroup,
      kSecAttrSynchronizable: false,
      kSecUseDataProtectionKeychain: true,
    ]
  }

  func exactQuery(accountToken: String) -> [CFString: Any] {
    var query = serviceQuery
    query[kSecAttrAccount] = accountToken
    return query
  }

  private func updateAttributes(
    _ record: VersionedJournalDataRecord
  ) -> [CFString: Any] {
    [
      kSecAttrAccount: record.accountToken,
      kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecAttrLabel: label,
      kSecValueData: record.data,
    ]
  }

  func isValidRecord(_ record: VersionedJournalDataRecord) -> Bool {
    !record.data.isEmpty && record.data.count <= maximumDataBytes
      && isValidAccountToken(record.accountToken)
  }

  private func isValidAccountToken(_ value: String) -> Bool {
    guard value.hasPrefix(accountTokenPrefix) else { return false }
    let suffix = value.dropFirst(accountTokenPrefix.count)
    if suffix == "genesis" { return true }
    return isVersionedAccountToken(value)
  }

  private var genesisAccountToken: String { accountTokenPrefix + "genesis" }

  private func isVersionedAccountToken(_ value: String) -> Bool {
    guard value.hasPrefix(accountTokenPrefix) else { return false }
    let suffix = value.dropFirst(accountTokenPrefix.count)
    return suffix.utf8.count == 64
      && suffix.utf8.allSatisfy { byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      }
  }
}
