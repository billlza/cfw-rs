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
