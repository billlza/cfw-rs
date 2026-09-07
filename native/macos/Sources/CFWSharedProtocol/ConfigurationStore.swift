import CryptoKit
import Darwin
import Foundation

public enum ConfigurationStoreError: Error, Equatable, Sendable {
  case appGroupUnavailable(String)
  case invalidJSON
  case invalidFileType
  case fileTooLarge(actual: UInt64, maximum: UInt64)
  case byteCountMismatch(expected: UInt64, actual: UInt64)
  case digestMismatch(expected: String, actual: String)
  case malformedAcceptanceJournal
  case unexpectedAcceptanceSlot(expected: ConfigurationSlot, actual: ConfigurationSlot)
  case acceptanceStateUnavailable(JournalAuthenticationError)
  case unsafeMetadata(AppGroupFileSecurityError)
  case installationIdentifierMismatch(expected: UUID, actual: UUID)
  case staleConfiguration(
    acceptedEpoch: UInt64,
    acceptedGeneration: UInt64,
    requestedEpoch: UInt64,
    requestedGeneration: UInt64
  )
  case io(operation: String, code: Int32)
}

extension ConfigurationStoreError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .appGroupUnavailable(let identifier):
      return "App Group \(identifier) is unavailable."
    case .invalidJSON:
      return "Engine configuration is not a JSON object."
    case .invalidFileType:
      return "Engine configuration file metadata is invalid."
    case .fileTooLarge(let actual, let maximum):
      return "Engine configuration has \(actual) bytes; maximum is \(maximum)."
    case .byteCountMismatch(let expected, let actual):
      return "Engine configuration has \(actual) bytes; expected \(expected)."
    case .digestMismatch(let expected, let actual):
      return "Engine configuration digest is \(actual); expected \(expected)."
    case .malformedAcceptanceJournal:
      return "Configuration acceptance cursor is malformed."
    case .unexpectedAcceptanceSlot(let expected, let actual):
      return "Configuration slot \(actual.rawValue) was sent to \(expected.rawValue)."
    case .acceptanceStateUnavailable(let error):
      return error.localizedDescription
    case .unsafeMetadata(let error):
      return error.localizedDescription
    case .installationIdentifierMismatch(let expected, let actual):
      return "Configuration installation identifier is \(actual); expected \(expected)."
    case .staleConfiguration(
      let acceptedEpoch,
      let acceptedGeneration,
      let requestedEpoch,
      let requestedGeneration
    ):
      return "Configuration \(requestedEpoch)/\(requestedGeneration) is not newer than "
        + "accepted \(acceptedEpoch)/\(acceptedGeneration)."
    case .io(let operation, let code):
      return "Configuration operation \(operation) failed with errno \(code)."
    }
  }
}

public struct AppGroupConfigurationStore: Sendable {
  private let rootURL: URL

  public init(appGroupIdentifier: String) throws {
    guard
      let containerURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: appGroupIdentifier
      )
    else {
      throw ConfigurationStoreError.appGroupUnavailable(appGroupIdentifier)
    }
    rootURL = containerURL.appendingPathComponent("Configurations", isDirectory: true)
  }

  public init(testingRootURL: URL) {
    rootURL = testingRootURL
  }

  public func persist(
    _ configuration: Data,
    slot: ConfigurationSlot,
    tunnelOptions: TunnelNetworkOptions?,
    credentialAudience: CredentialAudience,
    installationID: UUID,
    epoch: UInt64,
    generation: UInt64
  ) throws -> ConfigurationDescriptor {
    let descriptor = try ConfigurationDescriptor(
      slot: slot,
      tunnelOptions: tunnelOptions,
      credentialAudience: credentialAudience,
      installationID: installationID,
      epoch: epoch,
      generation: generation,
      byteCount: UInt64(configuration.count),
      sha256: digest(configuration)
    )
    try persist(configuration, descriptor: descriptor)
    return descriptor
  }

  /// Persists a host-validated configuration for non-production callers that
  /// explicitly require durable storage. The Release System Proxy path sends
  /// secret-bearing runtime bytes over authenticated XPC and never calls this
  /// method.
  ///
  /// This storage is deliberately not used by the root-owned Packet Tunnel
  /// system extension because macOS does not guarantee that both execution
  /// contexts resolve an App Group identifier to the same inode.
  public func persist(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws {
    try validate(configuration, descriptor: descriptor)
    let directoryFD = try createAndOpenDirectory()
    defer { Darwin.close(directoryFD) }
    try atomicWrite(
      configuration,
      fileName: descriptor.slot.fileName,
      directoryFD: directoryFD
    )
  }

  public func load(_ descriptor: ConfigurationDescriptor) throws -> Data {
    let directoryFD = try openDirectory()
    defer { Darwin.close(directoryFD) }

    let fileFD: Int32
    do {
      fileFD = try SecureAppGroupFileSystem.openPrivateRegularFile(
        in: directoryFD,
        named: descriptor.slot.fileName,
        flags: O_RDONLY
      )
    } catch let error as AppGroupFileSecurityError {
      throw ConfigurationStoreError.unsafeMetadata(error)
    }
    defer { Darwin.close(fileFD) }

    var metadata = stat()
    guard fstat(fileFD, &metadata) == 0 else {
      throw ConfigurationStoreError.io(operation: "fstat", code: errno)
    }
    guard metadata.st_size >= 0 else {
      throw ConfigurationStoreError.invalidFileType
    }

    let actualByteCount = UInt64(metadata.st_size)
    guard actualByteCount <= NativeProtocolConstants.maximumConfigurationBytes else {
      throw ConfigurationStoreError.fileTooLarge(
        actual: actualByteCount,
        maximum: NativeProtocolConstants.maximumConfigurationBytes
      )
    }
    guard actualByteCount == descriptor.byteCount else {
      throw ConfigurationStoreError.byteCountMismatch(
        expected: descriptor.byteCount,
        actual: actualByteCount
      )
    }

    var data = Data(count: Int(actualByteCount))
    try data.withUnsafeMutableBytes { buffer in
      guard let baseAddress = buffer.baseAddress else {
        return
      }
      var offset = 0
      while offset < buffer.count {
        let count = Darwin.read(fileFD, baseAddress.advanced(by: offset), buffer.count - offset)
        if count < 0, errno == EINTR {
          continue
        }
        guard count > 0 else {
          throw ConfigurationStoreError.io(
            operation: count == 0 ? "unexpected-eof" : "read",
            code: count == 0 ? 0 : errno
          )
        }
        offset += count
      }
    }

    let actualDigest = digest(data)
    guard actualDigest == descriptor.sha256 else {
      throw ConfigurationStoreError.digestMismatch(
        expected: descriptor.sha256.hex,
        actual: actualDigest.hex
      )
    }
    try validateJSONObject(data)
    return data
  }

  private func atomicWrite(_ data: Data, fileName: String, directoryFD: Int32) throws {
    let temporaryName = ".\(fileName).\(UUID().uuidString).tmp"
    let temporaryFD: Int32
    do {
      temporaryFD = try SecureAppGroupFileSystem.createPrivateRegularFile(
        in: directoryFD,
        named: temporaryName,
        flags: O_WRONLY
      )
    } catch let error as AppGroupFileSecurityError {
      throw ConfigurationStoreError.unsafeMetadata(error)
    }

    var committed = false
    defer { Darwin.close(temporaryFD) }
    do {
      try data.withUnsafeBytes { buffer in
        guard let baseAddress = buffer.baseAddress else {
          return
        }
        var offset = 0
        while offset < buffer.count {
          let count = Darwin.write(
            temporaryFD,
            baseAddress.advanced(by: offset),
            buffer.count - offset
          )
          if count < 0, errno == EINTR {
            continue
          }
          guard count > 0 else {
            throw ConfigurationStoreError.io(operation: "write", code: errno)
          }
          offset += count
        }
      }

      guard fsync(temporaryFD) == 0 else {
        throw ConfigurationStoreError.io(operation: "fsync-file", code: errno)
      }
      guard renameat(directoryFD, temporaryName, directoryFD, fileName) == 0 else {
        throw ConfigurationStoreError.io(operation: "renameat", code: errno)
      }
      committed = true
      guard fsync(directoryFD) == 0 else {
        throw ConfigurationStoreError.io(operation: "fsync-directory", code: errno)
      }
    } catch {
      let originalError = error
      if !committed, unlinkat(directoryFD, temporaryName, 0) != 0 {
        throw ConfigurationStoreError.io(
          operation: "cleanup-temporary-after-\(String(describing: originalError))",
          code: errno
        )
      }
      throw originalError
    }
  }

  private func openDirectory() throws -> Int32 {
    do {
      return try SecureAppGroupFileSystem.openPrivateDirectory(at: rootURL)
    } catch let error as AppGroupFileSecurityError {
      throw ConfigurationStoreError.unsafeMetadata(error)
    }
  }

  private func createAndOpenDirectory() throws -> Int32 {
    do {
      return try SecureAppGroupFileSystem.createAndOpenPrivateDirectory(at: rootURL)
    } catch let error as AppGroupFileSecurityError {
      throw ConfigurationStoreError.unsafeMetadata(error)
    }
  }

  private func digest(_ data: Data) -> SHA256Digest {
    let value = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    // CryptoKit always emits exactly 32 bytes and lowercase formatting is fixed.
    // Preserve the checked public initializer at untrusted decode boundaries.
    return SHA256Digest(validatedHex: value)
  }

  private func validate(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws {
    do {
      try descriptor.validateConfigurationBytes(configuration)
    } catch let error as ConfigurationBytesValidationError {
      switch error {
      case .empty:
        throw ConfigurationStoreError.fileTooLarge(
          actual: 0,
          maximum: NativeProtocolConstants.maximumConfigurationBytes)
      case .tooLarge(let actual, let maximum):
        throw ConfigurationStoreError.fileTooLarge(actual: actual, maximum: maximum)
      case .byteCountMismatch(let expected, let actual):
        throw ConfigurationStoreError.byteCountMismatch(expected: expected, actual: actual)
      case .digestMismatch(let expected, let actual):
        throw ConfigurationStoreError.digestMismatch(expected: expected, actual: actual)
      case .invalidJSON:
        throw ConfigurationStoreError.invalidJSON
      }
    }
  }

  private func validateJSONObject(_ data: Data) throws {
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: data, options: [])
    } catch {
      throw ConfigurationStoreError.invalidJSON
    }
    guard value is [String: Any] else {
      throw ConfigurationStoreError.invalidJSON
    }
  }
}
