import Darwin
import Foundation

private struct SandboxAcceptedConfigurationCursor: Codable, Equatable, Sendable {
  let installationID: UUID
  let epoch: UInt64
  let generation: UInt64
}

/// Persistent replay protection owned solely by the sandboxed Packet Tunnel
/// system extension. No App Group or shared Keychain assumption crosses the
/// root/user execution-context boundary.
public struct SandboxConfigurationAcceptanceStore: Sendable {
  private static let maximumCursorBytes = 4_096
  private let rootURL: URL

  public init() throws {
    guard
      let applicationSupport = FileManager.default.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
      ).first
    else {
      throw ConfigurationStoreError.io(operation: "resolve-sandbox-container", code: ENOENT)
    }
    rootURL = applicationSupport.appendingPathComponent("ProviderState", isDirectory: true)
  }

  init(testingRootURL: URL) {
    rootURL = testingRootURL
  }

  public func accept(_ descriptor: ConfigurationDescriptor) throws {
    guard descriptor.slot == .tunnel else {
      throw ConfigurationStoreError.unexpectedAcceptanceSlot(
        expected: .tunnel,
        actual: descriptor.slot
      )
    }
    let directoryFD: Int32
    do {
      directoryFD = try SecureAppGroupFileSystem.createAndOpenPrivateDirectory(at: rootURL)
    } catch let error as AppGroupFileSecurityError {
      throw ConfigurationStoreError.unsafeMetadata(error)
    }
    defer { Darwin.close(directoryFD) }
    guard flock(directoryFD, LOCK_EX) == 0 else {
      throw ConfigurationStoreError.io(operation: "lock-sandbox-acceptance", code: errno)
    }

    if let cursor = try loadCursor(directoryFD: directoryFD) {
      guard cursor.installationID == descriptor.installationID else {
        throw ConfigurationStoreError.installationIdentifierMismatch(
          expected: cursor.installationID,
          actual: descriptor.installationID
        )
      }
      let isNewer =
        descriptor.epoch > cursor.epoch
        || (descriptor.epoch == cursor.epoch && descriptor.generation > cursor.generation)
      guard isNewer else {
        throw ConfigurationStoreError.staleConfiguration(
          acceptedEpoch: cursor.epoch,
          acceptedGeneration: cursor.generation,
          requestedEpoch: descriptor.epoch,
          requestedGeneration: descriptor.generation
        )
      }
    }

    let data = try canonicalData(
      SandboxAcceptedConfigurationCursor(
        installationID: descriptor.installationID,
        epoch: descriptor.epoch,
        generation: descriptor.generation
      )
    )
    try atomicWrite(data, directoryFD: directoryFD)
  }

  private func loadCursor(directoryFD: Int32) throws
    -> SandboxAcceptedConfigurationCursor?
  {
    let descriptor: Int32
    do {
      descriptor = try SecureAppGroupFileSystem.openPrivateRegularFile(
        in: directoryFD,
        named: "accepted.json",
        flags: O_RDONLY
      )
    } catch AppGroupFileSecurityError.io(let operation, let code)
      where operation == "open-file" && code == ENOENT
    {
      return nil
    } catch let error as AppGroupFileSecurityError {
      throw ConfigurationStoreError.unsafeMetadata(error)
    }
    defer { Darwin.close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0, metadata.st_size > 0,
      metadata.st_size <= Self.maximumCursorBytes
    else {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    var data = Data(count: Int(metadata.st_size))
    try data.withUnsafeMutableBytes { bytes in
      guard let baseAddress = bytes.baseAddress else { return }
      var offset = 0
      while offset < bytes.count {
        let count = Darwin.read(
          descriptor,
          baseAddress.advanced(by: offset),
          bytes.count - offset
        )
        if count < 0, errno == EINTR { continue }
        guard count > 0 else {
          throw ConfigurationStoreError.io(
            operation: count == 0 ? "unexpected-eof-acceptance" : "read-acceptance",
            code: count == 0 ? 0 : errno
          )
        }
        offset += count
      }
    }
    let cursor: SandboxAcceptedConfigurationCursor
    do {
      cursor = try JSONDecoder().decode(SandboxAcceptedConfigurationCursor.self, from: data)
    } catch {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    guard try canonicalData(cursor) == data else {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    return cursor
  }

  private func atomicWrite(_ data: Data, directoryFD: Int32) throws {
    let temporaryName = ".accepted.\(UUID().uuidString).tmp"
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
    var renamed = false
    defer { Darwin.close(temporaryFD) }
    do {
      try data.withUnsafeBytes { bytes in
        guard let baseAddress = bytes.baseAddress else { return }
        var offset = 0
        while offset < bytes.count {
          let count = Darwin.write(
            temporaryFD,
            baseAddress.advanced(by: offset),
            bytes.count - offset
          )
          if count < 0, errno == EINTR { continue }
          guard count > 0 else {
            throw ConfigurationStoreError.io(operation: "write-acceptance", code: errno)
          }
          offset += count
        }
      }
      guard fsync(temporaryFD) == 0 else {
        throw ConfigurationStoreError.io(operation: "fsync-acceptance", code: errno)
      }
      guard renameat(directoryFD, temporaryName, directoryFD, "accepted.json") == 0 else {
        throw ConfigurationStoreError.io(operation: "rename-acceptance", code: errno)
      }
      renamed = true
      guard fsync(directoryFD) == 0 else {
        throw ConfigurationStoreError.io(operation: "fsync-acceptance-directory", code: errno)
      }
    } catch {
      let originalError = error
      if !renamed, unlinkat(directoryFD, temporaryName, 0) != 0 {
        throw ConfigurationStoreError.io(
          operation: "cleanup-acceptance-temporary",
          code: errno
        )
      }
      throw originalError
    }
  }

  private func canonicalData(_ cursor: SandboxAcceptedConfigurationCursor) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(cursor)
    guard !data.isEmpty, data.count <= Self.maximumCursorBytes else {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    return data
  }
}
