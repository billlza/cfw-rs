import Darwin
import Foundation

private struct AcceptedConfigurationCursor: Codable, Equatable, Sendable {
  let slot: ConfigurationSlot
  let installationID: UUID
  let epoch: UInt64
  let generation: UInt64
}

/// User-context engine-owner replay state. The authoritative cursor resides
/// in a slot-specific Data Protection Keychain item. This store is valid for
/// the ProxyAgent but must not be used by a Network Extension system extension,
/// which runs globally and has no Data Protection Keychain access.
public struct ConfigurationAcceptanceStore: Sendable {
  private static let maximumCursorBytes = 4_096
  private let rootURL: URL
  private let allowedSlot: ConfigurationSlot
  private let cursorStore: any JournalDataStoring

  public init(
    appGroupIdentifier: String,
    allowedSlot: ConfigurationSlot,
    keychainAccessGroup: String
  ) throws {
    guard
      let containerURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: appGroupIdentifier
      )
    else {
      throw ConfigurationStoreError.appGroupUnavailable(appGroupIdentifier)
    }
    rootURL = containerURL.appendingPathComponent("ProviderState", isDirectory: true)
    self.allowedSlot = allowedSlot
    do {
      cursorStore = try KeychainJournalDataStore(
        keychainAccessGroup: keychainAccessGroup,
        service: "com.bill.clashformac.configuration-acceptance",
        account: allowedSlot.rawValue,
        label: "Clash for Mac accepted configuration cursor"
      )
    } catch {
      throw ConfigurationStoreError.acceptanceStateUnavailable(error)
    }
  }

  init(
    testingRootURL: URL,
    allowedSlot: ConfigurationSlot,
    cursorStore: any JournalDataStoring
  ) {
    rootURL = testingRootURL
    self.allowedSlot = allowedSlot
    self.cursorStore = cursorStore
  }

  public func accept(_ descriptor: ConfigurationDescriptor) throws {
    guard descriptor.slot == allowedSlot else {
      throw ConfigurationStoreError.unexpectedAcceptanceSlot(
        expected: allowedSlot,
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
      throw ConfigurationStoreError.io(operation: "lock-acceptance-directory", code: errno)
    }

    if let cursor = try loadCursor() {
      guard cursor.slot == allowedSlot else {
        throw ConfigurationStoreError.malformedAcceptanceJournal
      }
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

    let cursor = AcceptedConfigurationCursor(
      slot: allowedSlot,
      installationID: descriptor.installationID,
      epoch: descriptor.epoch,
      generation: descriptor.generation
    )
    let data = try Self.canonicalData(cursor)
    do {
      try cursorStore.save(data)
    } catch {
      throw ConfigurationStoreError.acceptanceStateUnavailable(error)
    }
  }

  private func loadCursor() throws -> AcceptedConfigurationCursor? {
    let data: Data?
    do {
      data = try cursorStore.load()
    } catch {
      throw ConfigurationStoreError.acceptanceStateUnavailable(error)
    }
    guard let data else {
      return nil
    }
    guard !data.isEmpty, data.count <= Self.maximumCursorBytes else {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    let cursor: AcceptedConfigurationCursor
    do {
      cursor = try JSONDecoder().decode(AcceptedConfigurationCursor.self, from: data)
    } catch {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    guard try Self.canonicalData(cursor) == data else {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
    return cursor
  }

  private static func canonicalData(_ cursor: AcceptedConfigurationCursor) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do {
      let data = try encoder.encode(cursor)
      guard data.count <= Self.maximumCursorBytes else {
        throw ConfigurationStoreError.malformedAcceptanceJournal
      }
      return data
    } catch let error as ConfigurationStoreError {
      throw error
    } catch {
      throw ConfigurationStoreError.malformedAcceptanceJournal
    }
  }
}
