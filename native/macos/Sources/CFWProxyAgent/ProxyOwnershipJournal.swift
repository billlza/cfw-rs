import CFWSharedProtocol
import Foundation

enum SystemProxyField: String, Codable, CaseIterable, Comparable, Sendable {
  case httpEnabled = "HTTPEnable"
  case httpHost = "HTTPProxy"
  case httpPort = "HTTPPort"
  case httpsEnabled = "HTTPSEnable"
  case httpsHost = "HTTPSProxy"
  case httpsPort = "HTTPSPort"
  case socksEnabled = "SOCKSEnable"
  case socksHost = "SOCKSProxy"
  case socksPort = "SOCKSPort"
  case proxyAutoConfigEnabled = "ProxyAutoConfigEnable"
  case proxyAutoDiscoveryEnabled = "ProxyAutoDiscoveryEnable"

  static func < (lhs: SystemProxyField, rhs: SystemProxyField) -> Bool {
    lhs.rawValue < rhs.rawValue
  }

  var isEnableFlag: Bool {
    switch self {
    case .httpEnabled, .httpsEnabled, .socksEnabled, .proxyAutoConfigEnabled,
      .proxyAutoDiscoveryEnabled:
      return true
    default:
      return false
    }
  }

  func acceptsOriginalValue(_ value: ProxyPreferenceValue?) -> Bool {
    guard let value else {
      return true
    }
    switch (self, value) {
    case (.httpEnabled, .boolean), (.httpsEnabled, .boolean), (.socksEnabled, .boolean),
      (.proxyAutoConfigEnabled, .boolean), (.proxyAutoDiscoveryEnabled, .boolean):
      return true
    case (.httpEnabled, .integer(let value)),
      (.httpsEnabled, .integer(let value)),
      (.socksEnabled, .integer(let value)),
      (.proxyAutoConfigEnabled, .integer(let value)),
      (.proxyAutoDiscoveryEnabled, .integer(let value)):
      return value == 0 || value == 1
    case (.httpHost, .string), (.httpsHost, .string), (.socksHost, .string):
      return true
    case (.httpPort, .integer), (.httpsPort, .integer), (.socksPort, .integer):
      return true
    default:
      return false
    }
  }
}

enum ProxyPreferenceValue: Equatable, Sendable {
  case boolean(Bool)
  case integer(Int)
  case string(String)
}

extension ProxyPreferenceValue: Codable {
  private enum CodingKeys: String, CodingKey {
    case kind
    case boolean
    case integer
    case string
  }

  private enum Kind: String, Codable {
    case boolean
    case integer
    case string
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(Kind.self, forKey: .kind) {
    case .boolean:
      self = .boolean(try container.decode(Bool.self, forKey: .boolean))
    case .integer:
      self = .integer(try container.decode(Int.self, forKey: .integer))
    case .string:
      self = .string(try container.decode(String.self, forKey: .string))
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .boolean(let value):
      try container.encode(Kind.boolean, forKey: .kind)
      try container.encode(value, forKey: .boolean)
    case .integer(let value):
      try container.encode(Kind.integer, forKey: .kind)
      try container.encode(value, forKey: .integer)
    case .string(let value):
      try container.encode(Kind.string, forKey: .kind)
      try container.encode(value, forKey: .string)
    }
  }
}

struct OwnedSystemProxyField: Codable, Equatable, Sendable {
  let field: SystemProxyField
  let originalValue: ProxyPreferenceValue?
  let appliedValue: ProxyPreferenceValue
}

struct SystemProxyServiceOwnership: Codable, Equatable, Sendable {
  let serviceID: String
  let fields: [OwnedSystemProxyField]

  init(serviceID: String, fields: [OwnedSystemProxyField]) throws {
    guard !serviceID.isEmpty, !fields.isEmpty else {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    let names = fields.map(\.field)
    guard Set(names).count == names.count,
      Set(names) == Set(SystemProxyField.allCases),
      fields.allSatisfy({ $0.field.acceptsOriginalValue($0.originalValue) })
    else {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    self.serviceID = serviceID
    self.fields = fields.sorted { $0.field < $1.field }
  }
}

enum ProxyOwnershipJournalPhase: String, Codable, Sendable {
  case prepared
  case applied
}

struct ProxyOwnershipJournal: Codable, Equatable, Sendable {
  static let schemaVersion: UInt16 = 1

  let schemaVersion: UInt16
  let phase: ProxyOwnershipJournalPhase
  let configuration: ConfigurationDescriptor
  let services: [SystemProxyServiceOwnership]

  init(
    phase: ProxyOwnershipJournalPhase,
    configuration: ConfigurationDescriptor,
    services: [SystemProxyServiceOwnership]
  ) throws {
    guard configuration.slot == .systemProxy, !services.isEmpty else {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    let validatedServices = try services.map {
      try SystemProxyServiceOwnership(serviceID: $0.serviceID, fields: $0.fields)
    }
    let serviceIDs = validatedServices.map(\.serviceID)
    guard Set(serviceIDs).count == serviceIDs.count else {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    var expectedHost: String?
    var expectedPort: Int?
    for service in validatedServices {
      let values = Dictionary(
        uniqueKeysWithValues: service.fields.map { ($0.field, $0.appliedValue) })
      guard values[.httpEnabled] == .integer(1),
        values[.httpsEnabled] == .integer(1),
        values[.socksEnabled] == .integer(1),
        values[.proxyAutoConfigEnabled] == .integer(0),
        values[.proxyAutoDiscoveryEnabled] == .integer(0),
        case .some(.string(let httpHost)) = values[.httpHost],
        case .some(.string(let httpsHost)) = values[.httpsHost],
        case .some(.string(let socksHost)) = values[.socksHost],
        httpHost == "127.0.0.1",
        httpsHost == httpHost,
        socksHost == httpHost,
        case .some(.integer(let httpPort)) = values[.httpPort],
        case .some(.integer(let httpsPort)) = values[.httpsPort],
        case .some(.integer(let socksPort)) = values[.socksPort],
        (1...65_535).contains(httpPort),
        httpsPort == httpPort,
        socksPort == httpPort,
        expectedHost == nil || expectedHost == httpHost,
        expectedPort == nil || expectedPort == httpPort
      else {
        throw ProxyOwnershipJournalError.invalidJournal
      }
      expectedHost = httpHost
      expectedPort = httpPort
    }
    schemaVersion = Self.schemaVersion
    self.phase = phase
    self.configuration = configuration
    self.services = validatedServices.sorted { $0.serviceID < $1.serviceID }
  }

  func markingApplied() throws -> ProxyOwnershipJournal {
    try ProxyOwnershipJournal(
      phase: .applied,
      configuration: configuration,
      services: services
    )
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case phase
    case configuration
    case services
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let schemaVersion = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard schemaVersion == Self.schemaVersion else {
      throw ProxyOwnershipJournalError.unsupportedSchemaVersion(schemaVersion)
    }
    try self.init(
      phase: container.decode(ProxyOwnershipJournalPhase.self, forKey: .phase),
      configuration: container.decode(ConfigurationDescriptor.self, forKey: .configuration),
      services: container.decode([SystemProxyServiceOwnership].self, forKey: .services)
    )
  }
}

enum ProxyOwnershipConflictReason: Equatable, Sendable {
  case serviceMissing
  case proxyProtocolMissing
  case valueChanged(current: ProxyPreferenceValue?)
}

struct ProxyOwnershipConflict: Equatable, Sendable {
  let serviceID: String
  let field: SystemProxyField
  let reason: ProxyOwnershipConflictReason
}

struct ProxyRestoreResult: Equatable, Sendable {
  let conflicts: [ProxyOwnershipConflict]

  var isComplete: Bool {
    conflicts.isEmpty
  }
}

enum ProxyOwnershipJournalError: Error, Equatable, Sendable {
  case unsupportedSchemaVersion(UInt16)
  case authenticationUnavailable(JournalAuthenticationError)
  case nonCanonicalPayload
  case invalidJournal
  case journalTooLarge(actual: Int, maximum: Int)
}

extension ProxyOwnershipJournalError: LocalizedError {
  var errorDescription: String? {
    switch self {
    case .unsupportedSchemaVersion(let version):
      return "Proxy ownership journal schema \(version) is unsupported."
    case .authenticationUnavailable(let error):
      return "Proxy ownership journal Keychain access failed: \(error.localizedDescription)"
    case .nonCanonicalPayload:
      return "Proxy ownership journal payload is not canonical."
    case .invalidJournal:
      return "Proxy ownership journal is invalid."
    case .journalTooLarge(let actual, let maximum):
      return "Proxy ownership journal has \(actual) bytes; maximum is \(maximum)."
    }
  }
}

protocol ProxyOwnershipJournalStoring: Sendable {
  func load() throws -> ProxyOwnershipJournal?
  func save(_ journal: ProxyOwnershipJournal) throws
  func remove() throws
}

/// The ownership journal is a single Data Protection Keychain item. Keeping the
/// complete bounded journal in one authoritative item avoids cross-store commit
/// windows while retaining the prepared state needed to recover a crash that
/// occurs after system proxy preferences have changed.
struct KeychainProxyOwnershipJournalStore: ProxyOwnershipJournalStoring {
  private static let maximumBytes = 128 * 1_024
  private let dataStore: any JournalDataStoring

  init(keychainAccessGroup: String) throws {
    do {
      dataStore = try KeychainJournalDataStore(
        keychainAccessGroup: keychainAccessGroup,
        service: "com.bill.clashformac.proxy-ownership-journal",
        account: "canonical-journal-v1",
        label: "Clash for Mac system proxy ownership journal"
      )
    } catch {
      throw ProxyOwnershipJournalError.authenticationUnavailable(error)
    }
  }

  init(testingDataStore: any JournalDataStoring) {
    dataStore = testingDataStore
  }

  func load() throws -> ProxyOwnershipJournal? {
    let data: Data?
    do {
      data = try dataStore.load()
    } catch {
      throw ProxyOwnershipJournalError.authenticationUnavailable(error)
    }
    guard let data else {
      return nil
    }
    guard !data.isEmpty else {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    guard data.count <= Self.maximumBytes else {
      throw ProxyOwnershipJournalError.journalTooLarge(
        actual: data.count,
        maximum: Self.maximumBytes
      )
    }

    let journal: ProxyOwnershipJournal
    do {
      journal = try JSONDecoder().decode(ProxyOwnershipJournal.self, from: data)
    } catch let error as ProxyOwnershipJournalError {
      throw error
    } catch {
      throw ProxyOwnershipJournalError.invalidJournal
    }
    guard try Self.canonicalPayload(for: journal) == data else {
      throw ProxyOwnershipJournalError.nonCanonicalPayload
    }
    return journal
  }

  func save(_ journal: ProxyOwnershipJournal) throws {
    let data = try Self.canonicalPayload(for: journal)
    guard data.count <= Self.maximumBytes else {
      throw ProxyOwnershipJournalError.journalTooLarge(
        actual: data.count,
        maximum: Self.maximumBytes
      )
    }
    do {
      try dataStore.save(data)
    } catch {
      throw ProxyOwnershipJournalError.authenticationUnavailable(error)
    }
  }

  func remove() throws {
    do {
      try dataStore.remove()
    } catch {
      throw ProxyOwnershipJournalError.authenticationUnavailable(error)
    }
  }

  private static func canonicalPayload(for journal: ProxyOwnershipJournal) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do {
      return try encoder.encode(journal)
    } catch {
      throw ProxyOwnershipJournalError.invalidJournal
    }
  }
}
