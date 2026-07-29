import CryptoKit
import Foundation

public enum NativeProtocolConstants {
  public static let schemaVersion: UInt16 = 4
  public static let maximumMessageBytes = 1_048_576
  public static let maximumConfigurationBytes: UInt64 = 384 * 1_024
  public static let maximumFailureMessageBytes = 1_024
  public static let tunnelStartPayloadOptionKey = "cfw.tunnel-start-payload-v1"
  /// The sole `startVPNTunnel(options:)` key in the production ticket-only path.
  /// Its value is the bounded, opaque 32-byte Authority start ticket and carries
  /// no configuration or credential bytes.
  public static let tunnelStartTicketOptionKey = "cfw.tunnel-start-ticket-v1"
}

public enum ProtocolValidationError: Error, Equatable, Sendable {
  case unsupportedSchemaVersion(UInt16)
  case invalidRequestIdentifier
  case invalidEpoch
  case invalidGeneration
  case invalidByteCount
  case invalidDigest
  case invalidTunnelOptions
  case invalidState
  case invalidCommand
  case invalidResponse
  case messageTooLarge(actual: Int, maximum: Int)
}

public enum ConfigurationBytesValidationError: Error, Equatable, Sendable {
  case empty
  case tooLarge(actual: UInt64, maximum: UInt64)
  case byteCountMismatch(expected: UInt64, actual: UInt64)
  case digestMismatch(expected: String, actual: String)
  case invalidJSON
}

public struct RequestID: Codable, Hashable, Sendable {
  public let rawValue: UUID

  public init() {
    rawValue = UUID()
  }

  public init(rawValue: UUID) {
    self.rawValue = rawValue
  }
}

public enum EngineMode: String, Codable, CaseIterable, Sendable {
  case off
  case systemProxy
  case tunnel
}

public enum EngineStateKind: String, Codable, CaseIterable, Sendable {
  case off
  case proxyStarting
  case proxyActive
  case proxyStopping
  case tunnelInstalling
  case awaitingApproval
  case tunnelStarting
  case tunnelActive
  case tunnelStopping
  case failed
}

public struct EngineFailure: Codable, Equatable, Sendable {
  public let code: String
  public let message: String
  public let isRetryable: Bool

  public init(code: String, message: String, isRetryable: Bool) {
    self.code = code
    self.message = message
    self.isRetryable = isRetryable
  }

  private enum CodingKeys: String, CodingKey {
    case code
    case message
    case isRetryable
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let code = try container.decode(String.self, forKey: .code)
    let message = try container.decode(String.self, forKey: .message)
    guard Self.isValidCode(code), Self.isValidMessage(message) else {
      throw ProtocolValidationError.invalidResponse
    }
    self.code = code
    self.message = message
    isRetryable = try container.decode(Bool.self, forKey: .isRetryable)
  }

  public func encode(to encoder: Encoder) throws {
    guard Self.isValidCode(code), Self.isValidMessage(message) else {
      throw ProtocolValidationError.invalidResponse
    }
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(code, forKey: .code)
    try container.encode(message, forKey: .message)
    try container.encode(isRetryable, forKey: .isRetryable)
  }

  private static func isValidCode(_ code: String) -> Bool {
    !code.isEmpty && code.utf8.count <= 64
      && code.utf8.allSatisfy {
        (97...122).contains($0) || (48...57).contains($0) || $0 == 45
      }
  }

  private static func isValidMessage(_ message: String) -> Bool {
    !message.isEmpty
      && message.utf8.count <= NativeProtocolConstants.maximumFailureMessageBytes
      && !message.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0)
      }
  }
}

public struct EngineState: Codable, Equatable, Sendable {
  public let kind: EngineStateKind
  public let failure: EngineFailure?

  public init(kind: EngineStateKind, failure: EngineFailure? = nil) throws {
    guard (kind == .failed) == (failure != nil) else {
      throw ProtocolValidationError.invalidState
    }
    self.kind = kind
    self.failure = failure
  }

  fileprivate init(validatedKind kind: EngineStateKind, failure: EngineFailure?) {
    self.kind = kind
    self.failure = failure
  }

  public static let off = EngineState(validatedKind: .off, failure: nil)

  public static func failed(_ failure: EngineFailure) -> EngineState {
    EngineState(validatedKind: .failed, failure: failure)
  }

  private enum CodingKeys: String, CodingKey {
    case kind
    case failure
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let kind = try container.decode(EngineStateKind.self, forKey: .kind)
    let failure = try container.decodeIfPresent(EngineFailure.self, forKey: .failure)
    try self.init(kind: kind, failure: failure)
  }
}

public enum ConfigurationSlot: String, Codable, CaseIterable, Sendable {
  case systemProxy
  case tunnel

  public var fileName: String {
    switch self {
    case .systemProxy:
      "system-proxy-config.json"
    case .tunnel:
      "tunnel-config.json"
    }
  }
}

public struct TunnelNetworkOptions: Codable, Equatable, Sendable {
  public static let minimumMTU: UInt16 = 1_280
  public static let maximumMTU: UInt16 = 1_500

  public let ipv6Enabled: Bool
  public let bypassPrivateNetworks: Bool
  public let mtu: UInt16

  public init(
    ipv6Enabled: Bool,
    bypassPrivateNetworks: Bool = true,
    mtu: UInt16 = 1_500
  ) throws {
    guard mtu >= Self.minimumMTU, mtu <= Self.maximumMTU else {
      throw ProtocolValidationError.invalidTunnelOptions
    }
    self.ipv6Enabled = ipv6Enabled
    self.bypassPrivateNetworks = bypassPrivateNetworks
    self.mtu = mtu
  }

  private enum CodingKeys: String, CodingKey {
    case ipv6Enabled = "ipv6_enabled"
    case bypassPrivateNetworks = "bypass_private_networks"
    case mtu
  }
}

public struct SHA256Digest: Codable, Hashable, Sendable {
  public let hex: String

  public init(hex: String) throws {
    guard hex == hex.lowercased(), hex.utf8.count == 64,
      hex.utf8.allSatisfy({ byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      })
    else {
      throw ProtocolValidationError.invalidDigest
    }
    self.hex = hex
  }

  init(validatedHex: String) {
    hex = validatedHex
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    try self.init(hex: container.decode(String.self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(hex)
  }
}

public struct ConfigurationDescriptor: Codable, Equatable, Sendable {
  public let slot: ConfigurationSlot
  public let tunnelOptions: TunnelNetworkOptions?
  public let credentialAudience: CredentialAudience
  public let installationID: UUID
  public let epoch: UInt64
  public let generation: UInt64
  public let byteCount: UInt64
  public let sha256: SHA256Digest
  /// Product identity digest covering the exact bounded runtime configuration,
  /// credential-slot references, mode, and mode-specific network options.
  /// This is intentionally distinct from `sha256`, which authenticates the
  /// exact in-memory runtime configuration bytes.
  public let identitySHA256: SHA256Digest
  /// Secret-free, closed injection instructions bound by identitySHA256.
  public let credentialSlots: [CredentialSlot]

  public init(
    slot: ConfigurationSlot,
    tunnelOptions: TunnelNetworkOptions?,
    credentialAudience: CredentialAudience,
    installationID: UUID,
    epoch: UInt64,
    generation: UInt64,
    byteCount: UInt64,
    sha256: SHA256Digest,
    identitySHA256: SHA256Digest? = nil,
    credentialSlots: [CredentialSlot] = []
  ) throws {
    guard (slot == .tunnel) == (tunnelOptions != nil) else {
      throw ProtocolValidationError.invalidTunnelOptions
    }
    guard epoch > 0 else {
      throw ProtocolValidationError.invalidEpoch
    }
    guard generation > 0 else {
      throw ProtocolValidationError.invalidGeneration
    }
    guard byteCount > 0, byteCount <= NativeProtocolConstants.maximumConfigurationBytes else {
      throw ProtocolValidationError.invalidByteCount
    }
    self.slot = slot
    self.tunnelOptions = tunnelOptions
    self.credentialAudience = credentialAudience
    self.installationID = installationID
    self.epoch = epoch
    self.generation = generation
    self.byteCount = byteCount
    self.sha256 = sha256
    self.identitySHA256 = identitySHA256 ?? sha256
    guard credentialSlots.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw ProtocolValidationError.invalidDigest
    }
    self.credentialSlots = credentialSlots
  }

  private enum CodingKeys: String, CodingKey {
    case slot
    case tunnelOptions
    case credentialAudience
    case installationID
    case epoch
    case generation
    case byteCount
    case sha256
    case identitySHA256
    case credentialSlots
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      slot: container.decode(ConfigurationSlot.self, forKey: .slot),
      tunnelOptions: container.decodeIfPresent(
        TunnelNetworkOptions.self,
        forKey: .tunnelOptions
      ),
      credentialAudience: container.decode(
        CredentialAudience.self,
        forKey: .credentialAudience
      ),
      installationID: container.decode(UUID.self, forKey: .installationID),
      epoch: container.decode(UInt64.self, forKey: .epoch),
      generation: container.decode(UInt64.self, forKey: .generation),
      byteCount: container.decode(UInt64.self, forKey: .byteCount),
      sha256: container.decode(SHA256Digest.self, forKey: .sha256),
      identitySHA256: container.decode(SHA256Digest.self, forKey: .identitySHA256),
      credentialSlots: container.decode([CredentialSlot].self, forKey: .credentialSlots)
    )
  }
}

extension ConfigurationDescriptor {
  /// Validates one bounded in-memory configuration against the exact descriptor
  /// before it crosses an engine-owner boundary. This function performs no I/O
  /// and never logs or returns the configuration bytes.
  public func validateConfigurationBytes(_ configuration: Data) throws {
    guard !configuration.isEmpty else {
      throw ConfigurationBytesValidationError.empty
    }
    guard UInt64(configuration.count) <= NativeProtocolConstants.maximumConfigurationBytes else {
      throw ConfigurationBytesValidationError.tooLarge(
        actual: UInt64(configuration.count),
        maximum: NativeProtocolConstants.maximumConfigurationBytes
      )
    }
    let actualByteCount = UInt64(configuration.count)
    guard byteCount == actualByteCount else {
      throw ConfigurationBytesValidationError.byteCountMismatch(
        expected: byteCount,
        actual: actualByteCount
      )
    }
    let actualDigest = SHA256.hash(data: configuration)
      .map { String(format: "%02x", $0) }
      .joined()
    guard sha256.hex == actualDigest else {
      throw ConfigurationBytesValidationError.digestMismatch(
        expected: sha256.hex,
        actual: actualDigest
      )
    }
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: configuration, options: [])
    } catch {
      throw ConfigurationBytesValidationError.invalidJSON
    }
    guard value is [String: Any] else {
      throw ConfigurationBytesValidationError.invalidJSON
    }
  }
}

public struct EngineSnapshot: Codable, Equatable, Sendable {
  public let mode: EngineMode
  public let state: EngineState
  public let configuration: ConfigurationDescriptor?
  public let sequence: UInt64

  public init(
    mode: EngineMode,
    state: EngineState,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) throws {
    switch (mode, state.kind, configuration) {
    case (.off, .off, nil),
      (.off, .failed, _),
      (.systemProxy, .proxyStarting, .some),
      (.systemProxy, .proxyActive, .some),
      (.systemProxy, .proxyStopping, .some),
      (.systemProxy, .failed, _),
      (.tunnel, .tunnelInstalling, _),
      (.tunnel, .awaitingApproval, _),
      (.tunnel, .tunnelStarting, .some),
      (.tunnel, .tunnelActive, .some),
      (.tunnel, .tunnelStopping, .some),
      (.tunnel, .failed, _):
      break
    default:
      throw ProtocolValidationError.invalidState
    }
    self.mode = mode
    self.state = state
    self.configuration = configuration
    self.sequence = sequence
  }

  private init(
    validatedMode mode: EngineMode,
    state: EngineState,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) {
    self.mode = mode
    self.state = state
    self.configuration = configuration
    self.sequence = sequence
  }

  private enum CodingKeys: String, CodingKey {
    case mode
    case state
    case configuration
    case sequence
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      mode: container.decode(EngineMode.self, forKey: .mode),
      state: container.decode(EngineState.self, forKey: .state),
      configuration: container.decodeIfPresent(
        ConfigurationDescriptor.self, forKey: .configuration),
      sequence: container.decode(UInt64.self, forKey: .sequence)
    )
  }

  public static let off = EngineSnapshot(
    validatedMode: .off,
    state: .off,
    configuration: nil,
    sequence: 0
  )

  public static func off(sequence: UInt64) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .off,
      state: .off,
      configuration: nil,
      sequence: sequence
    )
  }

  public static func proxyFailed(
    _ failure: EngineFailure,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .systemProxy,
      state: .failed(failure),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func proxyStarting(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .systemProxy,
      state: EngineState(validatedKind: .proxyStarting, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func proxyActive(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .systemProxy,
      state: EngineState(validatedKind: .proxyActive, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func proxyStopping(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .systemProxy,
      state: EngineState(validatedKind: .proxyStopping, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelStarting(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: EngineState(validatedKind: .tunnelStarting, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelActive(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: EngineState(validatedKind: .tunnelActive, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelStopping(
    configuration: ConfigurationDescriptor,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: EngineState(validatedKind: .tunnelStopping, failure: nil),
      configuration: configuration,
      sequence: sequence
    )
  }

  public static func tunnelFailed(
    _ failure: EngineFailure,
    configuration: ConfigurationDescriptor?,
    sequence: UInt64
  ) -> EngineSnapshot {
    EngineSnapshot(
      validatedMode: .tunnel,
      state: .failed(failure),
      configuration: configuration,
      sequence: sequence
    )
  }
}

public enum NativeCommandKind: String, Codable, Sendable {
  case installTunnel
  case startSystemProxy
  case startTunnel
  case validateConfiguration
  case stop
  case snapshot
}

public struct NativeCommand: Codable, Equatable, Sendable {
  public let kind: NativeCommandKind
  public let configuration: ConfigurationDescriptor?

  public init(
    kind: NativeCommandKind,
    configuration: ConfigurationDescriptor? = nil
  ) throws {
    let requiresConfiguration =
      kind == .startSystemProxy || kind == .startTunnel || kind == .validateConfiguration
      || kind == .stop
    guard requiresConfiguration == (configuration != nil) else {
      throw ProtocolValidationError.invalidCommand
    }
    if kind == .startSystemProxy, configuration?.slot != .systemProxy {
      throw ProtocolValidationError.invalidCommand
    }
    if kind == .startTunnel, configuration?.slot != .tunnel {
      throw ProtocolValidationError.invalidCommand
    }
    self.kind = kind
    self.configuration = configuration
  }

  private enum CodingKeys: String, CodingKey {
    case kind
    case configuration
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      kind: container.decode(NativeCommandKind.self, forKey: .kind),
      configuration: container.decodeIfPresent(
        ConfigurationDescriptor.self, forKey: .configuration)
    )
  }
}

public struct RequestEnvelope: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let requestID: RequestID
  public let command: NativeCommand

  public init(requestID: RequestID = RequestID(), command: NativeCommand) {
    schemaVersion = NativeProtocolConstants.schemaVersion
    self.requestID = requestID
    self.command = command
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case requestID
    case command
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let schemaVersion = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard schemaVersion == NativeProtocolConstants.schemaVersion else {
      throw ProtocolValidationError.unsupportedSchemaVersion(schemaVersion)
    }
    self.schemaVersion = schemaVersion
    requestID = try container.decode(RequestID.self, forKey: .requestID)
    command = try container.decode(NativeCommand.self, forKey: .command)
  }
}

public enum CommandResultKind: String, Codable, Sendable {
  case accepted
  case snapshot
}

public struct CommandResult: Codable, Equatable, Sendable {
  public let kind: CommandResultKind
  public let snapshot: EngineSnapshot?

  public init(kind: CommandResultKind, snapshot: EngineSnapshot? = nil) throws {
    guard (kind == .snapshot) == (snapshot != nil) else {
      throw ProtocolValidationError.invalidResponse
    }
    self.kind = kind
    self.snapshot = snapshot
  }

  private enum CodingKeys: String, CodingKey {
    case kind
    case snapshot
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      kind: container.decode(CommandResultKind.self, forKey: .kind),
      snapshot: container.decodeIfPresent(EngineSnapshot.self, forKey: .snapshot)
    )
  }
}

public struct ResponseEnvelope: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let requestID: RequestID
  public let result: CommandResult?
  public let failure: EngineFailure?

  public init(requestID: RequestID, result: CommandResult) {
    schemaVersion = NativeProtocolConstants.schemaVersion
    self.requestID = requestID
    self.result = result
    failure = nil
  }

  public init(requestID: RequestID, failure: EngineFailure) {
    schemaVersion = NativeProtocolConstants.schemaVersion
    self.requestID = requestID
    result = nil
    self.failure = failure
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case requestID
    case result
    case failure
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let schemaVersion = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard schemaVersion == NativeProtocolConstants.schemaVersion else {
      throw ProtocolValidationError.unsupportedSchemaVersion(schemaVersion)
    }
    let result = try container.decodeIfPresent(CommandResult.self, forKey: .result)
    let failure = try container.decodeIfPresent(EngineFailure.self, forKey: .failure)
    guard (result != nil) != (failure != nil) else {
      throw ProtocolValidationError.invalidResponse
    }
    self.schemaVersion = schemaVersion
    requestID = try container.decode(RequestID.self, forKey: .requestID)
    self.result = result
    self.failure = failure
  }
}

public enum ProtocolCodec {
  public static func encode(_ envelope: RequestEnvelope) throws -> Data {
    try encodeChecked(envelope)
  }

  public static func encode(_ envelope: ResponseEnvelope) throws -> Data {
    try encodeChecked(envelope)
  }

  public static func decodeRequest(_ data: Data) throws -> RequestEnvelope {
    try decodeChecked(RequestEnvelope.self, from: data)
  }

  public static func decodeResponse(_ data: Data) throws -> ResponseEnvelope {
    try decodeChecked(ResponseEnvelope.self, from: data)
  }

  private static func encodeChecked<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(value)
    try validateSize(data)
    return data
  }

  private static func decodeChecked<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    try validateSize(data)
    return try JSONDecoder().decode(type, from: data)
  }

  private static func validateSize(_ data: Data) throws {
    guard data.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw ProtocolValidationError.messageTooLarge(
        actual: data.count,
        maximum: NativeProtocolConstants.maximumMessageBytes
      )
    }
  }
}
