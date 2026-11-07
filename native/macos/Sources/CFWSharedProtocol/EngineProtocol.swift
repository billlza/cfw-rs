import Foundation

public enum NativeProtocolConstants {
  public static let schemaVersion: UInt16 = 7
  public static let maximumMessageBytes = EngineCapacity.maximumBridgeBytes
  public static let maximumConfigurationBytes: UInt64 = UInt64(
    EngineCapacity.maximumConfigurationBytes)
  public static let maximumFailureMessageBytes = 1_024
  public static let tunnelStartPayloadOptionKey = "cfw.tunnel-start-payload-v1"
  /// The sole `NETunnelProviderSession.startTunnel(options:)` key in the production ticket-only path.
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

public struct RequestID: Codable, Hashable, Sendable {
  public let rawValue: UUID

  public init() {
    rawValue = UUID()
  }

  public init(rawValue: UUID) {
    self.rawValue = rawValue
  }
}

public enum NativeCommandKind: String, Codable, Sendable {
  case installTunnel
  case startLocalProxy
  case startSystemProxy
  case startTunnel
  case validateConfiguration
  case stop
  /// Restores the System Proxy settings of the session the configuration
  /// names while its engine keeps running, before the Host orders its stop.
  case restoreSettingsBeforeStop
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
      kind == .startLocalProxy || kind == .startSystemProxy || kind == .startTunnel
      || kind == .validateConfiguration
      || kind == .stop || kind == .restoreSettingsBeforeStop
    guard requiresConfiguration == (configuration != nil) else {
      throw ProtocolValidationError.invalidCommand
    }
    if kind == .startSystemProxy || kind == .restoreSettingsBeforeStop,
      configuration?.slot != .systemProxy
    {
      throw ProtocolValidationError.invalidCommand
    }
    if kind == .startLocalProxy, configuration?.slot != .localProxy {
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
