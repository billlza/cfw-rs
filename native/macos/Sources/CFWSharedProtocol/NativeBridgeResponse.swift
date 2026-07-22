import Foundation

public struct NativeRequestEnvelope: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let requestID: UUID
  public let command: NativeBridgeCommand

  public init(requestID: UUID = UUID(), command: NativeBridgeCommand) {
    schemaVersion = NativeBridgeProtocolConstants.schemaVersion
    self.requestID = requestID
    self.command = command
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case requestID = "request_id"
    case command
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let version = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard version == NativeBridgeProtocolConstants.schemaVersion else {
      throw NativeBridgeProtocolError.unsupportedSchemaVersion(version)
    }
    schemaVersion = version
    requestID = try container.decode(UUID.self, forKey: .requestID)
    command = try container.decode(NativeBridgeCommand.self, forKey: .command)
  }
}

public enum NativeEngineOwner: String, Codable, Sendable {
  case proxyAgent = "proxy_agent"
  case packetTunnelSystemExtension = "packet_tunnel_system_extension"
}

public struct NativeRuntimeIdentity: Codable, Equatable, Sendable {
  public let owner: NativeEngineOwner
  public let context: EngineCommandContext
  public let configDigest: String
  public let ready: Bool

  public init(
    owner: NativeEngineOwner,
    context: EngineCommandContext,
    configDigest: SHA256Digest,
    ready: Bool
  ) {
    self.owner = owner
    self.context = context
    self.configDigest = configDigest.hex
    self.ready = ready
  }

  private enum CodingKeys: String, CodingKey {
    case owner
    case context
    case configDigest = "config_digest"
    case ready
  }
}

public enum NativeEngineStatus: Equatable, Sendable {
  case off
  case systemProxy(NativeRuntimeIdentity)
  case tunnel(NativeRuntimeIdentity)
}

extension NativeEngineStatus: Codable {
  private enum CodingKeys: String, CodingKey {
    case status
    case runtime
  }

  private enum Status: String, Codable {
    case off
    case systemProxy = "system_proxy"
    case tunnel
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(Status.self, forKey: .status) {
    case .off: self = .off
    case .systemProxy:
      self = .systemProxy(try container.decode(NativeRuntimeIdentity.self, forKey: .runtime))
    case .tunnel:
      self = .tunnel(try container.decode(NativeRuntimeIdentity.self, forKey: .runtime))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .off:
      try container.encode(Status.off, forKey: .status)
    case .systemProxy(let runtime):
      try container.encode(Status.systemProxy, forKey: .status)
      try container.encode(runtime, forKey: .runtime)
    case .tunnel(let runtime):
      try container.encode(Status.tunnel, forKey: .status)
      try container.encode(runtime, forKey: .runtime)
    }
  }
}

public enum NativeTunnelInstallOutcome: String, Codable, Sendable {
  case ready
  case awaitingApproval = "awaiting_approval"
}

public enum NativeBridgeErrorCode: String, Codable, Sendable {
  case busy
  case permissionDenied = "permission_denied"
  case approvalDenied = "approval_denied"
  case configurationRejected = "configuration_rejected"
  case credentialsUnavailable = "credentials_unavailable"
  case credentialConflict = "credential_conflict"
  case credentialVaultMissing = "credential_vault_missing"
  case credentialGCConflict = "credential_gc_conflict"
  case identityRejected = "identity_rejected"
  case timeout
  case unavailable
  case `internal`
}

public struct NativeBridgeFailure: Codable, Equatable, Sendable {
  public let code: NativeBridgeErrorCode
  public let message: String

  public init(code: NativeBridgeErrorCode, message: String) {
    self.code = code
    self.message = message
  }

  private enum CodingKeys: String, CodingKey {
    case code
    case message
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let code = try container.decode(NativeBridgeErrorCode.self, forKey: .code)
    let message = try container.decode(String.self, forKey: .message)
    guard Self.isValidMessage(message) else {
      throw NativeBridgeProtocolError.invalidResponse
    }
    self.code = code
    self.message = message
  }

  public func encode(to encoder: Encoder) throws {
    guard Self.isValidMessage(message) else {
      throw NativeBridgeProtocolError.invalidResponse
    }
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(code, forKey: .code)
    try container.encode(message, forKey: .message)
  }

  private static func isValidMessage(_ message: String) -> Bool {
    !message.isEmpty
      && message.utf8.count <= NativeBridgeProtocolConstants.maximumFailureMessageBytes
      && !message.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0)
      }
  }
}

public enum NativeBridgeResult: Equatable, Sendable {
  case status(NativeEngineStatus)
  case runtime(NativeRuntimeIdentity)
  case tunnelInstall(NativeTunnelInstallOutcome)
  case acknowledged
  case credentialReceipt(NativeCredentialReceipt)
  case credentialPresence([NativeCredentialPresence])
  case credentialGarbageCollectionPreview(CredentialGarbageCollectionPreview)
  case credentialGarbageCollectionReceipt(CredentialGarbageCollectionReceipt)
  case cutoverPreflight(CutoverPreflightOutcome)
}

extension NativeBridgeResult: Codable {
  private enum CodingKeys: String, CodingKey {
    case kind
    case value
  }

  private enum Kind: String, Codable {
    case status
    case runtime
    case tunnelInstall = "tunnel_install"
    case acknowledged
    case credentialReceipt = "credential_receipt"
    case credentialPresence = "credential_presence"
    case credentialGarbageCollectionPreview = "credential_garbage_collection_preview"
    case credentialGarbageCollectionReceipt = "credential_garbage_collection_receipt"
    case cutoverPreflight = "cutover_preflight"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(Kind.self, forKey: .kind) {
    case .status: self = .status(try container.decode(NativeEngineStatus.self, forKey: .value))
    case .runtime:
      self = .runtime(try container.decode(NativeRuntimeIdentity.self, forKey: .value))
    case .tunnelInstall:
      self = .tunnelInstall(
        try container.decode(NativeTunnelInstallOutcome.self, forKey: .value)
      )
    case .acknowledged: self = .acknowledged
    case .credentialReceipt:
      self = .credentialReceipt(
        try container.decode(NativeCredentialReceipt.self, forKey: .value)
      )
    case .credentialPresence:
      self = .credentialPresence(
        try container.decode([NativeCredentialPresence].self, forKey: .value)
      )
    case .credentialGarbageCollectionPreview:
      self = .credentialGarbageCollectionPreview(
        try container.decode(CredentialGarbageCollectionPreview.self, forKey: .value)
      )
    case .credentialGarbageCollectionReceipt:
      self = .credentialGarbageCollectionReceipt(
        try container.decode(CredentialGarbageCollectionReceipt.self, forKey: .value)
      )
    case .cutoverPreflight:
      self = .cutoverPreflight(
        try container.decode(CutoverPreflightOutcome.self, forKey: .value)
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .status(let status):
      try container.encode(Kind.status, forKey: .kind)
      try container.encode(status, forKey: .value)
    case .runtime(let runtime):
      try container.encode(Kind.runtime, forKey: .kind)
      try container.encode(runtime, forKey: .value)
    case .tunnelInstall(let outcome):
      try container.encode(Kind.tunnelInstall, forKey: .kind)
      try container.encode(outcome, forKey: .value)
    case .acknowledged:
      try container.encode(Kind.acknowledged, forKey: .kind)
    case .credentialReceipt(let receipt):
      try container.encode(Kind.credentialReceipt, forKey: .kind)
      try container.encode(receipt, forKey: .value)
    case .credentialPresence(let presence):
      try container.encode(Kind.credentialPresence, forKey: .kind)
      try container.encode(presence, forKey: .value)
    case .credentialGarbageCollectionPreview(let preview):
      try container.encode(Kind.credentialGarbageCollectionPreview, forKey: .kind)
      try container.encode(preview, forKey: .value)
    case .credentialGarbageCollectionReceipt(let receipt):
      try container.encode(Kind.credentialGarbageCollectionReceipt, forKey: .kind)
      try container.encode(receipt, forKey: .value)
    case .cutoverPreflight(let outcome):
      try container.encode(Kind.cutoverPreflight, forKey: .kind)
      try container.encode(outcome, forKey: .value)
    }
  }
}

public struct NativeResponseEnvelope: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let requestID: UUID?
  public let result: NativeBridgeResult?
  public let failure: NativeBridgeFailure?

  public init(requestID: UUID, result: NativeBridgeResult) {
    schemaVersion = NativeBridgeProtocolConstants.schemaVersion
    self.requestID = requestID
    self.result = result
    failure = nil
  }

  public init(requestID: UUID?, failure: NativeBridgeFailure) {
    schemaVersion = NativeBridgeProtocolConstants.schemaVersion
    self.requestID = requestID
    result = nil
    self.failure = failure
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case requestID = "request_id"
    case result
    case failure
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let version = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard version == NativeBridgeProtocolConstants.schemaVersion else {
      throw NativeBridgeProtocolError.unsupportedSchemaVersion(version)
    }
    let result = try container.decodeIfPresent(NativeBridgeResult.self, forKey: .result)
    let failure = try container.decodeIfPresent(NativeBridgeFailure.self, forKey: .failure)
    guard (result != nil) != (failure != nil) else {
      throw NativeBridgeProtocolError.invalidResponse
    }
    schemaVersion = version
    requestID = try container.decodeIfPresent(UUID.self, forKey: .requestID)
    self.result = result
    self.failure = failure
  }
}
