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

public enum NativeBridgeErrorCode: String, Codable, CaseIterable, Sendable {
  case busy
  case resourceExhausted = "resource_exhausted"
  case journalCapacityExhausted = "journal_capacity_exhausted"
  case permissionDenied = "permission_denied"
  case approvalDenied = "approval_denied"
  case configurationRejected = "configuration_rejected"
  case mixedEndpointInUse = "mixed_endpoint_in_use"
  case controllerEndpointInUse = "controller_endpoint_in_use"
  case credentialsUnavailable = "credentials_unavailable"
  case credentialConflict = "credential_conflict"
  case credentialVaultMissing = "credential_vault_missing"
  case credentialVaultCorrupt = "credential_vault_corrupt"
  case credentialMigrationRequired = "credential_migration_required"
  case credentialGCConflict = "credential_gc_conflict"
  case proxyAgentApprovalRequired = "proxy_agent_approval_required"
  case globalAuthorityUnavailable = "global_authority_unavailable"
  case globalAuthorityRegistrationRequired = "global_authority_registration_required"
  case globalAuthorityApprovalRequired = "global_authority_approval_required"
  case globalAuthorityIdentityRejected = "global_authority_identity_rejected"
  case globalAuthorityProtocolMismatch = "global_authority_protocol_mismatch"
  case globalAuthorityRecovering = "global_authority_recovering"
  case globalAuthorityTimeout = "global_authority_timeout"
  case globalAuthorityInterrupted = "global_authority_interrupted"
  case globalLeaseConflict = "global_lease_conflict"
  case replayRejected = "replay_rejected"
  case staleOperation = "stale_operation"
  case ticketExpired = "ticket_expired"
  case ticketAlreadyRedeemed = "ticket_already_redeemed"
  case ticketInvalid = "ticket_invalid"
  case compensationConflict = "compensation_conflict"
  case cleanupUnproven = "cleanup_unproven"
  case quarantined
  case invalidMessage = "invalid_message"
  case secretBoundsExceeded = "secret_bounds_exceeded"
  case secretLifecycleViolation = "secret_lifecycle_violation"
  case journalCorrupt = "journal_corrupt"
  case ownerUnresponsive = "owner_unresponsive"
  case identityRejected = "identity_rejected"
  case timeout
  case unavailable
  case `internal`

  public var stableMessage: String {
    switch self {
    case .busy: "Global Authority mutation is busy."
    case .resourceExhausted: "Global Authority read capacity is exhausted."
    case .journalCapacityExhausted:
      "The Global Authority journal reached its fixed capacity and requires maintenance."
    case .permissionDenied: "The native operation was denied."
    case .approvalDenied: "Required operating-system approval was denied."
    case .configurationRejected: "The native configuration was rejected."
    case .mixedEndpointInUse: "The mixed listener endpoint is already in use."
    case .controllerEndpointInUse: "The controller endpoint is already in use."
    case .credentialsUnavailable: "Required credentials are unavailable."
    case .credentialConflict: "Credential material conflicts with an immutable entry."
    case .credentialVaultMissing: "The credential vault is unavailable."
    case .credentialVaultCorrupt: "The credential vault data is corrupt."
    case .credentialMigrationRequired:
      "The credential vault uses an unsupported schema and must be cleared and reprovisioned."
    case .credentialGCConflict: "Credential cleanup requires a fresh preview."
    case .proxyAgentApprovalRequired: "ProxyAgent approval is required in System Settings."
    case .globalAuthorityUnavailable: "Global Authority is unavailable."
    case .globalAuthorityRegistrationRequired: "Global Authority registration is required."
    case .globalAuthorityApprovalRequired: "Global Authority approval is required."
    case .globalAuthorityIdentityRejected: "Global Authority peer identity was rejected."
    case .globalAuthorityProtocolMismatch: "Global Authority protocol is incompatible."
    case .globalAuthorityRecovering: "Global Authority is recovering; starts are disabled."
    case .globalAuthorityTimeout: "The Authority operation timed out."
    case .globalAuthorityInterrupted: "The Authority connection was interrupted."
    case .globalLeaseConflict: "A conflicting Global Authority lease exists."
    case .replayRejected: "Authority replay protection rejected the context."
    case .staleOperation: "Authority operation context is stale."
    case .ticketExpired: "The Authority start ticket expired."
    case .ticketAlreadyRedeemed: "The Authority start ticket was already redeemed."
    case .ticketInvalid: "The Authority start ticket is invalid."
    case .compensationConflict: "Tunnel preference compensation conflicted."
    case .cleanupUnproven: "Global cleanup could not be proven."
    case .quarantined: "Global Authority is quarantined pending reconciliation."
    case .invalidMessage: "The Authority message is invalid."
    case .secretBoundsExceeded: "Authority secret material exceeds a fixed bound."
    case .secretLifecycleViolation: "Authority secret lifecycle verification failed."
    case .journalCorrupt: "The Authority journal is corrupt."
    case .ownerUnresponsive: "The Authority engine owner is unresponsive."
    case .identityRejected: "The native peer identity was rejected."
    case .timeout: "The native operation timed out."
    case .unavailable: "The native operation is unavailable."
    case .internal: "The native bridge failed at a stable internal boundary."
    }
  }

  public init(from decoder: Decoder) throws {
    let wireCode = try decoder.singleValueContainer().decode(String.self)
    self = Self(rawValue: wireCode) ?? .internal
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(rawValue)
  }
}

public struct NativeBridgeFailure: Codable, Equatable, Sendable {
  public let code: NativeBridgeErrorCode
  public let message: String

  public init(code: NativeBridgeErrorCode, message _: String) {
    self.code = code
    self.message = code.stableMessage
  }

  private enum CodingKeys: String, CodingKey {
    case code
    case message
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let wireCode = try container.decode(String.self, forKey: .code)
    let suppliedMessage = try container.decode(String.self, forKey: .message)
    guard Self.isValidMessage(suppliedMessage) else {
      throw NativeBridgeProtocolError.invalidResponse
    }
    code = NativeBridgeErrorCode(rawValue: wireCode) ?? .internal
    message = code.stableMessage
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(code, forKey: .code)
    try container.encode(code.stableMessage, forKey: .message)
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
  case serviceMaintenance(NativeServiceMaintenanceResult)
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
    case serviceMaintenance = "service_maintenance"
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
    case .serviceMaintenance:
      self = .serviceMaintenance(
        try container.decode(NativeServiceMaintenanceResult.self, forKey: .value)
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
    case .serviceMaintenance(let result):
      try container.encode(Kind.serviceMaintenance, forKey: .kind)
      try container.encode(result, forKey: .value)
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
