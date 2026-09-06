import Foundation

public struct CutoverPreflightRequest: Codable, Equatable, Sendable {
  public let target: EngineMode
  public let systemProxyRequest: EngineStartRequest
  public let tunnelRequest: EngineStartRequest

  public init(
    target: EngineMode,
    systemProxyRequest: EngineStartRequest,
    tunnelRequest: EngineStartRequest
  ) throws {
    guard target != .off,
      systemProxyRequest.tunnelOptions == nil,
      tunnelRequest.tunnelOptions != nil,
      systemProxyRequest.context == tunnelRequest.context,
      systemProxyRequest.credentialAudience == tunnelRequest.credentialAudience
    else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    let systemReferences = Set(systemProxyRequest.credentialSlots.map(\.reference))
    let tunnelReferences = Set(tunnelRequest.credentialSlots.map(\.reference))
    guard systemReferences == tunnelReferences else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.target = target
    self.systemProxyRequest = systemProxyRequest
    self.tunnelRequest = tunnelRequest
  }

  private enum CodingKeys: String, CodingKey {
    case target
    case systemProxyRequest = "system_proxy_request"
    case tunnelRequest = "tunnel_request"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      target: container.decode(EngineMode.self, forKey: .target),
      systemProxyRequest: container.decode(
        EngineStartRequest.self,
        forKey: .systemProxyRequest
      ),
      tunnelRequest: container.decode(EngineStartRequest.self, forKey: .tunnelRequest)
    )
  }
}

public struct CutoverPreflightAttestation: Codable, Equatable, Sendable {
  public static let maximumValidityMilliseconds: UInt32 = 300_000

  public let attestationID: UUID
  public let target: EngineMode
  public let context: EngineCommandContext
  public let systemProxyConfigDigest: SHA256Digest
  public let tunnelConfigDigest: SHA256Digest
  public let credentialAudience: CredentialAudience
  public let credentialReferences: [CredentialReference]
  public let validForMillis: UInt32

  public init(
    attestationID: UUID,
    target: EngineMode,
    context: EngineCommandContext,
    systemProxyConfigDigest: SHA256Digest,
    tunnelConfigDigest: SHA256Digest,
    credentialAudience: CredentialAudience,
    credentialReferences: [CredentialReference],
    validForMillis: UInt32
  ) throws {
    guard target != .off, validForMillis > 0,
      validForMillis <= Self.maximumValidityMilliseconds
    else {
      throw NativeBridgeProtocolError.invalidCommand
    }
    guard credentialReferences.count <= NativeBridgeProtocolConstants.maximumCredentialSlots,
      credentialReferences.sorted(by: CredentialReference.canonicalPrecedes)
        == credentialReferences,
      Set(credentialReferences.map(\.id)).count == credentialReferences.count
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.attestationID = attestationID
    self.target = target
    self.context = context
    self.systemProxyConfigDigest = systemProxyConfigDigest
    self.tunnelConfigDigest = tunnelConfigDigest
    self.credentialAudience = credentialAudience
    self.credentialReferences = credentialReferences
    self.validForMillis = validForMillis
  }

  private enum CodingKeys: String, CodingKey {
    case attestationID = "attestation_id"
    case target
    case context
    case systemProxyConfigDigest = "system_proxy_config_digest"
    case tunnelConfigDigest = "tunnel_config_digest"
    case credentialAudience = "credential_audience"
    case credentialReferences = "credential_references"
    case validForMillis = "valid_for_millis"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let identifierText = try container.decode(String.self, forKey: .attestationID)
    guard identifierText == identifierText.lowercased(),
      let identifier = UUID(uuidString: identifierText),
      identifier.uuidString.lowercased() == identifierText
    else {
      throw NativeBridgeProtocolError.invalidContext
    }
    try self.init(
      attestationID: identifier,
      target: container.decode(EngineMode.self, forKey: .target),
      context: container.decode(EngineCommandContext.self, forKey: .context),
      systemProxyConfigDigest: container.decode(
        SHA256Digest.self,
        forKey: .systemProxyConfigDigest
      ),
      tunnelConfigDigest: container.decode(SHA256Digest.self, forKey: .tunnelConfigDigest),
      credentialAudience: container.decode(
        CredentialAudience.self,
        forKey: .credentialAudience
      ),
      credentialReferences: container.decode(
        [CredentialReference].self,
        forKey: .credentialReferences
      ),
      validForMillis: container.decode(UInt32.self, forKey: .validForMillis)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(attestationID.uuidString.lowercased(), forKey: .attestationID)
    try container.encode(target, forKey: .target)
    try container.encode(context, forKey: .context)
    try container.encode(systemProxyConfigDigest, forKey: .systemProxyConfigDigest)
    try container.encode(tunnelConfigDigest, forKey: .tunnelConfigDigest)
    try container.encode(credentialAudience, forKey: .credentialAudience)
    try container.encode(credentialReferences, forKey: .credentialReferences)
    try container.encode(validForMillis, forKey: .validForMillis)
  }
}

public enum CutoverPreflightOutcome: Equatable, Sendable {
  case awaitingApproval(
    target: EngineMode,
    context: EngineCommandContext,
    systemProxyConfigDigest: SHA256Digest,
    tunnelConfigDigest: SHA256Digest,
    credentialAudience: CredentialAudience
  )
  case ready(CutoverPreflightAttestation)
}

extension CutoverPreflightOutcome: Codable {
  private enum CodingKeys: String, CodingKey {
    case status
    case target
    case context
    case systemProxyConfigDigest = "system_proxy_config_digest"
    case tunnelConfigDigest = "tunnel_config_digest"
    case credentialAudience = "credential_audience"
    case attestation
  }

  private enum Status: String, Codable {
    case awaitingApproval = "awaiting_approval"
    case ready
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(Status.self, forKey: .status) {
    case .awaitingApproval:
      self = .awaitingApproval(
        target: try container.decode(EngineMode.self, forKey: .target),
        context: try container.decode(EngineCommandContext.self, forKey: .context),
        systemProxyConfigDigest: try container.decode(
          SHA256Digest.self,
          forKey: .systemProxyConfigDigest
        ),
        tunnelConfigDigest: try container.decode(
          SHA256Digest.self,
          forKey: .tunnelConfigDigest
        ),
        credentialAudience: try container.decode(
          CredentialAudience.self,
          forKey: .credentialAudience
        )
      )
    case .ready:
      self = .ready(
        try container.decode(CutoverPreflightAttestation.self, forKey: .attestation)
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .awaitingApproval(
      let target,
      let context,
      let systemProxyConfigDigest,
      let tunnelConfigDigest,
      let credentialAudience
    ):
      try container.encode(Status.awaitingApproval, forKey: .status)
      try container.encode(target, forKey: .target)
      try container.encode(context, forKey: .context)
      try container.encode(systemProxyConfigDigest, forKey: .systemProxyConfigDigest)
      try container.encode(tunnelConfigDigest, forKey: .tunnelConfigDigest)
      try container.encode(credentialAudience, forKey: .credentialAudience)
    case .ready(let attestation):
      try container.encode(Status.ready, forKey: .status)
      try container.encode(attestation, forKey: .attestation)
    }
  }
}
