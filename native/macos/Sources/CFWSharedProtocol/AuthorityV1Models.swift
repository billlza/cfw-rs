import Foundation

public enum AuthorityV1Limits {
  public static let major: UInt16 = 1
  public static let minor: UInt16 = 1
  public static let minimumMinor: UInt16 = 1
  public static let supportedFeatureBits: UInt64 = 0
  public static let maximumEnvelopeBytes = 1_048_576
  public static let maximumConfigurationBytes = EngineCapacity.maximumConfigurationBytes
  public static let maximumTotalSecretBytes = 256 * 1_024
  public static let maximumCredentialSlots = EngineCapacity.maximumCredentialSlots
  public static let maximumIndividualSecretBytes = 16 * 1_024
  public static let maximumReadOnlyRequests = 64
  public static let maximumMutatingTransactions = 1
  public static let maximumQueuedEventsPerPeer = 32
  public static let preparationLifetimeMilliseconds: UInt64 = 10_000
  public static let commandTimeoutMilliseconds: UInt64 = 5_000
  public static let stopAttestationTimeoutMilliseconds: UInt64 = 5_000
  /// How long a ProxyAgent waits, once, for the Authority to say whether it
  /// still holds the lease the agent bound. The agent asks after its stopped
  /// attestation failed, within the Host's wait for its stop reply. An
  /// Authority of an earlier build does not know the question, and its
  /// connection fails it, which the agent takes as no answer.
  public static let ownerLeaseStatusTimeoutMilliseconds: UInt64 = 1_000
  public static let ticketBytes = 32
  public static let capabilityBytes = 32
  public static let connectionNonceBytes = 32
  public static let maximumDescriptionBytes = 256
}

public enum AuthorityV1ValidationError: Error, Equatable, Sendable {
  case malformedEnvelope
  case noncanonicalRepresentation
  case unsupportedMajor(UInt16)
  case unsupportedMinor(UInt16)
  case unsupportedRequiredFeatures(UInt64)
  case unknownCommand
  case invalidType
  case invalidIdentifier
  case invalidDigest
  case invalidContext
  case invalidState
  case invalidConfiguration
  case invalidAttestation
  case invalidReceipt
  case invalidTicket
  case invalidCapability
  case duplicateCredentialSlot
  case boundViolation
  case secretUnavailable
  case messageTooLarge(actual: Int, maximum: Int)
}

public struct AuthorityIdentifier: Codable, Hashable, Sendable {
  public let rawValue: UUID

  public init(_ rawValue: UUID) { self.rawValue = rawValue }

  public init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer().decode(String.self)
    guard value == value.lowercased(), let uuid = UUID(uuidString: value),
      uuid.uuidString.lowercased() == value
    else { throw AuthorityV1ValidationError.invalidIdentifier }
    rawValue = uuid
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(rawValue.uuidString.lowercased())
  }
}

public struct AuthorityProtocolVersion: Codable, Equatable, Sendable {
  public let major: UInt16
  public let minor: UInt16
  public let minimumMinor: UInt16
  public let featureBits: UInt64
  public let maxMessageBytes: UInt32

  public init(
    major: UInt16 = AuthorityV1Limits.major,
    minor: UInt16 = AuthorityV1Limits.minor,
    minimumMinor: UInt16 = AuthorityV1Limits.minimumMinor,
    featureBits: UInt64 = AuthorityV1Limits.supportedFeatureBits,
    maxMessageBytes: UInt32 = UInt32(AuthorityV1Limits.maximumEnvelopeBytes)
  ) throws {
    guard major == AuthorityV1Limits.major else {
      throw AuthorityV1ValidationError.unsupportedMajor(major)
    }
    guard minor == AuthorityV1Limits.minor,
      minimumMinor == AuthorityV1Limits.minimumMinor
    else { throw AuthorityV1ValidationError.unsupportedMinor(minor) }
    let unsupported = featureBits & ~AuthorityV1Limits.supportedFeatureBits
    guard unsupported == 0 else {
      throw AuthorityV1ValidationError.unsupportedRequiredFeatures(unsupported)
    }
    guard maxMessageBytes > 0,
      maxMessageBytes <= UInt32(AuthorityV1Limits.maximumEnvelopeBytes)
    else { throw AuthorityV1ValidationError.boundViolation }
    self.major = major
    self.minor = minor
    self.minimumMinor = minimumMinor
    self.featureBits = featureBits
    self.maxMessageBytes = maxMessageBytes
  }

  enum CodingKeys: String, CodingKey {
    case major, minor
    case minimumMinor = "minimum_minor"
    case featureBits = "feature_bits"
    case maxMessageBytes = "max_message_bytes"
  }

  public init(from decoder: Decoder) throws {
    let value = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      major: value.decode(UInt16.self, forKey: .major),
      minor: value.decode(UInt16.self, forKey: .minor),
      minimumMinor: value.decode(UInt16.self, forKey: .minimumMinor),
      featureBits: value.decode(UInt64.self, forKey: .featureBits),
      maxMessageBytes: value.decode(UInt32.self, forKey: .maxMessageBytes)
    )
  }
}

public enum AuthorityMode: String, Codable, CaseIterable, Sendable {
  case localProxy = "local_proxy"
  case systemProxy = "system_proxy"
  case tunnel

  public var isProxyAgent: Bool { self == .localProxy || self == .systemProxy }
}

public enum AuthorityRole: String, Codable, CaseIterable, Hashable, Sendable {
  case host
  case proxyAgent = "proxy_agent"
  case provider
}

public enum AuthorityState: String, Codable, CaseIterable, Sendable {
  case recovering, off, preparing, starting, active, stopping, quarantined
}

public enum AuthorityLeaseState: String, Codable, CaseIterable, Sendable {
  case prepared, bound, starting, active, stopping, revoked
}

public struct RootContext: Codable, Equatable, Comparable, Sendable {
  public let installationID: AuthorityIdentifier
  public let epoch: UInt64
  public let generation: UInt64

  public init(installationID: AuthorityIdentifier, epoch: UInt64, generation: UInt64) throws {
    guard epoch > 0, generation > 0 else { throw AuthorityV1ValidationError.invalidContext }
    self.installationID = installationID
    self.epoch = epoch
    self.generation = generation
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    (lhs.epoch, lhs.generation) < (rhs.epoch, rhs.generation)
  }

  enum CodingKeys: String, CodingKey {
    case installationID = "installation_id"
    case epoch, generation
  }
}

public struct OperationContext: Codable, Equatable, Sendable {
  public let operationID: AuthorityIdentifier
  public let root: RootContext
  public let mode: AuthorityMode
  public let configSHA256: SHA256Digest
  public let identitySHA256: SHA256Digest
  public let ownerUID: UInt32
  public let authorityRevision: UInt64

  public init(
    operationID: AuthorityIdentifier, root: RootContext, mode: AuthorityMode,
    configSHA256: SHA256Digest, identitySHA256: SHA256Digest,
    ownerUID: UInt32, authorityRevision: UInt64
  ) throws {
    guard authorityRevision > 0 else { throw AuthorityV1ValidationError.invalidContext }
    self.operationID = operationID
    self.root = root
    self.mode = mode
    self.configSHA256 = configSHA256
    self.identitySHA256 = identitySHA256
    self.ownerUID = ownerUID
    self.authorityRevision = authorityRevision
  }

  enum CodingKeys: String, CodingKey {
    case operationID = "operation_id"
    case root, mode
    case configSHA256 = "config_sha256"
    case identitySHA256 = "identity_sha256"
    case ownerUID = "owner_uid"
    case authorityRevision = "authority_revision"
  }
}

/// Connection identity is derived from public, kernel-populated Foundation XPC
/// attributes after the role-specific listener has accepted the peer's exact
/// code-signing requirement. It is never a caller-supplied wire type.
public struct PeerIdentity: Equatable, Sendable {
  public let connectionIdentityDigest: SHA256Digest
  public let pid: Int32
  public let euid: UInt32
  public let auditSessionID: UInt32
  public let role: AuthorityRole
  public let consoleUID: UInt32?

  public init(
    connectionIdentityDigest: SHA256Digest, pid: Int32, euid: UInt32,
    auditSessionID: UInt32,
    role: AuthorityRole, consoleUID: UInt32?
  ) {
    self.connectionIdentityDigest = connectionIdentityDigest
    self.pid = pid
    self.euid = euid
    self.auditSessionID = auditSessionID
    self.role = role
    self.consoleUID = consoleUID
  }
}
