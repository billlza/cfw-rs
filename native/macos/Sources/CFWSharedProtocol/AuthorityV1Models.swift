import Foundation

public enum AuthorityV1Limits {
  public static let major: UInt16 = 1
  public static let minor: UInt16 = 1
  public static let minimumMinor: UInt16 = 1
  public static let supportedFeatureBits: UInt64 = 0
  public static let maximumEnvelopeBytes = 1_048_576
  public static let maximumConfigurationBytes = 768 * 1_024
  public static let maximumTotalSecretBytes = 256 * 1_024
  public static let maximumCredentialSlots = 256
  public static let maximumIndividualSecretBytes = 16 * 1_024
  public static let maximumReadOnlyRequests = 64
  public static let maximumMutatingTransactions = 1
  public static let maximumQueuedEventsPerPeer = 32
  public static let preparationLifetimeMilliseconds: UInt64 = 10_000
  public static let commandTimeoutMilliseconds: UInt64 = 5_000
  public static let stopAttestationTimeoutMilliseconds: UInt64 = 5_000
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
  case systemProxy = "system_proxy"
  case tunnel
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

public struct GlobalLease: Codable, Equatable, Sendable {
  public let leaseID: AuthorityIdentifier
  public let operation: OperationContext
  public let state: AuthorityLeaseState
  public let issuedMonotonic: UInt64
  public let expiryMonotonic: UInt64
  public let ownerConnectionNonce: SHA256Digest

  public init(
    leaseID: AuthorityIdentifier, operation: OperationContext, state: AuthorityLeaseState,
    issuedMonotonic: UInt64, expiryMonotonic: UInt64,
    ownerConnectionNonce: SHA256Digest
  ) throws {
    guard issuedMonotonic > 0, expiryMonotonic > issuedMonotonic else {
      throw AuthorityV1ValidationError.invalidState
    }
    self.leaseID = leaseID
    self.operation = operation
    self.state = state
    self.issuedMonotonic = issuedMonotonic
    self.expiryMonotonic = expiryMonotonic
    self.ownerConnectionNonce = ownerConnectionNonce
  }

  enum CodingKeys: String, CodingKey {
    case leaseID = "lease_id"
    case operation, state
    case issuedMonotonic = "issued_monotonic_ms"
    case expiryMonotonic = "expiry_monotonic_ms"
    case ownerConnectionNonce = "owner_connection_nonce_sha256"
  }
}

public struct ReplayCursor: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let installationID: AuthorityIdentifier
  public let acceptedEpoch: UInt64
  public let acceptedGeneration: UInt64
  public let revision: UInt64
  public let previousRecordSHA256: SHA256Digest

  public init(
    installationID: AuthorityIdentifier, acceptedEpoch: UInt64,
    acceptedGeneration: UInt64, revision: UInt64,
    previousRecordSHA256: SHA256Digest
  ) throws {
    guard acceptedEpoch > 0, acceptedGeneration > 0, revision > 0 else {
      throw AuthorityV1ValidationError.invalidContext
    }
    schemaVersion = 1
    self.installationID = installationID
    self.acceptedEpoch = acceptedEpoch
    self.acceptedGeneration = acceptedGeneration
    self.revision = revision
    self.previousRecordSHA256 = previousRecordSHA256
  }

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case installationID = "installation_id"
    case acceptedEpoch = "accepted_epoch"
    case acceptedGeneration = "accepted_generation"
    case revision
    case previousRecordSHA256 = "previous_record_sha256"
  }

  public init(from decoder: Decoder) throws {
    let value = try decoder.container(keyedBy: CodingKeys.self)
    guard try value.decode(UInt16.self, forKey: .schemaVersion) == 1 else {
      throw AuthorityV1ValidationError.invalidContext
    }
    try self.init(
      installationID: value.decode(AuthorityIdentifier.self, forKey: .installationID),
      acceptedEpoch: value.decode(UInt64.self, forKey: .acceptedEpoch),
      acceptedGeneration: value.decode(UInt64.self, forKey: .acceptedGeneration),
      revision: value.decode(UInt64.self, forKey: .revision),
      previousRecordSHA256: value.decode(SHA256Digest.self, forKey: .previousRecordSHA256)
    )
  }
}

public struct AuthorityConfigurationDescriptor: Codable, Equatable, Sendable {
  public let byteCount: UInt32
  public let configSHA256: SHA256Digest
  public let identitySHA256: SHA256Digest
  public let credentialAudience: CredentialAudience
  public let credentialSlots: [CredentialSlot]
  public let tunnelOptions: TunnelNetworkOptions?

  public init(
    byteCount: UInt32, configSHA256: SHA256Digest, identitySHA256: SHA256Digest,
    credentialAudience: CredentialAudience,
    credentialSlots: [CredentialSlot], tunnelOptions: TunnelNetworkOptions?
  ) throws {
    guard byteCount > 0, byteCount <= AuthorityV1Limits.maximumConfigurationBytes,
      credentialSlots.count <= AuthorityV1Limits.maximumCredentialSlots
    else { throw AuthorityV1ValidationError.boundViolation }
    var pointers = Set<String>()
    guard credentialSlots.allSatisfy({ pointers.insert($0.jsonPointer).inserted }) else {
      throw AuthorityV1ValidationError.duplicateCredentialSlot
    }
    self.byteCount = byteCount
    self.configSHA256 = configSHA256
    self.identitySHA256 = identitySHA256
    self.credentialAudience = credentialAudience
    self.credentialSlots = credentialSlots
    self.tunnelOptions = tunnelOptions
  }

  enum CodingKeys: String, CodingKey {
    case byteCount = "byte_count"
    case configSHA256 = "config_sha256"
    case identitySHA256 = "identity_sha256"
    case credentialAudience = "credential_audience"
    case credentialSlots = "credential_slots"
    case tunnelOptions = "tunnel_options"
  }
}

public struct LeaseView: Codable, Equatable, Sendable {
  public let leaseID: AuthorityIdentifier
  public let operation: OperationContext
  public let state: AuthorityLeaseState
  public let expiryMonotonic: UInt64

  public init(
    leaseID: AuthorityIdentifier, operation: OperationContext,
    state: AuthorityLeaseState, expiryMonotonic: UInt64
  ) throws {
    guard expiryMonotonic > 0 else { throw AuthorityV1ValidationError.invalidState }
    self.leaseID = leaseID
    self.operation = operation
    self.state = state
    self.expiryMonotonic = expiryMonotonic
  }

  enum CodingKeys: String, CodingKey {
    case leaseID = "lease_id"
    case operation, state
    case expiryMonotonic = "expiry_monotonic_ms"
  }
}

public struct AuthorityFailureSummary: Codable, Equatable, Sendable {
  public let code: String

  public init(code: String) throws {
    guard !code.isEmpty, code.utf8.count <= 64,
      code.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 })
    else { throw AuthorityV1ValidationError.invalidState }
    self.code = code
  }
}

public struct AuthoritySnapshot: Codable, Equatable, Sendable {
  public let protocolVersion: AuthorityProtocolVersion
  public let state: AuthorityState
  public let revision: UInt64
  /// The durable installation lineage. A freshly installed Authority has no
  /// cursor yet and reports a strict global Off snapshot at its current
  /// revision; the first successful prepare atomically enrolls the lineage.
  public let replayCursor: ReplayCursor?
  public let leaseView: LeaseView?
  public let lastFailure: AuthorityFailureSummary?
  public let consoleUID: UInt32?

  public init(
    protocolVersion: AuthorityProtocolVersion, state: AuthorityState, revision: UInt64,
    replayCursor: ReplayCursor?, leaseView: LeaseView?,
    lastFailure: AuthorityFailureSummary?, consoleUID: UInt32?
  ) throws {
    guard revision > 0, replayCursor?.revision ?? 0 <= revision,
      (state == .off || state == .recovering || state == .quarantined) == (leaseView == nil)
    else { throw AuthorityV1ValidationError.invalidState }
    guard replayCursor != nil || (state == .off && leaseView == nil) else {
      throw AuthorityV1ValidationError.invalidState
    }
    self.protocolVersion = protocolVersion
    self.state = state
    self.revision = revision
    self.replayCursor = replayCursor
    self.leaseView = leaseView
    self.lastFailure = lastFailure
    self.consoleUID = consoleUID
  }

  enum CodingKeys: String, CodingKey {
    case protocolVersion = "protocol_version"
    case state, revision
    case replayCursor = "replay_cursor"
    case leaseView = "lease_view"
    case lastFailure = "last_failure"
    case consoleUID = "console_uid"
  }
}

public struct ReadyFlags: OptionSet, Codable, Equatable, Sendable {
  public let rawValue: UInt16
  public init(rawValue: UInt16) { self.rawValue = rawValue }

  public init(from decoder: Decoder) throws {
    self.init(rawValue: try decoder.singleValueContainer().decode(UInt16.self))
  }

  public func encode(to encoder: Encoder) throws {
    var value = encoder.singleValueContainer()
    try value.encode(rawValue)
  }

  public static let libboxStarted = Self(rawValue: 1 << 0)
  public static let transportReady = Self(rawValue: 1 << 1)
  public static let operatingSystemStateReady = Self(rawValue: 1 << 2)
  public static let all: Self = [.libboxStarted, .transportReady, .operatingSystemStateReady]
}

public struct PacketPumpLimits: Codable, Equatable, Sendable {
  public let maximumQueuedPackets: UInt16
  public let maximumQueuedBytes: UInt32
  public let maximumPacketBytes: UInt16
  public let maximumReadBatch: UInt8

  public init(
    maximumQueuedPackets: UInt16, maximumQueuedBytes: UInt32,
    maximumPacketBytes: UInt16, maximumReadBatch: UInt8
  ) throws {
    guard (1...1_024).contains(maximumQueuedPackets),
      (1...4 * 1_048_576).contains(maximumQueuedBytes),
      (1_280...1_500).contains(maximumPacketBytes),
      (1...64).contains(maximumReadBatch)
    else { throw AuthorityV1ValidationError.boundViolation }
    self.maximumQueuedPackets = maximumQueuedPackets
    self.maximumQueuedBytes = maximumQueuedBytes
    self.maximumPacketBytes = maximumPacketBytes
    self.maximumReadBatch = maximumReadBatch
  }

  enum CodingKeys: String, CodingKey {
    case maximumQueuedPackets = "maximum_queued_packets"
    case maximumQueuedBytes = "maximum_queued_bytes"
    case maximumPacketBytes = "maximum_packet_bytes"
    case maximumReadBatch = "maximum_read_batch"
  }
}

public struct ReadyAttestation: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let runtimeDigest: SHA256Digest
  public let ownerRole: AuthorityRole
  public let readyFlags: ReadyFlags
  public let packetPumpLimits: PacketPumpLimits?
  public let monotonicTimestamp: UInt64

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    runtimeDigest: SHA256Digest, ownerRole: AuthorityRole,
    readyFlags: ReadyFlags, packetPumpLimits: PacketPumpLimits?,
    monotonicTimestamp: UInt64
  ) throws {
    guard ownerRole != .host, readyFlags == .all, monotonicTimestamp > 0,
      (operation.mode == .tunnel) == (packetPumpLimits != nil),
      operation.mode == .tunnel ? ownerRole == .provider : ownerRole == .proxyAgent
    else { throw AuthorityV1ValidationError.invalidAttestation }
    self.operation = operation
    self.leaseID = leaseID
    self.runtimeDigest = runtimeDigest
    self.ownerRole = ownerRole
    self.readyFlags = readyFlags
    self.packetPumpLimits = packetPumpLimits
    self.monotonicTimestamp = monotonicTimestamp
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
    case runtimeDigest = "runtime_digest"
    case ownerRole = "owner_role"
    case readyFlags = "ready_flags"
    case packetPumpLimits = "packet_pump_limits"
    case monotonicTimestamp = "monotonic_timestamp_ms"
  }
}

public struct StoppedAttestation: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let libboxStopped: Bool
  public let transportClosed: Bool
  public let osRestored: Bool
  public let monotonicTimestamp: UInt64

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    libboxStopped: Bool, transportClosed: Bool, osRestored: Bool,
    monotonicTimestamp: UInt64
  ) throws {
    guard libboxStopped, transportClosed, osRestored, monotonicTimestamp > 0 else {
      throw AuthorityV1ValidationError.invalidAttestation
    }
    self.operation = operation
    self.leaseID = leaseID
    self.libboxStopped = libboxStopped
    self.transportClosed = transportClosed
    self.osRestored = osRestored
    self.monotonicTimestamp = monotonicTimestamp
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
    case libboxStopped = "libbox_stopped"
    case transportClosed = "transport_closed"
    case osRestored = "os_restored"
    case monotonicTimestamp = "monotonic_timestamp_ms"
  }
}

public struct TunnelPreferenceValues: Codable, Equatable, Sendable {
  public let descriptorSHA256: SHA256Digest?
  public let isEnabled: Bool
  public let localizedDescription: String?

  public init(
    descriptorSHA256: SHA256Digest?, isEnabled: Bool,
    localizedDescription: String?
  ) throws {
    guard localizedDescription?.utf8.count ?? 0 <= AuthorityV1Limits.maximumDescriptionBytes,
      localizedDescription?.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        != true
    else { throw AuthorityV1ValidationError.invalidReceipt }
    self.descriptorSHA256 = descriptorSHA256
    self.isEnabled = isEnabled
    self.localizedDescription = localizedDescription
  }

  enum CodingKeys: String, CodingKey {
    case descriptorSHA256 = "descriptor_sha256"
    case isEnabled = "is_enabled"
    case localizedDescription = "localized_description"
  }
}

public struct PreferenceMutationReceipt: Codable, Equatable, Sendable {
  public let operationID: AuthorityIdentifier
  public let createdManager: Bool
  public let priorValues: TunnelPreferenceValues?
  public let writtenDescriptorSHA256: SHA256Digest

  public init(
    operationID: AuthorityIdentifier, createdManager: Bool,
    priorValues: TunnelPreferenceValues?, writtenDescriptorSHA256: SHA256Digest
  ) throws {
    guard createdManager == (priorValues == nil) else {
      throw AuthorityV1ValidationError.invalidReceipt
    }
    self.operationID = operationID
    self.createdManager = createdManager
    self.priorValues = priorValues
    self.writtenDescriptorSHA256 = writtenDescriptorSHA256
  }

  enum CodingKeys: String, CodingKey {
    case operationID = "operation_id"
    case createdManager = "created_manager"
    case priorValues = "prior_values"
    case writtenDescriptorSHA256 = "written_descriptor_sha256"
  }
}

public struct HandshakeRequest: Codable, Equatable, Sendable {
  public let version: AuthorityProtocolVersion

  public init(version: AuthorityProtocolVersion) {
    self.version = version
  }
}

public struct HandshakeResponse: Codable, Equatable, Sendable {
  public let version: AuthorityProtocolVersion
  public let maximumConfigurationBytes: UInt32
  public let maximumTotalSecretBytes: UInt32
  public let maximumCredentialSlots: UInt16
  public let maximumIndividualSecretBytes: UInt32
  public let maximumReadOnlyRequests: UInt16
  public let maximumMutatingTransactions: UInt8
  public let maximumQueuedEventsPerPeer: UInt16
  public let preparationLifetimeMilliseconds: UInt64
  public let commandTimeoutMilliseconds: UInt64
  public let stopAttestationTimeoutMilliseconds: UInt64

  public static func v1() throws -> Self {
    Self(
      version: try AuthorityProtocolVersion(),
      maximumConfigurationBytes: UInt32(AuthorityV1Limits.maximumConfigurationBytes),
      maximumTotalSecretBytes: UInt32(AuthorityV1Limits.maximumTotalSecretBytes),
      maximumCredentialSlots: UInt16(AuthorityV1Limits.maximumCredentialSlots),
      maximumIndividualSecretBytes: UInt32(AuthorityV1Limits.maximumIndividualSecretBytes),
      maximumReadOnlyRequests: UInt16(AuthorityV1Limits.maximumReadOnlyRequests),
      maximumMutatingTransactions: UInt8(AuthorityV1Limits.maximumMutatingTransactions),
      maximumQueuedEventsPerPeer: UInt16(AuthorityV1Limits.maximumQueuedEventsPerPeer),
      preparationLifetimeMilliseconds: AuthorityV1Limits.preparationLifetimeMilliseconds,
      commandTimeoutMilliseconds: AuthorityV1Limits.commandTimeoutMilliseconds,
      stopAttestationTimeoutMilliseconds: AuthorityV1Limits.stopAttestationTimeoutMilliseconds
    )
  }

  enum CodingKeys: String, CodingKey {
    case version
    case maximumConfigurationBytes = "maximum_configuration_bytes"
    case maximumTotalSecretBytes = "maximum_total_secret_bytes"
    case maximumCredentialSlots = "maximum_credential_slots"
    case maximumIndividualSecretBytes = "maximum_individual_secret_bytes"
    case maximumReadOnlyRequests = "maximum_read_only_requests"
    case maximumMutatingTransactions = "maximum_mutating_transactions"
    case maximumQueuedEventsPerPeer = "maximum_queued_events_per_peer"
    case preparationLifetimeMilliseconds = "preparation_lifetime_ms"
    case commandTimeoutMilliseconds = "command_timeout_ms"
    case stopAttestationTimeoutMilliseconds = "stop_attestation_timeout_ms"
  }
}

public struct PrepareStartRequest: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let expectedRevision: UInt64
  public let configuration: AuthorityConfigurationDescriptor

  public init(
    operation: OperationContext, expectedRevision: UInt64,
    configuration: AuthorityConfigurationDescriptor
  ) throws {
    guard expectedRevision == operation.authorityRevision,
      (operation.mode == .tunnel) == (configuration.tunnelOptions != nil),
      operation.configSHA256 == configuration.configSHA256,
      operation.identitySHA256 == configuration.identitySHA256
    else { throw AuthorityV1ValidationError.invalidConfiguration }
    self.operation = operation
    self.expectedRevision = expectedRevision
    self.configuration = configuration
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case expectedRevision = "expected_revision"
    case configuration
  }
}

public final class PreparedStart: @unchecked Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let ticket: StartTicket?
  public let ownerCapability: OwnerCapability?
  public let expiresMonotonic: UInt64
  public let preferenceDescriptorSHA256: SHA256Digest

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    ticket: StartTicket?, ownerCapability: OwnerCapability?,
    expiresMonotonic: UInt64, preferenceDescriptorSHA256: SHA256Digest
  ) throws {
    guard (operation.mode == .tunnel) == (ticket != nil),
      (operation.mode == .systemProxy) == (ownerCapability != nil),
      (ticket != nil) != (ownerCapability != nil), expiresMonotonic > 0,
      preferenceDescriptorSHA256 == operation.identitySHA256
    else { throw AuthorityV1ValidationError.invalidState }
    self.operation = operation
    self.leaseID = leaseID
    self.ticket = ticket
    self.ownerCapability = ownerCapability
    self.expiresMonotonic = expiresMonotonic
    self.preferenceDescriptorSHA256 = preferenceDescriptorSHA256
  }

  deinit { erase() }

  public func erase() {
    ticket?.erase()
    ownerCapability?.erase()
  }
}

public struct BindProxyOwnerRequest: Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let capability: OwnerCapability
}

/// Non-secret operation metadata transported alongside (never inside) a
/// one-use Proxy owner capability on the authenticated Host→ProxyAgent XPC
/// method. The Authority verifies the exact pair again when binding.
public struct ProxyOwnerContext: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier

  public init(operation: OperationContext, leaseID: AuthorityIdentifier) throws {
    guard operation.mode == .systemProxy else {
      throw AuthorityV1ValidationError.invalidContext
    }
    self.operation = operation
    self.leaseID = leaseID
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
  }
}

public struct RedeemTunnelTicketRequest: Sendable {
  public let ticket: StartTicket

  public init(ticket: StartTicket) {
    self.ticket = ticket
  }
}

public final class RedeemedTunnelStart: @unchecked Sendable {
  public let operation: OperationContext
  public let lease: LeaseView
  public let configuration: SensitiveBytes
  public let secrets: AuthoritySecretMaterial

  public init(
    operation: OperationContext, lease: LeaseView,
    configuration: SensitiveBytes, secrets: AuthoritySecretMaterial
  ) throws {
    guard operation.mode == .tunnel, lease.operation == operation else {
      throw AuthorityV1ValidationError.invalidState
    }
    self.operation = operation
    self.lease = lease
    self.configuration = configuration
    self.secrets = secrets
  }
}

public struct BeginStopRequest: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let expectedRevision: UInt64

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    expectedRevision: UInt64
  ) throws {
    guard expectedRevision >= operation.authorityRevision else {
      throw AuthorityV1ValidationError.invalidContext
    }
    self.operation = operation
    self.leaseID = leaseID
    self.expectedRevision = expectedRevision
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
    case expectedRevision = "expected_revision"
  }
}

public struct CompleteStopRequest: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let expectedRevision: UInt64

  public init(
    operation: OperationContext,
    leaseID: AuthorityIdentifier,
    expectedRevision: UInt64
  ) throws {
    guard expectedRevision >= operation.authorityRevision else {
      throw AuthorityV1ValidationError.invalidContext
    }
    self.operation = operation
    self.leaseID = leaseID
    self.expectedRevision = expectedRevision
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
    case expectedRevision = "expected_revision"
  }
}

/// Host-observed System Proxy recovery evidence. Every field is explicit so a
/// missing observation cannot be decoded as a successful default. The
/// Authority still derives all of its own transient-state evidence internally.
public struct RecoveryProxyOffEvidence: Codable, Equatable, Sendable {
  public let ownershipCleared: Bool
  public let listenerClosed: Bool
  public let effectiveSystemConfigurationRestored: Bool

  public init(
    ownershipCleared: Bool,
    listenerClosed: Bool,
    effectiveSystemConfigurationRestored: Bool
  ) {
    self.ownershipCleared = ownershipCleared
    self.listenerClosed = listenerClosed
    self.effectiveSystemConfigurationRestored = effectiveSystemConfigurationRestored
  }

  enum CodingKeys: String, CodingKey {
    case ownershipCleared = "ownership_cleared"
    case listenerClosed = "listener_closed"
    case effectiveSystemConfigurationRestored =
      "effective_system_configuration_restored"
  }
}

/// Host-observed Packet Tunnel provider recovery evidence. `ownershipCleared`
/// means no provider endpoint still claims the recovered Authority generation;
/// libbox and packet-pump teardown remain separate mandatory observations.
public struct RecoveryProviderOffEvidence: Codable, Equatable, Sendable {
  public let ownershipCleared: Bool
  public let libboxStopped: Bool
  public let packetPumpClosed: Bool

  public init(
    ownershipCleared: Bool,
    libboxStopped: Bool,
    packetPumpClosed: Bool
  ) {
    self.ownershipCleared = ownershipCleared
    self.libboxStopped = libboxStopped
    self.packetPumpClosed = packetPumpClosed
  }

  enum CodingKeys: String, CodingKey {
    case ownershipCleared = "ownership_cleared"
    case libboxStopped = "libbox_stopped"
    case packetPumpClosed = "packet_pump_closed"
  }
}

/// Public NetworkExtension manager observation made by the authenticated Host.
/// Only `disconnected` and `invalid` are acceptable Off barriers; the remaining
/// values exist so an uncertain observation is represented and rejected rather
/// than omitted or coerced to success.
public enum RecoveryManagedTunnelStatus: String, Codable, CaseIterable, Sendable {
  case disconnected
  case invalid
  case connecting
  case connected
  case unknown
}

/// Exact compare-and-swap request for recovering a restarted Authority to Off.
/// The complete replay cursor binds the request to the durable journal head,
/// while `expectedRevision` prevents a stale Host observation from committing.
public struct ReconcileOffRequest: Codable, Equatable, Sendable {
  public let expectedRevision: UInt64
  public let replayCursor: ReplayCursor
  public let proxy: RecoveryProxyOffEvidence
  public let provider: RecoveryProviderOffEvidence
  public let managedTunnel: RecoveryManagedTunnelStatus

  public init(
    expectedRevision: UInt64,
    replayCursor: ReplayCursor,
    proxy: RecoveryProxyOffEvidence,
    provider: RecoveryProviderOffEvidence,
    managedTunnel: RecoveryManagedTunnelStatus
  ) throws {
    guard expectedRevision == replayCursor.revision else {
      throw AuthorityV1ValidationError.invalidContext
    }
    self.expectedRevision = expectedRevision
    self.replayCursor = replayCursor
    self.proxy = proxy
    self.provider = provider
    self.managedTunnel = managedTunnel
  }

  enum CodingKeys: String, CodingKey {
    case expectedRevision = "expected_revision"
    case replayCursor = "replay_cursor"
    case proxy, provider
    case managedTunnel = "managed_tunnel"
  }
}

/// Durable acknowledgement of the exact recovery cursor accepted by the
/// Authority. A successful reconciliation always consumes exactly one journal
/// revision.
public struct ReconcileOffReceipt: Codable, Equatable, Sendable {
  public let revision: UInt64
  public let replayCursor: ReplayCursor

  public init(revision: UInt64, replayCursor: ReplayCursor) throws {
    let (expected, overflow) = replayCursor.revision.addingReportingOverflow(1)
    guard !overflow, revision == expected else {
      throw AuthorityV1ValidationError.invalidContext
    }
    self.revision = revision
    self.replayCursor = replayCursor
  }

  enum CodingKeys: String, CodingKey {
    case revision
    case replayCursor = "replay_cursor"
  }
}

public struct StopDirective: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let deadlineMonotonic: UInt64
  public let revision: UInt64

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    deadlineMonotonic: UInt64, revision: UInt64
  ) throws {
    guard deadlineMonotonic > 0, revision >= operation.authorityRevision else {
      throw AuthorityV1ValidationError.invalidState
    }
    self.operation = operation
    self.leaseID = leaseID
    self.deadlineMonotonic = deadlineMonotonic
    self.revision = revision
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
    case deadlineMonotonic = "deadline_monotonic_ms"
    case revision
  }
}

public struct CancelPreparedRequest: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let expectedRevision: UInt64

  public init(operation: OperationContext, expectedRevision: UInt64) throws {
    guard expectedRevision >= operation.authorityRevision else {
      throw AuthorityV1ValidationError.invalidContext
    }
    self.operation = operation
    self.expectedRevision = expectedRevision
  }

  enum CodingKeys: String, CodingKey {
    case operation
    case expectedRevision = "expected_revision"
  }
}

public struct SnapshotRequest: Codable, Equatable, Sendable {
  public init() {}
}

public struct AuthorityAcknowledgement: Codable, Equatable, Sendable {
  public let operationID: AuthorityIdentifier
  public let revision: UInt64

  public init(operationID: AuthorityIdentifier, revision: UInt64) throws {
    guard revision > 0 else { throw AuthorityV1ValidationError.invalidContext }
    self.operationID = operationID
    self.revision = revision
  }

  enum CodingKeys: String, CodingKey {
    case operationID = "operation_id"
    case revision
  }
}

public enum AuthorityCommand: Sendable {
  case handshake(HandshakeRequest)
  case prepareStart(PrepareStartRequest)
  case bindProxyOwner(BindProxyOwnerRequest)
  case redeemTunnelTicket(RedeemTunnelTicketRequest)
  case attestReady(ReadyAttestation)
  case beginStop(BeginStopRequest)
  case completeStop(CompleteStopRequest)
  case reconcileOff(ReconcileOffRequest)
  case attestStopped(StoppedAttestation)
  case cancelPrepared(CancelPreparedRequest)
  case snapshot(SnapshotRequest)

  public var isReadOnly: Bool {
    switch self {
    case .handshake, .snapshot: true
    default: false
    }
  }
}

public struct AuthorityRequestEnvelope: Sendable {
  public let major: UInt16
  public let minor: UInt16
  public let requiredFeatureBits: UInt64
  public let requestID: AuthorityIdentifier
  public let command: AuthorityCommand

  public init(
    requestID: AuthorityIdentifier, requiredFeatureBits: UInt64 = 0,
    command: AuthorityCommand
  ) throws {
    let unsupported = requiredFeatureBits & ~AuthorityV1Limits.supportedFeatureBits
    guard unsupported == 0 else {
      throw AuthorityV1ValidationError.unsupportedRequiredFeatures(unsupported)
    }
    major = AuthorityV1Limits.major
    minor = AuthorityV1Limits.minor
    self.requiredFeatureBits = requiredFeatureBits
    self.requestID = requestID
    self.command = command
  }
}

public enum AuthorityEvent: Codable, Equatable, Sendable {
  case snapshot(AuthoritySnapshot)
  case revoke(StopDirective)
  case stop(StopDirective)

  enum CodingKeys: String, CodingKey { case kind, payload }
  enum Kind: String, Codable { case snapshot, revoke, stop }

  public init(from decoder: Decoder) throws {
    let value = try decoder.container(keyedBy: CodingKeys.self)
    switch try value.decode(Kind.self, forKey: .kind) {
    case .snapshot: self = .snapshot(try value.decode(AuthoritySnapshot.self, forKey: .payload))
    case .revoke: self = .revoke(try value.decode(StopDirective.self, forKey: .payload))
    case .stop: self = .stop(try value.decode(StopDirective.self, forKey: .payload))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var value = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .snapshot(let payload):
      try value.encode(Kind.snapshot, forKey: .kind)
      try value.encode(payload, forKey: .payload)
    case .revoke(let payload):
      try value.encode(Kind.revoke, forKey: .kind)
      try value.encode(payload, forKey: .payload)
    case .stop(let payload):
      try value.encode(Kind.stop, forKey: .kind)
      try value.encode(payload, forKey: .payload)
    }
  }
}

public struct AuthorityConcurrencyLimits: Equatable, Sendable {
  public let maximumReadOnlyRequests = AuthorityV1Limits.maximumReadOnlyRequests
  public let maximumMutatingTransactions = AuthorityV1Limits.maximumMutatingTransactions
  public let maximumQueuedEventsPerPeer = AuthorityV1Limits.maximumQueuedEventsPerPeer
  public init() {}
}

public struct AuthorityResponseEnvelope<Payload: Codable & Sendable>: Codable, Sendable {
  public let major: UInt16
  public let minor: UInt16
  public let requestID: AuthorityIdentifier
  public let operationID: AuthorityIdentifier?
  public let result: Payload

  public init(
    requestID: AuthorityIdentifier, operationID: AuthorityIdentifier?, result: Payload
  ) {
    major = AuthorityV1Limits.major
    minor = AuthorityV1Limits.minor
    self.requestID = requestID
    self.operationID = operationID
    self.result = result
  }

  enum CodingKeys: String, CodingKey {
    case major, minor
    case requestID = "request_id"
    case operationID = "operation_id"
    case result
  }
}

/// Marker used by the canonical codec. Every public wire model validates semantic
/// invariants after decoding; secret-bearing types deliberately do not conform.
public protocol AuthorityV1WireModel: Codable, Sendable {
  func validateAuthorityV1() throws
}

extension AuthorityProtocolVersion: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try AuthorityProtocolVersion(
      major: major, minor: minor, minimumMinor: minimumMinor,
      featureBits: featureBits, maxMessageBytes: maxMessageBytes)
  }
}
extension RootContext: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try RootContext(installationID: installationID, epoch: epoch, generation: generation)
  }
}
extension OperationContext: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try root.validateAuthorityV1()
    _ = try OperationContext(
      operationID: operationID, root: root, mode: mode, configSHA256: configSHA256,
      identitySHA256: identitySHA256, ownerUID: ownerUID,
      authorityRevision: authorityRevision)
  }
}
extension GlobalLease: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try GlobalLease(
      leaseID: leaseID, operation: operation, state: state,
      issuedMonotonic: issuedMonotonic, expiryMonotonic: expiryMonotonic,
      ownerConnectionNonce: ownerConnectionNonce)
  }
}
extension ReplayCursor: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    guard schemaVersion == 1 else { throw AuthorityV1ValidationError.invalidContext }
    _ = try ReplayCursor(
      installationID: installationID, acceptedEpoch: acceptedEpoch,
      acceptedGeneration: acceptedGeneration, revision: revision,
      previousRecordSHA256: previousRecordSHA256)
  }
}
extension AuthorityConfigurationDescriptor: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try AuthorityConfigurationDescriptor(
      byteCount: byteCount, configSHA256: configSHA256,
      identitySHA256: identitySHA256, credentialAudience: credentialAudience,
      credentialSlots: credentialSlots,
      tunnelOptions: tunnelOptions)
  }
}
extension LeaseView: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try LeaseView(
      leaseID: leaseID, operation: operation, state: state,
      expiryMonotonic: expiryMonotonic)
  }
}
extension AuthorityFailureSummary: AuthorityV1WireModel {
  public func validateAuthorityV1() throws { _ = try AuthorityFailureSummary(code: code) }
}
extension AuthoritySnapshot: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try protocolVersion.validateAuthorityV1()
    try replayCursor?.validateAuthorityV1()
    try leaseView?.validateAuthorityV1()
    try lastFailure?.validateAuthorityV1()
    _ = try AuthoritySnapshot(
      protocolVersion: protocolVersion, state: state, revision: revision,
      replayCursor: replayCursor, leaseView: leaseView,
      lastFailure: lastFailure, consoleUID: consoleUID)
  }
}
extension PacketPumpLimits: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try PacketPumpLimits(
      maximumQueuedPackets: maximumQueuedPackets,
      maximumQueuedBytes: maximumQueuedBytes,
      maximumPacketBytes: maximumPacketBytes,
      maximumReadBatch: maximumReadBatch)
  }
}
extension ReadyAttestation: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    try packetPumpLimits?.validateAuthorityV1()
    _ = try ReadyAttestation(
      operation: operation, leaseID: leaseID, runtimeDigest: runtimeDigest,
      ownerRole: ownerRole, readyFlags: readyFlags,
      packetPumpLimits: packetPumpLimits, monotonicTimestamp: monotonicTimestamp)
  }
}
extension StoppedAttestation: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try StoppedAttestation(
      operation: operation, leaseID: leaseID, libboxStopped: libboxStopped,
      transportClosed: transportClosed, osRestored: osRestored,
      monotonicTimestamp: monotonicTimestamp)
  }
}
extension TunnelPreferenceValues: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try TunnelPreferenceValues(
      descriptorSHA256: descriptorSHA256, isEnabled: isEnabled,
      localizedDescription: localizedDescription)
  }
}
extension PreferenceMutationReceipt: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try priorValues?.validateAuthorityV1()
    _ = try PreferenceMutationReceipt(
      operationID: operationID, createdManager: createdManager,
      priorValues: priorValues, writtenDescriptorSHA256: writtenDescriptorSHA256)
  }
}
extension HandshakeRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws { try version.validateAuthorityV1() }
}
extension HandshakeResponse: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try version.validateAuthorityV1()
    guard self == (try HandshakeResponse.v1()) else {
      throw AuthorityV1ValidationError.boundViolation
    }
  }
}
extension PrepareStartRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    try configuration.validateAuthorityV1()
    _ = try PrepareStartRequest(
      operation: operation, expectedRevision: expectedRevision,
      configuration: configuration)
  }
}
extension ProxyOwnerContext: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try ProxyOwnerContext(operation: operation, leaseID: leaseID)
  }
}
extension BeginStopRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try BeginStopRequest(
      operation: operation, leaseID: leaseID, expectedRevision: expectedRevision)
  }
}
extension CompleteStopRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try CompleteStopRequest(
      operation: operation, leaseID: leaseID,
      expectedRevision: expectedRevision)
  }
}
extension RecoveryProxyOffEvidence: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = RecoveryProxyOffEvidence(
      ownershipCleared: ownershipCleared,
      listenerClosed: listenerClosed,
      effectiveSystemConfigurationRestored: effectiveSystemConfigurationRestored)
  }
}
extension RecoveryProviderOffEvidence: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = RecoveryProviderOffEvidence(
      ownershipCleared: ownershipCleared,
      libboxStopped: libboxStopped,
      packetPumpClosed: packetPumpClosed)
  }
}
extension ReconcileOffRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try replayCursor.validateAuthorityV1()
    try proxy.validateAuthorityV1()
    try provider.validateAuthorityV1()
    _ = try ReconcileOffRequest(
      expectedRevision: expectedRevision,
      replayCursor: replayCursor,
      proxy: proxy,
      provider: provider,
      managedTunnel: managedTunnel)
  }
}
extension ReconcileOffReceipt: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try replayCursor.validateAuthorityV1()
    _ = try ReconcileOffReceipt(
      revision: revision,
      replayCursor: replayCursor)
  }
}
extension StopDirective: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try StopDirective(
      operation: operation, leaseID: leaseID,
      deadlineMonotonic: deadlineMonotonic, revision: revision)
  }
}
extension CancelPreparedRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    _ = try CancelPreparedRequest(operation: operation, expectedRevision: expectedRevision)
  }
}
extension SnapshotRequest: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {}
}
extension AuthorityAcknowledgement: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    guard revision > 0 else { throw AuthorityV1ValidationError.invalidContext }
  }
}
extension AuthorityEvent: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    switch self {
    case .snapshot(let value): try value.validateAuthorityV1()
    case .revoke(let value), .stop(let value): try value.validateAuthorityV1()
    }
  }
}
extension AuthorityResponseEnvelope: AuthorityV1WireModel where Payload: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    guard major == AuthorityV1Limits.major else {
      throw AuthorityV1ValidationError.unsupportedMajor(major)
    }
    guard minor == AuthorityV1Limits.minor else {
      throw AuthorityV1ValidationError.unsupportedMinor(minor)
    }
    try result.validateAuthorityV1()
  }
}

// Stable Authority-domain failures. Policy is derived only from these codes,
// never from localized XPC, Security.framework, or NetworkExtension text.
public enum AuthorityRetryDirective: String, Codable, Equatable, Sendable {
  case never
  case idempotentReadOnly = "idempotent_read_only"
  case registrationStatusChange = "registration_status_change"
  case compatibleSoftwareUpdate = "compatible_software_update"
  case freshSnapshotAfterOff = "fresh_snapshot_after_off"
  case freshContext = "fresh_context"
  case freshGenerationAfterOff = "fresh_generation_after_off"
  case explicitReconciliation = "explicit_reconciliation"
  case maintenanceRequired = "maintenance_required"
}

public enum AuthorityOperationClass: Equatable, Sendable {
  case idempotentReadOnly
  case mutation
}

public enum AuthorityErrorCode: String, Codable, CaseIterable, Sendable {
  case globalAuthorityUnavailable = "global_authority_unavailable"
  case globalAuthorityRegistrationRequired = "global_authority_registration_required"
  case globalAuthorityApprovalRequired = "global_authority_approval_required"
  case globalAuthorityIdentityRejected = "global_authority_identity_rejected"
  case globalAuthorityProtocolMismatch = "global_authority_protocol_mismatch"
  case globalAuthorityRecovering = "global_authority_recovering"
  case globalAuthorityTimeout = "global_authority_timeout"
  case globalAuthorityInterrupted = "global_authority_interrupted"
  case busy
  case resourceExhausted = "resource_exhausted"
  case journalCapacityExhausted = "journal_capacity_exhausted"
  case staleOperation = "stale_operation"
  case replayRejected = "replay_rejected"
  case globalLeaseConflict = "global_lease_conflict"
  case ticketExpired = "ticket_expired"
  case ticketAlreadyRedeemed = "ticket_already_redeemed"
  case ticketInvalid = "ticket_invalid"
  case cleanupUnproven = "cleanup_unproven"
  case compensationConflict = "compensation_conflict"
  case quarantined
  case invalidMessage = "invalid_message"
  case secretBoundsExceeded = "secret_bounds_exceeded"
  case secretLifecycleViolation = "secret_lifecycle_violation"
  case journalCorrupt = "journal_corrupt"
  case ownerUnresponsive = "owner_unresponsive"

  public var nativeBridgeCode: NativeBridgeErrorCode {
    switch self {
    case .globalAuthorityUnavailable: .globalAuthorityUnavailable
    case .globalAuthorityRegistrationRequired: .globalAuthorityRegistrationRequired
    case .globalAuthorityApprovalRequired: .globalAuthorityApprovalRequired
    case .globalAuthorityIdentityRejected: .globalAuthorityIdentityRejected
    case .globalAuthorityProtocolMismatch: .globalAuthorityProtocolMismatch
    case .globalAuthorityRecovering: .globalAuthorityRecovering
    case .globalAuthorityTimeout: .globalAuthorityTimeout
    case .globalAuthorityInterrupted: .globalAuthorityInterrupted
    case .busy: .busy
    case .resourceExhausted: .resourceExhausted
    case .journalCapacityExhausted: .journalCapacityExhausted
    case .staleOperation: .staleOperation
    case .replayRejected: .replayRejected
    case .globalLeaseConflict: .globalLeaseConflict
    case .ticketExpired: .ticketExpired
    case .ticketAlreadyRedeemed: .ticketAlreadyRedeemed
    case .ticketInvalid: .ticketInvalid
    case .cleanupUnproven: .cleanupUnproven
    case .compensationConflict: .compensationConflict
    case .quarantined: .quarantined
    case .invalidMessage: .invalidMessage
    case .secretBoundsExceeded: .secretBoundsExceeded
    case .secretLifecycleViolation: .secretLifecycleViolation
    case .journalCorrupt: .journalCorrupt
    case .ownerUnresponsive: .ownerUnresponsive
    }
  }

  public var retryDirective: AuthorityRetryDirective {
    switch self {
    case .resourceExhausted, .ownerUnresponsive, .globalAuthorityTimeout,
      .globalAuthorityInterrupted:
      .idempotentReadOnly
    case .journalCapacityExhausted:
      .maintenanceRequired
    case .globalAuthorityUnavailable, .globalAuthorityRegistrationRequired,
      .globalAuthorityApprovalRequired:
      .registrationStatusChange
    case .globalAuthorityProtocolMismatch:
      .compatibleSoftwareUpdate
    case .busy, .globalLeaseConflict:
      .freshSnapshotAfterOff
    case .staleOperation, .replayRejected:
      .freshContext
    case .ticketExpired, .ticketAlreadyRedeemed:
      .freshGenerationAfterOff
    case .globalAuthorityRecovering, .secretLifecycleViolation, .cleanupUnproven,
      .compensationConflict, .quarantined, .journalCorrupt:
      .explicitReconciliation
    case .globalAuthorityIdentityRejected, .ticketInvalid, .invalidMessage,
      .secretBoundsExceeded:
      .never
    }
  }

  public func allowsAutomaticRetry(for operation: AuthorityOperationClass) -> Bool {
    operation == .idempotentReadOnly && retryDirective == .idempotentReadOnly
  }

  public var stableMessage: String {
    switch self {
    case .globalAuthorityUnavailable: "Global Authority is unavailable."
    case .globalAuthorityRegistrationRequired: "Global Authority registration is required."
    case .globalAuthorityApprovalRequired: "Global Authority approval is required."
    case .globalAuthorityIdentityRejected: "Global Authority peer identity was rejected."
    case .globalAuthorityProtocolMismatch: "Global Authority protocol is incompatible."
    case .globalAuthorityRecovering: "Global Authority is recovering; starts are disabled."
    case .globalAuthorityTimeout: "The Authority operation timed out."
    case .globalAuthorityInterrupted: "The Authority connection was interrupted."
    case .busy: "Global Authority mutation is busy."
    case .resourceExhausted: "Global Authority read capacity is exhausted."
    case .journalCapacityExhausted:
      "The Global Authority journal reached its fixed capacity and requires maintenance."
    case .staleOperation: "Authority operation context is stale."
    case .replayRejected: "Authority replay protection rejected the context."
    case .globalLeaseConflict: "A conflicting Global Authority lease exists."
    case .ticketExpired: "The Authority start ticket expired."
    case .ticketAlreadyRedeemed: "The Authority start ticket was already redeemed."
    case .ticketInvalid: "The Authority start ticket is invalid."
    case .cleanupUnproven: "Global cleanup could not be proven."
    case .compensationConflict: "Tunnel preference compensation conflicted."
    case .quarantined: "Global Authority is quarantined pending reconciliation."
    case .invalidMessage: "The Authority message is invalid."
    case .secretBoundsExceeded: "Authority secret material exceeds a fixed bound."
    case .secretLifecycleViolation: "Authority secret lifecycle verification failed."
    case .journalCorrupt: "The Authority journal is corrupt."
    case .ownerUnresponsive: "The Authority engine owner is unresponsive."
    }
  }
}

public struct AuthorityDiagnosticContext: Equatable, Sendable {
  public let operationID: AuthorityIdentifier?
  public let generation: UInt64?
  public let role: AuthorityRole?
  public let digestPrefix: String?

  public init(
    operationID: AuthorityIdentifier? = nil, generation: UInt64? = nil,
    role: AuthorityRole? = nil, digest: SHA256Digest? = nil
  ) {
    self.operationID = operationID
    self.generation = generation
    self.role = role
    digestPrefix = digest.map { String($0.hex.prefix(12)) }
  }
}

public struct AuthorityDomainError: Error, Equatable, Sendable, CustomStringConvertible {
  public let code: AuthorityErrorCode
  public let context: AuthorityDiagnosticContext

  public init(code: AuthorityErrorCode, context: AuthorityDiagnosticContext = .init()) {
    self.code = code
    self.context = context
  }

  public var description: String {
    var fields = ["code=\(code.rawValue)", "message=\(code.stableMessage)"]
    if let operationID = context.operationID {
      fields.append("operation_id=\(operationID.rawValue.uuidString.lowercased())")
    }
    if let generation = context.generation { fields.append("generation=\(generation)") }
    if let role = context.role { fields.append("role=\(role.rawValue)") }
    if let digestPrefix = context.digestPrefix { fields.append("digest_prefix=\(digestPrefix)") }
    return fields.joined(separator: " ")
  }

  public var nativeBridgeFailure: NativeBridgeFailure {
    NativeBridgeFailure(code: code.nativeBridgeCode, message: description)
  }
}
