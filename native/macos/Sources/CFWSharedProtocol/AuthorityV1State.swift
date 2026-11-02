import Foundation

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
  /// Recovery failures can also lack a trusted cursor. Their non-Off state
  /// remains observable and does not authorize a start or reconciliation.
  public let replayCursor: ReplayCursor?
  public let leaseView: LeaseView?
  public let lastFailure: AuthorityFailureSummary?
  public let consoleUID: UInt32?

  public init(
    protocolVersion: AuthorityProtocolVersion, state: AuthorityState, revision: UInt64,
    replayCursor: ReplayCursor?, leaseView: LeaseView?,
    lastFailure: AuthorityFailureSummary?, consoleUID: UInt32?
  ) throws {
    guard revision > 0, replayCursor?.revision ?? 0 <= revision else {
      throw AuthorityV1ValidationError.invalidState
    }
    switch state {
    case .off, .recovering:
      guard leaseView == nil else { throw AuthorityV1ValidationError.invalidState }
    case .quarantined:
      if let leaseView {
        guard replayCursor != nil, leaseView.state == .revoked else {
          throw AuthorityV1ValidationError.invalidState
        }
      }
    case .preparing, .starting, .active, .stopping:
      guard replayCursor != nil, leaseView != nil else {
        throw AuthorityV1ValidationError.invalidState
      }
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

  public static func required(for mode: AuthorityMode) -> Self {
    mode == .localProxy ? [.libboxStarted, .transportReady] : .all
  }
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
    guard ownerRole != .host, readyFlags == .required(for: operation.mode), monotonicTimestamp > 0,
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
