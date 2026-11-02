import Foundation

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
      operation.mode.isProxyAgent == (ownerCapability != nil),
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
    guard operation.mode.isProxyAgent else {
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

/// A ProxyAgent's question whether the Authority still holds the lease it
/// bound. The Authority answers only for the caller's own lease, as the
/// authenticated connection identifies the caller, never as these bytes do.
public struct OwnerLeaseStatusRequest: Codable, Equatable, Sendable {
  public let leaseID: AuthorityIdentifier

  public init(leaseID: AuthorityIdentifier) {
    self.leaseID = leaseID
  }

  enum CodingKeys: String, CodingKey {
    case leaseID = "lease_id"
  }
}

/// What the Authority knows of one owner's lease.
public enum OwnerLeaseStatus: String, Codable, Equatable, Sendable {
  /// The Authority holds the lease, and its stop can still complete.
  case held
  /// The Authority holds the lease in a quarantine: its stop can no longer
  /// complete, and the Authority releases it once the owner's process ended.
  case quarantined
  /// The Authority read its journal and holds no such lease.
  case absent
  /// The Authority has not read its journal, or quarantined the journal it
  /// read, so it cannot tell whether such a lease exists.
  case notReady = "not_ready"
}

public struct OwnerLeaseStatusResponse: Codable, Equatable, Sendable {
  public let status: OwnerLeaseStatus

  public init(status: OwnerLeaseStatus) {
    self.status = status
  }
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
