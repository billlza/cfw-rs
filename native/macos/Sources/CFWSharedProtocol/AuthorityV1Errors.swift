import Foundation

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
