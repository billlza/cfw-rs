import CFWSharedProtocol
import Foundation

public enum ManagedTunnelObservation: Equatable, Sendable {
  case disconnected
  case invalid
  case connecting
  case connected
  case unknown
}

public enum AuthorityCleanupObservation: Equatable, Sendable {
  case systemProxy(listenerClosed: Bool, systemConfigurationRestored: Bool)
  case tunnel(libboxStopped: Bool, packetPumpClosed: Bool)
  case reconciledBoth(
    proxyListenerClosed: Bool, systemConfigurationRestored: Bool,
    providerLibboxStopped: Bool, packetPumpClosed: Bool)
  case unknown
}

public struct GlobalOffProof: Equatable, Sendable {
  public let leaseReleased: Bool
  public let capabilityOrTicketCleared: Bool
  public let secretBufferCleared: Bool
  public let ownerEndpointCleared: Bool
  public let cleanup: AuthorityCleanupObservation
  public let managedTunnel: ManagedTunnelObservation

  public init(
    leaseReleased: Bool, capabilityOrTicketCleared: Bool,
    secretBufferCleared: Bool, ownerEndpointCleared: Bool,
    cleanup: AuthorityCleanupObservation, managedTunnel: ManagedTunnelObservation
  ) {
    self.leaseReleased = leaseReleased
    self.capabilityOrTicketCleared = capabilityOrTicketCleared
    self.secretBufferCleared = secretBufferCleared
    self.ownerEndpointCleared = ownerEndpointCleared
    self.cleanup = cleanup
    self.managedTunnel = managedTunnel
  }
}

public struct AuthorityOwnerBinding: Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let leaseOwnerUID: UInt32
  public let connectionNonce: SHA256Digest
  public let role: AuthorityRole
  public let mode: AuthorityMode

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    leaseOwnerUID: UInt32, connectionNonce: SHA256Digest,
    role: AuthorityRole, mode: AuthorityMode
  ) {
    self.operation = operation
    self.leaseID = leaseID
    self.leaseOwnerUID = leaseOwnerUID
    self.connectionNonce = connectionNonce
    self.role = role
    self.mode = mode
  }
}

public struct AuthorityPrepareInput: Sendable {
  public let request: PrepareStartRequest
  public let leaseID: AuthorityIdentifier
  public let ownerConnectionNonce: SHA256Digest
  public let issuedMonotonic: UInt64
  public let expiryMonotonic: UInt64
  public let retainsSecretBuffer: Bool

  public init(
    request: PrepareStartRequest, leaseID: AuthorityIdentifier,
    ownerConnectionNonce: SHA256Digest, issuedMonotonic: UInt64,
    expiryMonotonic: UInt64, retainsSecretBuffer: Bool
  ) {
    self.request = request
    self.leaseID = leaseID
    self.ownerConnectionNonce = ownerConnectionNonce
    self.issuedMonotonic = issuedMonotonic
    self.expiryMonotonic = expiryMonotonic
    self.retainsSecretBuffer = retainsSecretBuffer
  }
}

public enum AuthorityCapabilityCommand: Equatable, Sendable {
  case issueProxyCapability
  case issueTunnelTicket
}

public struct AuthorityPrepareAuthorization: Equatable, Sendable {
  public let leaseID: AuthorityIdentifier
  public let operation: OperationContext
  public let command: AuthorityCapabilityCommand
  public let committedRevision: UInt64
}

public enum AuthorityPendingMutation: Equatable, Sendable {
  case prepare(AuthorityIdentifier)
  case transition(AuthorityIdentifier)
  case globalOff(AuthorityIdentifier?)
}

public enum AuthorityDurableMutationKind: String, Equatable, Sendable {
  case enrollOff = "enroll_off"
  case prepare
  case bindOwner = "bind_owner"
  case ready
  case beginStop = "begin_stop"
  case ownerStopped = "owner_stopped"
  case abortPrepared = "abort_prepared"
  case revokeForConsoleChange = "revoke_for_console_change"
  case revokeForTimeout = "revoke_for_timeout"
  case globalOff = "global_off"
  case reconcileOff = "reconcile_off"
}

public enum AuthorityOffResolution: Equatable, Sendable {
  case off(revision: UInt64)
  case quarantined(revision: UInt64)
}
/// Pure machine-wide ownership reducer. Callers serialize durable mutation and persist the
/// resulting revision before acting on an authorization returned by this value.
public struct GlobalAuthorityReducer: Equatable, Sendable {
  public private(set) var state: AuthorityState
  public private(set) var revision: UInt64
  public private(set) var enrolledInstallationID: AuthorityIdentifier?
  public private(set) var replayCursor: ReplayCursor?
  public private(set) var lease: GlobalLease?
  public private(set) var ownerBinding: AuthorityOwnerBinding?
  public private(set) var pendingMutation: AuthorityPendingMutation?
  public private(set) var retainsCapabilityOrTicket: Bool
  public private(set) var retainsSecretBuffer: Bool
  public private(set) var ownerStopped: Bool
  public private(set) var lastMutation: AuthorityDurableMutationKind?
  private var acceptedReadyAttestation: ReadyAttestation?

  public var installationID: AuthorityIdentifier? {
    replayCursor?.installationID ?? enrolledInstallationID
  }

  public init(
    state: AuthorityState = .recovering, revision: UInt64,
    enrolledInstallationID: AuthorityIdentifier? = nil,
    replayCursor: ReplayCursor? = nil, lease: GlobalLease? = nil,
    ownerBinding: AuthorityOwnerBinding? = nil,
    retainsCapabilityOrTicket: Bool = false,
    retainsSecretBuffer: Bool = false, ownerStopped: Bool = false
  ) throws {
    guard revision > 0, replayCursor?.revision ?? 0 <= revision else {
      throw AuthorityDomainError(code: .journalCorrupt)
    }
    switch state {
    case .off:
      guard lease == nil, ownerBinding == nil else {
        throw AuthorityDomainError(code: .journalCorrupt)
      }
    case .preparing, .starting, .active, .stopping:
      guard lease != nil else { throw AuthorityDomainError(code: .journalCorrupt) }
    case .recovering, .quarantined:
      break
    }
    guard ownerBinding == nil || lease != nil else {
      throw AuthorityDomainError(code: .journalCorrupt)
    }
    if let cursor = replayCursor, let lease {
      guard cursor.installationID == lease.operation.root.installationID,
        (cursor.acceptedEpoch, cursor.acceptedGeneration)
          >= (lease.operation.root.epoch, lease.operation.root.generation)
      else { throw AuthorityDomainError(code: .journalCorrupt) }
    }
    if let cursor = replayCursor, let enrolledInstallationID {
      guard cursor.installationID == enrolledInstallationID else {
        throw AuthorityDomainError(code: .journalCorrupt)
      }
    }
    self.state = state
    self.revision = revision
    self.enrolledInstallationID =
      enrolledInstallationID ?? replayCursor?.installationID
    self.replayCursor = replayCursor
    self.lease = lease
    self.ownerBinding = ownerBinding
    pendingMutation = nil
    self.retainsCapabilityOrTicket = retainsCapabilityOrTicket
    self.retainsSecretBuffer = retainsSecretBuffer
    self.ownerStopped = ownerStopped
    lastMutation = nil
    acceptedReadyAttestation = nil
  }

  public static func unEnrolledOff(revision: UInt64 = 1) throws -> Self {
    try Self(state: .off, revision: revision)
  }

  public static func enrolledOff(
    installationID: AuthorityIdentifier, revision: UInt64 = 1
  ) throws -> Self {
    try Self(
      state: .off, revision: revision,
      enrolledInstallationID: installationID)
  }

  public static func recovering(
    revision: UInt64, replayCursor: ReplayCursor?,
    enrolledInstallationID: AuthorityIdentifier? = nil,
    lease: GlobalLease? = nil,
    ownerBinding: AuthorityOwnerBinding? = nil,
    retainsCapabilityOrTicket: Bool = false, retainsSecretBuffer: Bool = false
  ) throws -> Self {
    // Recovery never treats durable prepared/active metadata as an executable lease.
    // It is retained only while the owner and OS are reconciled.
    try Self(
      state: .recovering,
      revision: revision,
      enrolledInstallationID: enrolledInstallationID,
      replayCursor: replayCursor, lease: lease,
      ownerBinding: ownerBinding,
      retainsCapabilityOrTicket: retainsCapabilityOrTicket,
      retainsSecretBuffer: retainsSecretBuffer)
  }

  /// Persists installation enrollment as an Off genesis record before any
  /// prepare can retain a lease, capability, ticket, configuration, or secret.
  /// The in-memory bootstrap revision is the first durable revision, so this
  /// transition deliberately does not increment it.
  public mutating func enrollOff(_ installationID: AuthorityIdentifier) throws {
    guard state == .off, replayCursor == nil, enrolledInstallationID == nil,
      lease == nil, ownerBinding == nil, !retainsCapabilityOrTicket,
      !retainsSecretBuffer, pendingMutation == nil
    else { throw AuthorityDomainError(code: .journalCorrupt) }
    enrolledInstallationID = installationID
    lastMutation = .enrollOff
  }

  @discardableResult
  public mutating func prepare(
    _ input: AuthorityPrepareInput
  ) throws -> AuthorityPrepareAuthorization {
    let operation = input.request.operation
    try requireExpectedRevision(input.request.expectedRevision, operation: operation)
    guard pendingMutation == nil else { throw failure(.busy, operation) }
    switch state {
    case .recovering: throw failure(.globalAuthorityRecovering, operation)
    case .quarantined: throw failure(.quarantined, operation)
    case .off: break
    default: throw failure(.globalLeaseConflict, operation)
    }
    guard lease == nil, ownerBinding == nil, !retainsCapabilityOrTicket,
      !retainsSecretBuffer
    else { throw failure(.globalLeaseConflict, operation) }

    let root = operation.root
    if let enrolledInstallationID,
      enrolledInstallationID != root.installationID
    {
      throw failure(.replayRejected, operation)
    }
    if let cursor = replayCursor {
      guard cursor.installationID == root.installationID else {
        throw failure(.replayRejected, operation)
      }
      guard
        (root.epoch, root.generation)
          > (cursor.acceptedEpoch, cursor.acceptedGeneration)
      else { throw failure(.replayRejected, operation) }
    }
    guard input.issuedMonotonic > 0,
      input.expiryMonotonic > input.issuedMonotonic,
      input.expiryMonotonic - input.issuedMonotonic
        <= AuthorityV1Limits.preparationLifetimeMilliseconds,
      operation.mode == .tunnel || !input.retainsSecretBuffer
    else { throw failure(.invalidMessage, operation) }

    let committedRevision = try incrementedRevision()
    let previousDigest: SHA256Digest
    if let existingDigest = replayCursor?.previousRecordSHA256 {
      previousDigest = existingDigest
    } else {
      previousDigest = try SHA256Digest(hex: String(repeating: "0", count: 64))
    }
    let newCursor = try ReplayCursor(
      installationID: root.installationID, acceptedEpoch: root.epoch,
      acceptedGeneration: root.generation, revision: committedRevision,
      previousRecordSHA256: previousDigest)
    let newLease = try GlobalLease(
      leaseID: input.leaseID, operation: operation, state: .prepared,
      issuedMonotonic: input.issuedMonotonic,
      expiryMonotonic: input.expiryMonotonic,
      ownerConnectionNonce: input.ownerConnectionNonce)

    pendingMutation = .prepare(operation.operationID)
    enrolledInstallationID = root.installationID
    replayCursor = newCursor
    lease = newLease
    ownerBinding = nil
    retainsCapabilityOrTicket = true
    retainsSecretBuffer = input.retainsSecretBuffer
    ownerStopped = false
    state = .preparing
    revision = committedRevision
    lastMutation = .prepare
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return AuthorityPrepareAuthorization(
      leaseID: input.leaseID, operation: operation,
      command: operation.mode == .tunnel ? .issueTunnelTicket : .issueProxyCapability,
      committedRevision: committedRevision)
  }

  /// Synchronizes the public replay cursor with the exact record hash returned
  /// by the durable store. Call only after the record and trusted anchor commit.
  public mutating func recordPersistedHead(
    _ head: AuthorityJournalHead
  ) throws {
    guard let cursor = replayCursor, cursor.revision == revision else { return }
    replayCursor = try ReplayCursor(
      installationID: cursor.installationID,
      acceptedEpoch: cursor.acceptedEpoch,
      acceptedGeneration: cursor.acceptedGeneration,
      revision: cursor.revision,
      previousRecordSHA256: head.recordSHA256)
  }

  @discardableResult
  public mutating func bindOwner(_ binding: AuthorityOwnerBinding) throws -> UInt64 {
    guard pendingMutation == nil else { throw failure(.busy, binding.operation) }
    guard state == .preparing, let current = lease else {
      throw failure(.globalLeaseConflict, binding.operation)
    }
    try requireExactLease(
      operation: binding.operation, leaseID: binding.leaseID,
      ownerUID: binding.leaseOwnerUID, connectionNonce: binding.connectionNonce)
    let expectedRole: AuthorityRole = current.operation.mode == .tunnel ? .provider : .proxyAgent
    guard binding.role == expectedRole, binding.mode == current.operation.mode else {
      throw failure(.globalAuthorityIdentityRejected, binding.operation, role: binding.role)
    }

    let next = try incrementedRevision()
    pendingMutation = .transition(binding.operation.operationID)
    lease = try replacingLeaseState(.starting, current)
    ownerBinding = binding
    state = .starting
    revision = next
    lastMutation = .bindOwner
    pendingMutation = nil
    return next
  }
  @discardableResult
  public mutating func attestReady(
    _ attestation: ReadyAttestation,
    ownerUID: UInt32, connectionNonce: SHA256Digest
  ) throws -> UInt64 {
    guard pendingMutation == nil else { throw failure(.busy, attestation.operation) }
    guard state == .starting || state == .active,
      let current = lease,
      let binding = ownerBinding
    else {
      throw failure(.staleOperation, attestation.operation)
    }
    try requireExactLease(
      operation: attestation.operation, leaseID: attestation.leaseID,
      ownerUID: ownerUID, connectionNonce: connectionNonce)
    guard binding.role == attestation.ownerRole,
      binding.operation == attestation.operation,
      attestation.runtimeDigest == attestation.operation.identitySHA256,
      attestation.readyFlags == .all
    else { throw failure(.staleOperation, attestation.operation, role: attestation.ownerRole) }
    if state == .active {
      guard current.state == .active,
        lastMutation == .ready,
        acceptedReadyAttestation == attestation
      else {
        throw failure(.staleOperation, attestation.operation)
      }
      return revision
    }

    let next = try incrementedRevision()
    pendingMutation = .transition(attestation.operation.operationID)
    lease = try replacingLeaseState(.active, current)
    state = .active
    revision = next
    lastMutation = .ready
    acceptedReadyAttestation = attestation
    pendingMutation = nil
    return next
  }

  @discardableResult
  public mutating func abortPrepared(
    operation: OperationContext, expectedRevision: UInt64
  ) throws -> UInt64 {
    try requireExpectedRevision(expectedRevision, operation: operation)
    guard pendingMutation == nil else { throw failure(.busy, operation) }
    guard state == .preparing, let current = lease,
      current.operation == operation
    else { throw failure(.staleOperation, operation) }

    let next = try incrementedRevision()
    pendingMutation = .transition(operation.operationID)
    lease = try replacingLeaseState(.stopping, current)
    ownerBinding = nil
    retainsCapabilityOrTicket = false
    retainsSecretBuffer = false
    ownerStopped = true
    state = .stopping
    revision = next
    lastMutation = .abortPrepared
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return next
  }

  @discardableResult
  public mutating func beginStop(_ request: BeginStopRequest) throws -> UInt64 {
    guard pendingMutation == nil else { throw failure(.busy, request.operation) }
    guard let current = lease else { throw failure(.staleOperation, request.operation) }
    try requireExactLease(operation: request.operation, leaseID: request.leaseID)
    if state == .stopping {
      if request.expectedRevision == revision { return revision }
      let (replayedRevision, overflow) =
        request.expectedRevision.addingReportingOverflow(1)
      guard !overflow,
        replayedRevision == revision,
        lastMutation == .beginStop
      else { throw failure(.staleOperation, request.operation) }
      return revision
    }
    try requireExpectedRevision(request.expectedRevision, operation: request.operation)
    guard state == .preparing || state == .starting || state == .active else {
      throw failure(.staleOperation, request.operation)
    }

    let next = try incrementedRevision()
    pendingMutation = .transition(request.operation.operationID)
    lease = try replacingLeaseState(.stopping, current)
    retainsCapabilityOrTicket = false
    retainsSecretBuffer = false
    ownerStopped = false
    state = .stopping
    revision = next
    lastMutation = .beginStop
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return next
  }

  @discardableResult
  public mutating func revokeForConsoleChange(
    liveConsoleUID: UInt32?, ownerConnectionNonce: SHA256Digest
  ) throws -> UInt64 {
    guard pendingMutation == nil else { throw AuthorityDomainError(code: .busy) }
    guard let current = lease else { return revision }
    guard current.ownerConnectionNonce == ownerConnectionNonce else {
      throw failure(.globalAuthorityIdentityRejected, current.operation)
    }
    guard liveConsoleUID != current.operation.ownerUID else { return revision }
    if state == .stopping { return revision }
    guard state == .preparing || state == .starting || state == .active else {
      throw failure(.staleOperation, current.operation)
    }

    let next = try incrementedRevision()
    pendingMutation = .transition(current.operation.operationID)
    lease = try replacingLeaseState(.revoked, current)
    retainsCapabilityOrTicket = false
    retainsSecretBuffer = false
    ownerStopped = false
    state = .stopping
    revision = next
    lastMutation = .revokeForConsoleChange
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return next
  }

  /// Forced revocation for owner-liveness failures: missed heartbeat, connection
  /// loss, owner identity drift, or an elapsed owner stop/reattest timeout. Unlike
  /// `revokeForConsoleChange` this is not bound to the owner connection nonce because
  /// the trigger is the loss or timeout of that very owner channel. It moves any live
  /// owner to `stopping`/`revoked` and never transfers or discloses the lease.
  @discardableResult
  public mutating func revokeForLiveness() throws -> UInt64 {
    guard pendingMutation == nil else { throw AuthorityDomainError(code: .busy) }
    guard let current = lease else { return revision }
    if state == .stopping { return revision }
    guard state == .preparing || state == .starting || state == .active else {
      throw failure(.staleOperation, current.operation)
    }

    let next = try incrementedRevision()
    pendingMutation = .transition(current.operation.operationID)
    lease = try replacingLeaseState(.revoked, current)
    retainsCapabilityOrTicket = false
    retainsSecretBuffer = false
    ownerStopped = false
    state = .stopping
    revision = next
    lastMutation = .revokeForTimeout
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return next
  }

  @discardableResult
  public mutating func attestStopped(
    _ attestation: StoppedAttestation, ownerUID: UInt32,
    connectionNonce: SHA256Digest
  ) throws -> UInt64 {
    guard pendingMutation == nil else { throw failure(.busy, attestation.operation) }
    guard state == .starting || state == .stopping, let current = lease else {
      throw failure(.staleOperation, attestation.operation)
    }
    try requireExactLease(
      operation: attestation.operation, leaseID: attestation.leaseID,
      ownerUID: ownerUID, connectionNonce: connectionNonce)
    guard !ownerStopped else { return revision }
    let next = try incrementedRevision()
    if state == .starting {
      pendingMutation = .transition(current.operation.operationID)
      lease = try replacingLeaseState(.stopping, current)
      retainsCapabilityOrTicket = false
      retainsSecretBuffer = false
      state = .stopping
    }
    ownerStopped = true
    revision = next
    lastMutation = .ownerStopped
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return next
  }

  @discardableResult
  public mutating func applyOffProof(
    _ proof: GlobalOffProof, expectedRevision: UInt64
  ) throws -> AuthorityOffResolution {
    try requireExpectedRevision(expectedRevision, operation: lease?.operation)
    guard pendingMutation == nil else { throw AuthorityDomainError(code: .busy) }
    guard state == .stopping || state == .recovering || state == .quarantined else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }

    let priorState = state
    let exact =
      proofIsExact(proof)
      && (priorState != .stopping || ownerStopped)
    let next = try incrementedRevision()
    pendingMutation = .globalOff(lease?.operation.operationID)
    revision = next

    if exact {
      lease = nil
      ownerBinding = nil
      retainsCapabilityOrTicket = false
      retainsSecretBuffer = false
      ownerStopped = false
      state = .off
      lastMutation =
        priorState == .quarantined || priorState == .recovering
        ? .reconcileOff : .globalOff
      acceptedReadyAttestation = nil
      pendingMutation = nil
      return .off(revision: next)
    }

    if proof.capabilityOrTicketCleared { retainsCapabilityOrTicket = false }
    if proof.secretBufferCleared { retainsSecretBuffer = false }
    if proof.ownerEndpointCleared { ownerBinding = nil }
    if let current = lease { lease = try replacingLeaseState(.revoked, current) }
    state = .quarantined
    lastMutation = .reconcileOff
    acceptedReadyAttestation = nil
    pendingMutation = nil
    return .quarantined(revision: next)
  }

  /// Returns the lease only to the exact owner user and connection. This prevents a new
  /// login session from inspecting or inheriting another user's prepared/active authority.
  public func leaseForOwner(
    ownerUID: UInt32, connectionNonce: SHA256Digest
  ) throws -> GlobalLease {
    guard let lease, lease.operation.ownerUID == ownerUID,
      lease.ownerConnectionNonce == connectionNonce
    else { throw AuthorityDomainError(code: .globalAuthorityIdentityRejected) }
    return lease
  }

  private func requireExpectedRevision(
    _ expected: UInt64, operation: OperationContext?
  ) throws {
    guard expected == revision else {
      throw failure(.staleOperation, operation)
    }
  }

  private func requireExactLease(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    ownerUID: UInt32? = nil, connectionNonce: SHA256Digest? = nil
  ) throws {
    guard let lease, lease.leaseID == leaseID, lease.operation == operation else {
      throw failure(.staleOperation, operation)
    }
    if let ownerUID, lease.operation.ownerUID != ownerUID {
      throw failure(.globalAuthorityIdentityRejected, operation)
    }
    if let connectionNonce, lease.ownerConnectionNonce != connectionNonce {
      throw failure(.globalAuthorityIdentityRejected, operation)
    }
  }

  private func incrementedRevision() throws -> UInt64 {
    guard revision < UInt64.max else { throw AuthorityDomainError(code: .journalCorrupt) }
    return revision + 1
  }

  private func replacingLeaseState(
    _ state: AuthorityLeaseState, _ lease: GlobalLease
  ) throws -> GlobalLease {
    try GlobalLease(
      leaseID: lease.leaseID, operation: lease.operation, state: state,
      issuedMonotonic: lease.issuedMonotonic,
      expiryMonotonic: lease.expiryMonotonic,
      ownerConnectionNonce: lease.ownerConnectionNonce)
  }
  private func proofIsExact(_ proof: GlobalOffProof) -> Bool {
    guard proof.leaseReleased, proof.capabilityOrTicketCleared,
      proof.secretBufferCleared, proof.ownerEndpointCleared,
      managedTunnelIsOff(proof.managedTunnel)
    else { return false }

    switch proof.cleanup {
    case .systemProxy(let listenerClosed, let restored):
      return listenerClosed && restored
    case .tunnel(let libboxStopped, let packetPumpClosed):
      return libboxStopped && packetPumpClosed
    case .reconciledBoth(
      let proxyListenerClosed, let restored,
      let providerLibboxStopped, let packetPumpClosed):
      return proxyListenerClosed && restored
        && providerLibboxStopped && packetPumpClosed
    case .unknown:
      return false
    }
  }

  private func managedTunnelIsOff(_ observation: ManagedTunnelObservation) -> Bool {
    observation == .disconnected || observation == .invalid
  }

  private func failure(
    _ code: AuthorityErrorCode, _ operation: OperationContext?,
    role: AuthorityRole? = nil
  ) -> AuthorityDomainError {
    AuthorityDomainError(
      code: code,
      context: AuthorityDiagnosticContext(
        operationID: operation?.operationID,
        generation: operation?.root.generation, role: role,
        digest: operation?.configSHA256))
  }
}
