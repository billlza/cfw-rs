import CFWSharedProtocol
import Darwin
import Foundation
@preconcurrency import SystemConfiguration

import struct CryptoKit.SHA256

public protocol AuthorityJournalCommitting: Sendable {
  @discardableResult
  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead
}

extension DescriptorRelativeAuthorityJournalStore: AuthorityJournalCommitting {}

public final class AuthorityConcurrencyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var reads = 0
  private var mutation = false

  public init() {}

  public func withRead<Result>(_ body: () throws -> Result) throws -> Result {
    try lock.withLock {
      guard reads < AuthorityV1Limits.maximumReadOnlyRequests else {
        throw AuthorityDomainError(code: .resourceExhausted)
      }
      reads += 1
    }
    defer { lock.withLock { reads -= 1 } }
    return try body()
  }

  public func withMutation<Result>(_ body: () throws -> Result) throws -> Result {
    try lock.withLock {
      guard !mutation else { throw AuthorityDomainError(code: .busy) }
      mutation = true
    }
    defer { lock.withLock { mutation = false } }
    return try body()
  }
}
private struct PendingProxyCapability {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
  let digest: SHA256Digest
  let expiresMonotonic: UInt64
}

/// The reasons the Authority forcibly revokes and stops the current owner outside a
/// cooperative `beginStop`. Every reason fails closed: the owner is ordered to stop
/// within the bounded deadline and the lease is never transferred to another user.
public enum AuthorityLivenessTrigger: Equatable, Sendable {
  case logout
  case consoleUserChange
  case connectionLoss
  case missedHeartbeat
  case ownerIdentityDrift
  case ownerStopTimeout
  case reattestTimeout
}

/// Result of a forced revocation. `directive` (when present) must be delivered to the
/// owner peer as a revocation event so the owner stops within the deadline; the queue
/// preserves revocation/stop events under saturation.
public struct AuthorityForcedStopOutcome: Sendable {
  public let directive: StopDirective?
  public let ownerPeerID: UUID?
  public let revision: UInt64
  public let quarantined: Bool

  public init(
    directive: StopDirective?, ownerPeerID: UUID?,
    revision: UInt64, quarantined: Bool
  ) {
    self.directive = directive
    self.ownerPeerID = ownerPeerID
    self.revision = revision
    self.quarantined = quarantined
  }
}

public final class GlobalAuthorityServiceCore: @unchecked Sendable {
  private let lock = NSLock()
  private let journal: any AuthorityJournalCommitting
  private let randomness: any AuthorityTicketRandomness
  private let clock: any AuthorityMonotonicClock
  private let secrets: TunnelSecretLifecycle
  private var reducer: GlobalAuthorityReducer
  private var proxyCapability: PendingProxyCapability?
  private var configurationDescriptor: AuthorityConfigurationDescriptor?
  private var boundPeerID: UUID?
  private var ownerAuditSessionID: UInt32?
  private var stopDeadlineMonotonic: UInt64?

  public init(
    reducer: GlobalAuthorityReducer,
    journal: any AuthorityJournalCommitting,
    randomness: any AuthorityTicketRandomness = SystemAuthorityTicketRandomness(),
    clock: any AuthorityMonotonicClock = SystemAuthorityMonotonicClock()
  ) {
    self.reducer = reducer
    self.journal = journal
    self.randomness = randomness
    self.clock = clock
    secrets = TunnelSecretLifecycle(randomness: randomness, clock: clock)
  }

  public var leaseOwnerUID: uid_t? {
    lock.withLock { reducer.lease.map { uid_t($0.operation.ownerUID) } }
  }

  /// Current durable machine-wide state. Exposed for the liveness supervisor and
  /// recovery reconciliation; never discloses lease secrets.
  public var authorityState: AuthorityState { lock.withLock { reducer.state } }

  public var currentRevision: UInt64 { lock.withLock { reducer.revision } }

  fileprivate func releaseObservationState() -> (
    state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?
  ) {
    lock.withLock {
      (
        state: reducer.state,
        revision: reducer.revision,
        leaseOwnerUID: reducer.lease.map { uid_t($0.operation.ownerUID) }
      )
    }
  }

  /// True once the current owner has durably attested a stop. Used by the liveness
  /// supervisor to escalate an elapsed stop timeout to Quarantined.
  public var ownerHasAttestedStopped: Bool { lock.withLock { reducer.ownerStopped } }

  /// Expires an owner that never arrived. Preparing has no data-plane or OS
  /// mutation yet, so the Authority can prove and commit Off itself after
  /// erasing the single-use capability/ticket and secret buffers.
  @discardableResult
  public func expireUnboundPreparationIfNeeded() throws -> Bool {
    try lock.withLock {
      guard reducer.state == .preparing,
        let lease = reducer.lease,
        clock.nowMilliseconds() >= lease.expiryMonotonic
      else { return false }
      try abortUnboundPreparationLocked(operation: lease.operation)
      return true
    }
  }

  /// Re-observes the public live console user and revokes the lease when the owner's
  /// user is no longer the live console user (Fast User Switching or logout). Returns
  /// a forced-stop outcome only when a revocation was durably committed; a lock screen
  /// that preserves the same console UID performs no transition and returns nil. The
  /// lease is never transferred to the new user.
  @discardableResult
  public func observeLiveConsoleUser(
    _ liveConsoleUID: uid_t?
  ) throws -> AuthorityForcedStopOutcome? {
    try lock.withLock {
      guard let lease = reducer.lease else { return nil }
      guard liveConsoleUID.map({ UInt32($0) }) != lease.operation.ownerUID else {
        return nil
      }
      if reducer.state == .preparing {
        try abortUnboundPreparationLocked(operation: lease.operation)
        return AuthorityForcedStopOutcome(
          directive: nil, ownerPeerID: nil,
          revision: reducer.revision, quarantined: false)
      }
      let before = reducer.revision
      var candidate = reducer
      let revision = try candidate.revokeForConsoleChange(
        liveConsoleUID: liveConsoleUID.map { UInt32($0) },
        ownerConnectionNonce: lease.ownerConnectionNonce)
      guard revision != before else { return nil }
      try persist(&candidate)
      reducer = candidate
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try forcedOutcomeLocked(revision: revision)
    }
  }

  /// Forced revocation for an owner-liveness failure (connection loss, missed
  /// heartbeat, owner identity drift, or an elapsed stop/reattest timeout). Returns a
  /// forced-stop outcome only when a revocation was durably committed.
  @discardableResult
  public func forceStop(
    trigger: AuthorityLivenessTrigger
  ) throws -> AuthorityForcedStopOutcome? {
    try lock.withLock {
      guard let lease = reducer.lease else { return nil }
      if reducer.state == .preparing {
        try abortUnboundPreparationLocked(operation: lease.operation)
        return AuthorityForcedStopOutcome(
          directive: nil, ownerPeerID: nil,
          revision: reducer.revision, quarantined: false)
      }
      let before = reducer.revision
      var candidate = reducer
      let revision = try candidate.revokeForLiveness()
      guard revision != before else { return nil }
      try persist(&candidate)
      reducer = candidate
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try forcedOutcomeLocked(revision: revision)
    }
  }

  /// Applies an owner/OS Off proof. Off is committed only when every barrier
  /// predicate is proven; any ambiguity retains Quarantined instead of Off.
  @discardableResult
  public func resolveOff(_ proof: GlobalOffProof) throws -> AuthorityOffResolution {
    try lock.withLock {
      var candidate = reducer
      let resolution = try candidate.applyOffProof(
        proof, expectedRevision: reducer.revision)
      try persist(&candidate)
      reducer = candidate
      stopDeadlineMonotonic = nil
      if case .off = resolution {
        proxyCapability = nil
        configurationDescriptor = nil
        boundPeerID = nil
        ownerAuditSessionID = nil
      }
      secrets.terminate(.cancellation)
      return resolution
    }
  }

  /// Commits the post-restart recovery barrier to Off only when the exact
  /// durable journal cursor, the authenticated live Host, both owner cleanup
  /// domains, and the public NetworkExtension state all agree. Transient
  /// capability/ticket/secret evidence is derived exclusively from Authority
  /// process state and is never accepted from request bytes.
  public func reconcileOff(
    _ request: ReconcileOffRequest, peer: PeerIdentity
  ) throws -> ReconcileOffReceipt {
    guard peer.role == .host,
      let consoleUID = peer.consoleUID,
      peer.euid == consoleUID,
      peer.auditSessionID != 0,
      peer.auditSessionID != UInt32.max
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }

    return try lock.withLock {
      switch reducer.state {
      case .recovering:
        break
      case .quarantined:
        throw AuthorityDomainError(code: .quarantined)
      default:
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      guard request.expectedRevision == reducer.revision else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      guard let replayCursor = reducer.replayCursor,
        request.replayCursor == replayCursor
      else {
        throw AuthorityDomainError(code: .replayRejected)
      }

      let managedTunnel: ManagedTunnelObservation
      switch request.managedTunnel {
      case .disconnected:
        managedTunnel = .disconnected
      case .invalid:
        managedTunnel = .invalid
      case .connecting, .connected, .unknown:
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      guard request.proxy.ownershipCleared,
        request.proxy.listenerClosed,
        request.proxy.effectiveSystemConfigurationRestored,
        request.provider.ownershipCleared,
        request.provider.libboxStopped,
        request.provider.packetPumpClosed
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      let leaseReleased = reducer.lease == nil
      let capabilityOrTicketCleared =
        !reducer.retainsCapabilityOrTicket && proxyCapability == nil
      let secretBufferCleared =
        !reducer.retainsSecretBuffer && !secrets.hasPendingMaterial
      let hasNoOwnerBinding = reducer.ownerBinding == nil
      let hasNoBoundPeer = boundPeerID == nil
      let hasNoOwnerAuditSession = ownerAuditSessionID == nil
      let ownerEndpointCleared =
        hasNoOwnerBinding && hasNoBoundPeer && hasNoOwnerAuditSession

      guard leaseReleased,
        capabilityOrTicketCleared,
        secretBufferCleared,
        ownerEndpointCleared,
        configurationDescriptor == nil
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      let proof = GlobalOffProof(
        leaseReleased: leaseReleased,
        capabilityOrTicketCleared: capabilityOrTicketCleared,
        secretBufferCleared: secretBufferCleared,
        ownerEndpointCleared: ownerEndpointCleared,
        cleanup: .reconciledBoth(
          proxyListenerClosed: request.proxy.listenerClosed,
          systemConfigurationRestored:
            request.proxy.effectiveSystemConfigurationRestored,
          providerLibboxStopped: request.provider.libboxStopped,
          packetPumpClosed: request.provider.packetPumpClosed),
        managedTunnel: managedTunnel)
      var candidate = reducer
      let resolution = try candidate.applyOffProof(
        proof, expectedRevision: request.expectedRevision)
      guard case .off(let revision) = resolution else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      let receipt = try ReconcileOffReceipt(
        revision: revision, replayCursor: replayCursor)
      try persist(&candidate)
      reducer = candidate
      stopDeadlineMonotonic = nil
      proxyCapability = nil
      configurationDescriptor = nil
      boundPeerID = nil
      ownerAuditSessionID = nil
      secrets.terminate(.cancellation)
      return receipt
    }
  }

  private func forcedOutcomeLocked(
    revision: UInt64
  ) throws -> AuthorityForcedStopOutcome {
    let directive: StopDirective?
    if let lease = reducer.lease {
      let deadline = try stopDeadlineMonotonic ?? stopDeadline()
      stopDeadlineMonotonic = deadline
      directive = try StopDirective(
        operation: lease.operation, leaseID: lease.leaseID,
        deadlineMonotonic: deadline, revision: revision)
    } else {
      directive = nil
    }
    return AuthorityForcedStopOutcome(
      directive: directive, ownerPeerID: boundPeerID,
      revision: revision, quarantined: reducer.state == .quarantined)
  }

  public func handshake(_ request: HandshakeRequest) throws -> HandshakeResponse {
    try request.validateAuthorityV1()
    guard request.version == (try AuthorityProtocolVersion()) else {
      throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
    }
    return try HandshakeResponse.v1()
  }

  public func prepare(
    _ request: PrepareStartRequest, configuration: Data,
    secretPayload: Data?, peer: PeerIdentity
  ) throws -> PreparedStart {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID,
      peer.auditSessionID != 0,
      peer.auditSessionID != UInt32.max
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    try AuthorityV1Codec.validateConfiguration(
      configuration, descriptor: request.configuration)
    return try lock.withLock {
      let prepared = try prepareLocked(
        request, configuration: configuration,
        secretPayload: secretPayload)
      ownerAuditSessionID = peer.auditSessionID
      return prepared
    }
  }
  private func prepareLocked(
    _ request: PrepareStartRequest, configuration: Data,
    secretPayload: Data?
  ) throws -> PreparedStart {
    let leaseID = AuthorityIdentifier(UUID())
    let nonce = try randomDigest()
    let issued = clock.nowMilliseconds()
    let expiry = try addLifetime(to: issued)
    var candidate = reducer

    switch request.operation.mode {
    case .tunnel:
      var configurationCopy = configuration
      defer {
        configurationCopy.resetBytes(
          in: configurationCopy.startIndex..<configurationCopy.endIndex)
      }
      let sensitiveConfiguration = try SensitiveBytes(
        copying: configurationCopy,
        maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
      let material: AuthoritySecretMaterial
      do {
        material = try AuthoritySecretPayloadCodec.decode(
          secretPayload, descriptor: request.configuration)
      } catch {
        sensitiveConfiguration.erase()
        throw AuthorityDomainError(code: .secretBoundsExceeded)
      }
      try ensureEnrollmentLocked(request.operation.root.installationID)
      let issuedTicket: AuthorityIssuedTicketTransport
      do {
        issuedTicket = try secrets.prepare(
          request: request, leaseID: leaseID,
          configuration: sensitiveConfiguration, secrets: material)
      } catch {
        throw mapSecretError(error)
      }
      do {
        try candidate.prepare(
          AuthorityPrepareInput(
            request: request, leaseID: leaseID,
            ownerConnectionNonce: nonce, issuedMonotonic: issued,
            expiryMonotonic: issuedTicket.expiresMonotonic,
            retainsSecretBuffer: true))
        try persist(&candidate)
        let ticket = try issuedTicket.withTicket { value in
          try value.withUnsafeBytes { try StartTicket(copying: Data($0)) }
        }
        reducer = candidate
        stopDeadlineMonotonic = nil
        configurationDescriptor = request.configuration
        proxyCapability = nil
        return try PreparedStart(
          operation: request.operation, leaseID: leaseID,
          ticket: ticket, ownerCapability: nil,
          expiresMonotonic: issuedTicket.expiresMonotonic,
          preferenceDescriptorSHA256: request.configuration.identitySHA256)
      } catch {
        issuedTicket.erase()
        secrets.terminate(.error)
        throw error
      }

    case .systemProxy:
      guard secretPayload == nil else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      try ensureEnrollmentLocked(request.operation.root.installationID)
      var rawCapability = try randomness.randomBytes(
        count: AuthorityV1Limits.capabilityBytes)
      defer { rawCapability.resetBytes(in: rawCapability.startIndex..<rawCapability.endIndex) }
      guard rawCapability.count == AuthorityV1Limits.capabilityBytes else {
        throw AuthorityDomainError(code: .secretLifecycleViolation)
      }
      let capability = try OwnerCapability(copying: rawCapability)
      do {
        try candidate.prepare(
          AuthorityPrepareInput(
            request: request, leaseID: leaseID,
            ownerConnectionNonce: nonce, issuedMonotonic: issued,
            expiryMonotonic: expiry, retainsSecretBuffer: false))
        try persist(&candidate)
        reducer = candidate
        stopDeadlineMonotonic = nil
        proxyCapability = PendingProxyCapability(
          operation: request.operation, leaseID: leaseID,
          digest: try digest(rawCapability),
          expiresMonotonic: expiry)
        configurationDescriptor = request.configuration
        return try PreparedStart(
          operation: request.operation, leaseID: leaseID,
          ticket: nil, ownerCapability: capability,
          expiresMonotonic: expiry,
          preferenceDescriptorSHA256: request.configuration.identitySHA256)
      } catch {
        capability.erase()
        throw error
      }
    }
  }

  private func ensureEnrollmentLocked(
    _ installationID: AuthorityIdentifier
  ) throws {
    guard reducer.installationID == nil else { return }
    var enrollment = reducer
    try enrollment.enrollOff(installationID)
    try persist(&enrollment)
    reducer = enrollment
  }
  public func bindProxyOwner(
    _ request: BindProxyOwnerRequest, peer: PeerIdentity, peerID: UUID
  ) throws -> LeaseView {
    guard peer.role == .proxyAgent,
      peer.euid == request.operation.ownerUID
    else { throw AuthorityDomainError(code: .globalAuthorityIdentityRejected) }
    defer { request.capability.erase() }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      guard let pending = proxyCapability else {
        throw AuthorityDomainError(code: .ticketInvalid)
      }
      guard clock.nowMilliseconds() < pending.expiresMonotonic else {
        try abortUnboundPreparationLocked(operation: pending.operation)
        throw AuthorityDomainError(code: .ticketExpired)
      }
      guard
        pending.operation == request.operation,
        pending.leaseID == request.leaseID,
        try request.capability.withUnsafeBytes({ try digest(Data($0)) }) == pending.digest,
        let lease = reducer.lease
      else { throw AuthorityDomainError(code: .ticketInvalid) }
      var candidate = reducer
      try candidate.bindOwner(
        AuthorityOwnerBinding(
          operation: request.operation, leaseID: request.leaseID,
          leaseOwnerUID: peer.euid,
          connectionNonce: lease.ownerConnectionNonce,
          role: .proxyAgent, mode: .systemProxy))
      try persist(&candidate)
      reducer = candidate
      proxyCapability = nil
      boundPeerID = peerID
      return try leaseView(candidate.lease)
    }
  }

  public struct RedeemResult: @unchecked Sendable {
    public let metadata: RedeemedTunnelMetadata
    public let transport: AuthorityRedeemedTunnelTransport
  }

  public func redeemTunnelTicket(
    _ request: RedeemTunnelTicketRequest,
    peer: PeerIdentity, peerID: UUID
  ) throws -> RedeemResult {
    guard peer.role == .provider else {
      request.ticket.erase()
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard let descriptor = configurationDescriptor,
        let lease = reducer.lease
      else {
        request.ticket.erase()
        throw AuthorityDomainError(code: .ticketInvalid)
      }
      let redemption: AuthorityTicketRedemption
      do {
        redemption = try secrets.redeem(ticket: request.ticket)
      } catch {
        throw mapSecretError(error)
      }
      do {
        guard redemption.operation == lease.operation,
          redemption.leaseID == lease.leaseID
        else {
          redemption.transport.erase()
          throw AuthorityDomainError(code: .ticketInvalid)
        }
        var candidate = reducer
        try candidate.bindOwner(
          AuthorityOwnerBinding(
            operation: redemption.operation, leaseID: redemption.leaseID,
            leaseOwnerUID: redemption.operation.ownerUID,
            connectionNonce: lease.ownerConnectionNonce,
            role: .provider, mode: .tunnel))
        try persist(&candidate)
        reducer = candidate
        boundPeerID = peerID
        return RedeemResult(
          metadata: try RedeemedTunnelMetadata(
            operation: redemption.operation, lease: leaseView(candidate.lease),
            configuration: descriptor),
          transport: redemption.transport)
      } catch {
        redemption.transport.erase()
        throw error
      }
    }
  }
  public func attestReady(
    _ attestation: ReadyAttestation, peer: PeerIdentity, peerID: UUID
  ) throws -> AuthorityAcknowledgement {
    try lock.withLock {
      try requireBoundOwner(peer: peer, peerID: peerID, operation: attestation.operation)
      guard let lease = reducer.lease else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      var candidate = reducer
      let previousRevision = candidate.revision
      let revision = try candidate.attestReady(
        attestation,
        ownerUID: attestation.operation.ownerUID,
        connectionNonce: lease.ownerConnectionNonce)
      if revision != previousRevision {
        try persist(&candidate)
      }
      reducer = candidate
      return try AuthorityAcknowledgement(
        operationID: attestation.operation.operationID,
        revision: revision)
    }
  }

  public func beginStop(
    _ request: BeginStopRequest, peer: PeerIdentity
  ) throws -> StopDirective {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      var candidate = reducer
      let previousRevision = candidate.revision
      let revision = try candidate.beginStop(request)
      let deadline = try stopDeadlineMonotonic ?? stopDeadline()
      if revision != previousRevision {
        try persist(&candidate)
      }
      reducer = candidate
      stopDeadlineMonotonic = deadline
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try StopDirective(
        operation: request.operation, leaseID: request.leaseID,
        deadlineMonotonic: deadline, revision: revision)
    }
  }

  public func completeStop(
    _ request: CompleteStopRequest, peer: PeerIdentity
  ) throws -> AuthorityAcknowledgement {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      guard reducer.state == .stopping,
        let lease = reducer.lease,
        lease.operation == request.operation,
        lease.leaseID == request.leaseID,
        reducer.ownerStopped
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      var candidate = reducer
      let resolution = try candidate.applyOffProof(
        Self.stoppedOwnerOffProof(for: request.operation.mode),
        expectedRevision: request.expectedRevision)
      guard case .off(let revision) = resolution else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      try persist(&candidate)
      reducer = candidate
      stopDeadlineMonotonic = nil
      proxyCapability = nil
      configurationDescriptor = nil
      boundPeerID = nil
      ownerAuditSessionID = nil
      secrets.terminate(.cancellation)
      return try AuthorityAcknowledgement(
        operationID: request.operation.operationID,
        revision: revision)
    }
  }

  public func attestStopped(
    _ attestation: StoppedAttestation, peer: PeerIdentity, peerID: UUID
  ) throws -> AuthorityAcknowledgement {
    try lock.withLock {
      try requireBoundOwner(peer: peer, peerID: peerID, operation: attestation.operation)
      guard let lease = reducer.lease else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      var candidate = reducer
      let previousRevision = candidate.revision
      let revision = try candidate.attestStopped(
        attestation, ownerUID: attestation.operation.ownerUID,
        connectionNonce: lease.ownerConnectionNonce)
      if revision != previousRevision {
        try persist(&candidate)
      }
      reducer = candidate
      return try AuthorityAcknowledgement(
        operationID: attestation.operation.operationID,
        revision: revision)
    }
  }
  public func cancelPrepared(
    _ request: CancelPreparedRequest, peer: PeerIdentity
  ) throws -> AuthorityAcknowledgement {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      let revision = try abortUnboundPreparationLocked(
        operation: request.operation,
        expectedRevision: request.expectedRevision)
      return try AuthorityAcknowledgement(
        operationID: request.operation.operationID,
        revision: revision)
    }
  }

  private func abortUnboundPreparationLocked(
    operation: OperationContext
  ) throws {
    _ = try abortUnboundPreparationLocked(
      operation: operation,
      expectedRevision: reducer.revision)
  }

  private func abortUnboundPreparationLocked(
    operation: OperationContext,
    expectedRevision: UInt64
  ) throws -> UInt64 {
    var candidate = reducer
    let deadline = try stopDeadline()
    _ = try candidate.abortPrepared(
      operation: operation,
      expectedRevision: expectedRevision)
    try persist(&candidate)
    // The abort record is already durable. Advance the in-memory high-water and
    // erase the one-use authorization before attempting the separate Off record,
    // so an Off-persist failure cannot leave memory projecting Preparing behind
    // the journal's committed Stopping state.
    reducer = candidate
    stopDeadlineMonotonic = deadline
    proxyCapability = nil
    boundPeerID = nil
    secrets.terminate(.cancellation)

    let resolution = try candidate.applyOffProof(
      Self.unboundPreparationOffProof(for: operation.mode),
      expectedRevision: candidate.revision)
    guard case .off(let revision) = resolution else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    try persist(&candidate)
    reducer = candidate
    stopDeadlineMonotonic = nil
    proxyCapability = nil
    configurationDescriptor = nil
    boundPeerID = nil
    ownerAuditSessionID = nil
    secrets.terminate(.cancellation)
    return revision
  }

  private static func unboundPreparationOffProof(
    for mode: AuthorityMode
  ) -> GlobalOffProof {
    let cleanup: AuthorityCleanupObservation =
      switch mode {
      case .systemProxy:
        .systemProxy(listenerClosed: true, systemConfigurationRestored: true)
      case .tunnel:
        .tunnel(libboxStopped: true, packetPumpClosed: true)
      }
    return GlobalOffProof(
      leaseReleased: true,
      capabilityOrTicketCleared: true,
      secretBufferCleared: true,
      ownerEndpointCleared: true,
      cleanup: cleanup,
      managedTunnel: .disconnected)
  }

  /// A cooperative stop is completed only after the authenticated owner has
  /// durably attested its local teardown and the authenticated Host has observed
  /// the matching OS-facing endpoint at its Off barrier. The Host's
  /// `completeStop` request is that second proof boundary.
  private static func stoppedOwnerOffProof(
    for mode: AuthorityMode
  ) -> GlobalOffProof {
    unboundPreparationOffProof(for: mode)
  }

  public func snapshot(peer: PeerIdentity) throws -> AuthoritySnapshot {
    try lock.withLock {
      if let lease = reducer.lease {
        switch peer.role {
        case .host:
          guard peer.euid == lease.operation.ownerUID,
            peer.auditSessionID == ownerAuditSessionID
          else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        case .proxyAgent:
          guard boundPeerID != nil,
            peer.euid == lease.operation.ownerUID,
            peer.auditSessionID == ownerAuditSessionID
          else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        case .provider:
          guard boundPeerID != nil else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        }
      }
      return try AuthoritySnapshot(
        protocolVersion: AuthorityProtocolVersion(),
        state: reducer.state, revision: reducer.revision,
        replayCursor: reducer.replayCursor,
        leaseView: try reducer.lease.map(leaseView),
        lastFailure: nil, consoleUID: peer.consoleUID)
    }
  }

  public func ownerPeerID() -> UUID? { lock.withLock { boundPeerID } }

  public func assertOwnerHeartbeat(
    peer: PeerIdentity,
    peerID: UUID
  ) throws {
    try lock.withLock {
      guard let lease = reducer.lease,
        [.starting, .active, .stopping].contains(reducer.state)
      else { throw AuthorityDomainError(code: .staleOperation) }
      try requireBoundOwner(
        peer: peer, peerID: peerID, operation: lease.operation)
    }
  }

  private func requireBoundOwner(
    peer: PeerIdentity, peerID: UUID, operation: OperationContext
  ) throws {
    let expectedRole: AuthorityRole = operation.mode == .tunnel ? .provider : .proxyAgent
    guard peer.role == expectedRole, boundPeerID == peerID,
      expectedRole == .provider || peer.auditSessionID == ownerAuditSessionID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
  }

  private func leaseView(_ lease: GlobalLease?) throws -> LeaseView {
    guard let lease else { throw AuthorityDomainError(code: .staleOperation) }
    return try LeaseView(
      leaseID: lease.leaseID, operation: lease.operation,
      state: lease.state, expiryMonotonic: lease.expiryMonotonic)
  }
  private func persist(_ value: inout GlobalAuthorityReducer) throws {
    guard let installationID = value.installationID,
      let mutation = value.lastMutation
    else { throw AuthorityDomainError(code: .journalCorrupt) }
    let operation = value.lease?.operation
    let cursor = value.replayCursor
    do {
      let head = try journal.appendCommitted(
        AuthorityCommittedState(
          installationID: installationID,
          epoch: cursor?.acceptedEpoch ?? 0,
          generation: cursor?.acceptedGeneration ?? 0,
          revision: value.revision,
          transition: journalTransition(mutation),
          state: value.state,
          operationID: operation?.operationID,
          mode: operation?.mode,
          configSHA256: operation?.configSHA256,
          leaseID: value.lease?.leaseID,
          ownerUID: operation?.ownerUID))
      try value.recordPersistedHead(head)
    } catch AuthorityJournalStorageError.capacityExhausted {
      throw AuthorityDomainError(code: .journalCapacityExhausted)
    } catch {
      throw AuthorityDomainError(code: .journalCorrupt)
    }
  }

  private func journalTransition(
    _ mutation: AuthorityDurableMutationKind
  ) -> AuthorityJournalTransition {
    switch mutation {
    case .enrollOff: .enrollOff
    case .prepare: .prepare
    case .bindOwner: .bindOwner
    case .ready: .ready
    case .beginStop: .beginStop
    case .ownerStopped: .ownerStopped
    case .abortPrepared: .abortPrepared
    case .revokeForConsoleChange: .revokeForConsoleChange
    case .revokeForTimeout: .revokeForTimeout
    case .globalOff: .globalOff
    case .reconcileOff: .reconcileOff
    }
  }

  private func randomDigest() throws -> SHA256Digest {
    var bytes = try randomness.randomBytes(
      count: AuthorityV1Limits.connectionNonceBytes)
    defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
    guard bytes.count == AuthorityV1Limits.connectionNonceBytes else {
      throw AuthorityDomainError(code: .secretLifecycleViolation)
    }
    return try digest(bytes)
  }

  private func digest(_ data: Data) throws -> SHA256Digest {
    try SHA256Digest(
      hex: SHA256.hash(data: data).map {
        String(format: "%02x", $0)
      }.joined())
  }

  private func addLifetime(to value: UInt64) throws -> UInt64 {
    let (result, overflow) = value.addingReportingOverflow(
      AuthorityV1Limits.preparationLifetimeMilliseconds)
    guard !overflow else { throw AuthorityDomainError(code: .invalidMessage) }
    return result
  }

  private func stopDeadline() throws -> UInt64 {
    let (result, overflow) = clock.nowMilliseconds().addingReportingOverflow(
      AuthorityV1Limits.stopAttestationTimeoutMilliseconds)
    guard !overflow else { throw AuthorityDomainError(code: .invalidMessage) }
    return result
  }

  private func mapSecretError(_ error: Error) -> AuthorityDomainError {
    guard let value = error as? AuthoritySecretLifecycleError else {
      return AuthorityDomainError(code: .secretLifecycleViolation)
    }
    return switch value {
    case .ticketExpired: AuthorityDomainError(code: .ticketExpired)
    case .ticketAlreadyRedeemed: AuthorityDomainError(code: .ticketAlreadyRedeemed)
    case .ticketInvalid: AuthorityDomainError(code: .ticketInvalid)
    case .invalidPreparation: AuthorityDomainError(code: .secretBoundsExceeded)
    default: AuthorityDomainError(code: .secretLifecycleViolation)
    }
  }
}
public final class AuthorityEventHub: @unchecked Sendable {
  private let lock = NSLock()
  private var channels: [UUID: AuthorityPeerEventChannel] = [:]

  public init() {}
  public func register(_ channel: AuthorityPeerEventChannel, peerID: UUID) {
    lock.withLock { channels[peerID] = channel }
  }
  public func remove(peerID: UUID) {
    lock.withLock { _ = channels.removeValue(forKey: peerID) }
  }
  public func send(_ event: AuthorityEvent, to peerID: UUID) {
    lock.withLock { channels[peerID] }?.enqueue(event)
  }
}

public final class AuthorityPeerEventChannel: @unchecked Sendable {
  private let queue = BoundedAuthorityEventQueue()
  private let sink: CFWGlobalAuthorityEventSinkProtocol?
  private let invalidate: @Sendable () -> Void
  private let stateLock = NSLock()
  private var draining = false

  public init(
    sink: CFWGlobalAuthorityEventSinkProtocol?,
    invalidate: @escaping @Sendable () -> Void
  ) {
    self.sink = sink
    self.invalidate = invalidate
  }

  public func enqueue(_ event: AuthorityEvent) {
    guard sink != nil else {
      invalidate()
      return
    }
    guard queue.enqueue(event) == .queued else {
      invalidate()
      return
    }
    let shouldDrain = stateLock.withLock {
      guard !draining else { return false }
      draining = true
      return true
    }
    if shouldDrain { drainNext() }
  }

  private func drainNext() {
    guard let event = queue.dequeue(), let sink else {
      let shouldRearm = stateLock.withLock { () -> Bool in
        draining = false
        guard queue.count > 0, sink != nil else { return false }
        draining = true
        return true
      }
      if shouldRearm { drainNext() }
      return
    }
    do {
      let data = try AuthorityV1Codec.encodeEvent(event)
      sink.deliverEvent(data) { [weak self] error in
        guard let self else { return }
        if error != nil {
          self.invalidate()
          self.stateLock.withLock { self.draining = false }
        } else {
          self.drainNext()
        }
      }
    } catch {
      invalidate()
      stateLock.withLock { draining = false }
    }
  }
}
public final class AuthenticatedAuthorityPeerService: NSObject,
  CFWGlobalAuthorityXPCProtocol, @unchecked Sendable
{
  public typealias Reauthorize = @Sendable () throws -> PeerIdentity
  public typealias RecordOperationDecision =
    @Sendable (ReleaseObservationAuthenticatedDecision) throws -> Void

  private let peerID: UUID
  private let initialPeer: PeerIdentity
  private let reauthorize: Reauthorize
  private let core: GlobalAuthorityServiceCore
  private let concurrency: AuthorityConcurrencyGate
  private let events: AuthorityEventHub
  private let liveness: AuthorityLivenessSupervisor
  private let recordOperationDecision: RecordOperationDecision

  public init(
    peerID: UUID, peer: PeerIdentity,
    reauthorize: @escaping Reauthorize,
    core: GlobalAuthorityServiceCore,
    concurrency: AuthorityConcurrencyGate,
    events: AuthorityEventHub,
    liveness: AuthorityLivenessSupervisor? = nil,
    recordOperationDecision: @escaping RecordOperationDecision = { _ in }
  ) {
    self.peerID = peerID
    initialPeer = peer
    self.reauthorize = reauthorize
    self.core = core
    self.concurrency = concurrency
    self.events = events
    self.liveness =
      liveness
      ?? AuthorityLivenessSupervisor(core: core, events: events)
    self.recordOperationDecision = recordOperationDecision
  }

  public func handshake(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    read(request, expected: .handshake, reply: reply) { envelope in
      guard case .handshake(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      return try self.response(
        self.core.handshake(value), envelope: envelope, operationID: nil)
    }
  }

  public func prepareStart(
    _ request: Data, configuration: Data, secretPayload: Data?,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .prepareStart, reply: reply) { envelope, peer in
      guard case .prepareStart(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let prepared = try self.core.prepare(
        value, configuration: configuration,
        secretPayload: secretPayload, peer: peer)
      defer {
        prepared.ticket?.erase()
        prepared.ownerCapability?.erase()
      }
      return try AuthorityPreparedStartCodec.encode(
        prepared, requestID: envelope.requestID)
    }
  }
  public func bindProxyOwner(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .bindProxyOwner, reply: reply) { envelope, peer in
      guard case .bindProxyOwner(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let lease = try self.core.bindProxyOwner(
        value, peer: peer, peerID: self.peerID)
      self.liveness.recordHeartbeat()
      return try self.response(
        lease, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func redeemTunnelTicket(
    _ request: Data,
    reply: @escaping (Data?, Data?, Data?, NSError?) -> Void
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: .redeemTunnelTicket)
      let peer = try reauthorize()
      let result = try concurrency.withMutation { () -> GlobalAuthorityServiceCore.RedeemResult in
        guard case .redeemTunnelTicket(let value) = envelope.command else {
          throw AuthorityDomainError(code: .invalidMessage)
        }
        let result = try core.redeemTunnelTicket(
          value, peer: peer, peerID: peerID)
        liveness.recordHeartbeat()
        return result
      }
      var configurationData = Data()
      var secretData: Data?
      let response = try result.transport.withMaterial { configuration, secrets in
        configurationData = try configuration.withUnsafeBytes { Data($0) }
        let encodedSecrets = try AuthoritySecretPayloadCodec.encode(secrets)
        defer { encodedSecrets?.erase() }
        secretData = try encodedSecrets?.withUnsafeBytes { Data($0) }
        return try self.response(
          result.metadata, envelope: envelope,
          operationID: result.metadata.operation.operationID)
      }
      defer {
        configurationData.resetBytes(
          in: configurationData.startIndex..<configurationData.endIndex)
        if var secretData {
          secretData.resetBytes(in: secretData.startIndex..<secretData.endIndex)
        }
      }
      reply(response, configurationData, secretData, nil)
    } catch {
      let observationError = recordRejectedOperation(
        request: request, error: error, preObservation: preObservation)
      reply(nil, nil, nil, observationError ?? xpcError(error))
    }
  }

  public func attestReady(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .attestReady, reply: reply) { envelope, peer in
      guard case .attestReady(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.attestReady(
        value, peer: peer, peerID: self.peerID)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }
  public func beginStop(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: .beginStop)
      let peer = try reauthorize()
      guard case .beginStop(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try concurrency.withMutation { () -> (Data, StopDirective, UUID?) in
        let directive = try core.beginStop(value, peer: peer)
        return (
          try response(
            directive, envelope: envelope,
            operationID: value.operation.operationID),
          directive,
          core.ownerPeerID()
        )
      }
      liveness.noteStopOrdered(
        revision: result.1.revision,
        deadlineMonotonic: result.1.deadlineMonotonic)
      if let ownerPeerID = result.2 {
        events.send(.stop(result.1), to: ownerPeerID)
      }
      reply(result.0, nil)
    } catch {
      let observationError = recordRejectedOperation(
        request: request, error: error, preObservation: preObservation)
      reply(nil, observationError ?? xpcError(error))
    }
  }

  public func completeStop(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .completeStop, reply: reply) { envelope, peer in
      guard case .completeStop(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.completeStop(value, peer: peer)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func reconcileOff(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .reconcileOff, reply: reply) { envelope, peer in
      guard case .reconcileOff(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.reconcileOff(value, peer: peer)
      return try self.response(
        result, envelope: envelope, operationID: nil)
    }
  }

  public func attestStopped(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .attestStopped, reply: reply) { envelope, peer in
      guard case .attestStopped(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.attestStopped(
        value, peer: peer, peerID: self.peerID)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func cancelPrepared(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .cancelPrepared, reply: reply) { envelope, peer in
      guard case .cancelPrepared(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.cancelPrepared(value, peer: peer)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func snapshot(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: .snapshot)
      let peer = try reauthorize()
      guard case .snapshot = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let response = try concurrency.withRead {
        try self.response(
          self.core.snapshot(peer: peer),
          envelope: envelope, operationID: nil)
      }
      reply(response, nil)
    } catch {
      let observationError = recordRejectedOperation(
        request: request, error: error, preObservation: preObservation)
      reply(nil, observationError ?? xpcError(error))
    }
  }

  public func ownerHeartbeat(_ reply: @escaping (NSError?) -> Void) {
    do {
      let peer = try reauthorize()
      try concurrency.withRead {
        try core.assertOwnerHeartbeat(peer: peer, peerID: peerID)
      }
      liveness.recordHeartbeat()
      reply(nil)
    } catch {
      reply(xpcError(error))
    }
  }
  private func read(
    _ request: Data, expected: AuthorityXPCMethod,
    reply: @escaping (Data?, NSError?) -> Void,
    body: (AuthorityRequestEnvelope) throws -> Data
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: expected)
      reply(try concurrency.withRead { try body(envelope) }, nil)
    } catch {
      let observationError = recordRejectedOperation(
        request: request, error: error, preObservation: preObservation)
      reply(nil, observationError ?? xpcError(error))
    }
  }

  private func mutate(
    _ request: Data, expected: AuthorityXPCMethod,
    reply: @escaping (Data?, NSError?) -> Void,
    body: (AuthorityRequestEnvelope, PeerIdentity) throws -> Data
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: expected)
      let peer = try reauthorize()
      reply(try concurrency.withMutation { try body(envelope, peer) }, nil)
    } catch {
      let observationError = recordRejectedOperation(
        request: request, error: error, preObservation: preObservation)
      reply(nil, observationError ?? xpcError(error))
    }
  }

  private func decode(
    _ request: Data, expected: AuthorityXPCMethod
  ) throws -> AuthorityRequestEnvelope {
    do {
      let envelope = try AuthorityV1Codec.decodeRequest(request)
      guard method(for: envelope.command) == expected else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      return envelope
    } catch let error as AuthorityV1ValidationError {
      switch error {
      case .unsupportedMajor, .unsupportedMinor, .unsupportedRequiredFeatures:
        throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
      default:
        throw AuthorityDomainError(code: .invalidMessage)
      }
    }
  }

  private func response<Payload: AuthorityV1WireModel>(
    _ payload: Payload, envelope: AuthorityRequestEnvelope,
    operationID: AuthorityIdentifier?
  ) throws -> Data {
    try AuthorityV1Codec.encodeResponse(
      AuthorityResponseEnvelope(
        requestID: envelope.requestID,
        operationID: operationID, result: payload))
  }

  private func method(for command: AuthorityCommand) -> AuthorityXPCMethod {
    switch command {
    case .handshake: .handshake
    case .prepareStart: .prepareStart
    case .bindProxyOwner: .bindProxyOwner
    case .redeemTunnelTicket: .redeemTunnelTicket
    case .attestReady: .attestReady
    case .beginStop: .beginStop
    case .completeStop: .completeStop
    case .reconcileOff: .reconcileOff
    case .attestStopped: .attestStopped
    case .cancelPrepared: .cancelPrepared
    case .snapshot: .snapshot
    }
  }

  private func recordRejectedOperation(
    request: Data,
    error: Error,
    preObservation: (state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?)
  ) -> NSError? {
    do {
      let postObservation = core.releaseObservationState()
      let outcome: ReleaseObservationOutcome
      if let domain = error as? AuthorityDomainError {
        outcome = try ReleaseObservationOutcome(authorityErrorCode: domain.code)
      } else if error is GlobalAuthorityAuthorizationError {
        outcome = .globalAuthorityIdentityRejected
      } else {
        outcome = .invalidMessage
      }
      let preDigest = try ReleaseObservationLogger.authorityStateSHA256(
        state: preObservation.state,
        revision: preObservation.revision,
        leaseOwnerUID: preObservation.leaseOwnerUID)
      let postDigest = try ReleaseObservationLogger.authorityStateSHA256(
        state: postObservation.state,
        revision: postObservation.revision,
        leaseOwnerUID: postObservation.leaseOwnerUID)
      let requestDigest = SHA256.hash(data: request).map {
        String(format: "%02x", $0)
      }.joined()
      let payload = try ReleaseObservationAuthenticatedDecision(
        role: initialPeer.role,
        peerPID: initialPeer.pid,
        effectiveUserIdentifier: initialPeer.euid,
        auditSessionIdentifier: initialPeer.auditSessionID,
        connectionIdentitySHA256: initialPeer.connectionIdentityDigest.hex,
        requestSHA256: requestDigest,
        accepted: false,
        actualCode: outcome,
        preStateSHA256: preDigest,
        postStateSHA256: postDigest,
        cleanupState: postObservation.state)
      try recordOperationDecision(payload)
      return nil
    } catch {
      return AuthorityXPCErrorContract.error(.globalAuthorityInterrupted)
    }
  }

  private func xpcError(_ error: Error) -> NSError {
    if let domain = error as? AuthorityDomainError {
      return AuthorityXPCErrorContract.error(domain.code)
    }
    if error is GlobalAuthorityAuthorizationError {
      return AuthorityXPCErrorContract.error(.globalAuthorityIdentityRejected)
    }
    return AuthorityXPCErrorContract.error(.invalidMessage)
  }
}
public enum AuthorityConnectionAdmission {
  public static func authorizeBeforeExport(
    authorize: () throws -> PeerIdentity,
    export: (PeerIdentity) -> Void
  ) -> Bool {
    do {
      let peer = try authorize()
      export(peer)
      return true
    } catch {
      return false
    }
  }
}

private final class AuthorityWeakConnectionBox: @unchecked Sendable {
  weak var connection: NSXPCConnection?
  init(_ connection: NSXPCConnection) { self.connection = connection }
}

private final class AuthorityConnectionTermination: @unchecked Sendable {
  private let lock = NSLock()
  private var terminated = false
  private let peerID: UUID
  private let role: AuthorityRole
  private let core: GlobalAuthorityServiceCore
  private let events: AuthorityEventHub
  private let liveness: AuthorityLivenessSupervisor

  init(
    peerID: UUID,
    role: AuthorityRole,
    core: GlobalAuthorityServiceCore,
    events: AuthorityEventHub,
    liveness: AuthorityLivenessSupervisor
  ) {
    self.peerID = peerID
    self.role = role
    self.core = core
    self.events = events
    self.liveness = liveness
  }

  func terminate() {
    let shouldTerminate = lock.withLock {
      guard !terminated else { return false }
      terminated = true
      return true
    }
    guard shouldTerminate else { return }
    events.remove(peerID: peerID)
    guard role != .host,
      core.ownerPeerID() == peerID,
      !core.ownerHasAttestedStopped
    else { return }
    do {
      _ = try liveness.forceStop(.connectionLoss)
    } catch {
      fatalError("Global Authority could not persist owner connection loss: \(error)")
    }
  }
}

private final class AuthorityProductionLivenessRuntime: @unchecked Sendable {
  let supervisor: AuthorityLivenessSupervisor
  private let timer: DispatchSourceTimer
  private let consoleSessionMonitor: ConsoleSessionChangeMonitor

  init(supervisor: AuthorityLivenessSupervisor) {
    self.supervisor = supervisor
    let monitor = ConsoleSessionChangeMonitor(
      queue: DispatchQueue(
        label: "com.bill.clashformac.global-authority.console-session"),
      handler: {
        do {
          _ = try supervisor.observeConsoleSessionChange()
        } catch {
          fatalError("Global Authority could not persist console-session change: \(error)")
        }
      })
    guard let monitor else {
      fatalError("Global Authority could not monitor the console session.")
    }
    consoleSessionMonitor = monitor
    timer = DispatchSource.makeTimerSource(
      queue: DispatchQueue(label: "com.bill.clashformac.global-authority.liveness"))
    timer.schedule(
      deadline: .now() + .seconds(1),
      repeating: .seconds(1),
      leeway: .milliseconds(100))
    timer.setEventHandler { [supervisor] in
      do {
        _ = try supervisor.observeConsoleUser()
        _ = try supervisor.evaluate()
      } catch {
        fatalError("Global Authority liveness evaluation failed: \(error)")
      }
    }
    timer.activate()
  }

  deinit { timer.cancel() }
}

private final class ConsoleSessionChangeHandlerBox: @unchecked Sendable {
  let handler: @Sendable () -> Void
  init(handler: @escaping @Sendable () -> Void) { self.handler = handler }
}

private final class ConsoleSessionChangeMonitor: @unchecked Sendable {
  private let handlerBox: ConsoleSessionChangeHandlerBox
  private let store: SCDynamicStore

  init?(
    queue: DispatchQueue,
    handler: @escaping @Sendable () -> Void
  ) {
    let handlerBox = ConsoleSessionChangeHandlerBox(handler: handler)
    var context = SCDynamicStoreContext(
      version: 0,
      info: Unmanaged.passUnretained(handlerBox).toOpaque(),
      retain: nil,
      release: nil,
      copyDescription: nil)
    let consoleUserKey = SCDynamicStoreKeyCreateConsoleUser(nil)
    guard
      let store = SCDynamicStoreCreate(
        nil,
        "Clash for Mac Global Authority console monitor" as CFString,
        { _, _, info in
          guard let info else { return }
          Unmanaged<ConsoleSessionChangeHandlerBox>
            .fromOpaque(info).takeUnretainedValue().handler()
        },
        &context),
      SCDynamicStoreSetNotificationKeys(
        store, [consoleUserKey] as CFArray, nil),
      SCDynamicStoreSetDispatchQueue(store, queue)
    else { return nil }
    self.handlerBox = handlerBox
    self.store = store
  }

  deinit {
    SCDynamicStoreSetDispatchQueue(store, nil)
    withExtendedLifetime(handlerBox) {}
  }
}

public final class AuthenticatedGlobalAuthorityListenerDelegate: NSObject,
  NSXPCListenerDelegate, @unchecked Sendable
{
  public typealias Authorize =
    @Sendable (
      AuthorityRole, pid_t, uid_t, UInt32, uid_t?
    ) throws -> PeerIdentity

  private let role: AuthorityRole
  private let core: GlobalAuthorityServiceCore
  private let concurrency: AuthorityConcurrencyGate
  private let events: AuthorityEventHub
  private let livenessRuntime: AuthorityProductionLivenessRuntime
  private let authorize: Authorize

  private init(
    role: AuthorityRole,
    core: GlobalAuthorityServiceCore,
    concurrency: AuthorityConcurrencyGate,
    events: AuthorityEventHub,
    livenessRuntime: AuthorityProductionLivenessRuntime,
    authorize: @escaping Authorize
  ) {
    self.role = role
    self.core = core
    self.concurrency = concurrency
    self.events = events
    self.livenessRuntime = livenessRuntime
    self.authorize = authorize
  }

  public static func production() throws
    -> [AuthorityRole: AuthenticatedGlobalAuthorityListenerDelegate]
  {
    let journal = try DescriptorRelativeAuthorityJournalStore()
    let reducer = try GlobalAuthorityReducer.reconciled(from: journal.recover())
    let core = GlobalAuthorityServiceCore(reducer: reducer, journal: journal)
    let concurrency = AuthorityConcurrencyGate()
    let events = AuthorityEventHub()
    let livenessRuntime = AuthorityProductionLivenessRuntime(
      supervisor: AuthorityLivenessSupervisor(core: core, events: events))
    let authorizer = RoleScopedConnectionPeerAuthorizer()
    return Dictionary(
      uniqueKeysWithValues: AuthorityRole.allCases.map { role in
        (
          role,
          Self(
            role: role,
            core: core,
            concurrency: concurrency,
            events: events,
            livenessRuntime: livenessRuntime
          ) { role, pid, euid, auditSessionID, ownerUID in
            try authorizer.authorize(
              role: role,
              processIdentifier: pid,
              effectiveUserIdentifier: euid,
              auditSessionIdentifier: auditSessionID,
              leaseOwnerUID: ownerUID)
          }
        )
      })
  }

  public func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    let pid = connection.processIdentifier
    let euid = connection.effectiveUserIdentifier
    let auditSessionID = UInt32(
      bitPattern: connection.auditSessionIdentifier)
    let preObservation = core.releaseObservationState()
    var admittedPeer: PeerIdentity?
    let admitted = AuthorityConnectionAdmission.authorizeBeforeExport(
      authorize: {
        try authorize(role, pid, euid, auditSessionID, core.leaseOwnerUID)
      },
      export: { admittedPeer = $0 })
    let postObservation = core.releaseObservationState()
    guard admitted, let peer = admittedPeer else {
      guard
        recordPeerAuthorizationDecision(
          pid: pid,
          euid: euid,
          auditSessionID: auditSessionID,
          peer: nil,
          preObservation: preObservation,
          postObservation: postObservation)
      else {
        fputs("global authority release observation failed\n", stderr)
        connection.invalidate()
        return false
      }
      connection.invalidate()
      return false
    }
    guard
      recordPeerAuthorizationDecision(
        pid: pid,
        euid: euid,
        auditSessionID: auditSessionID,
        peer: peer,
        preObservation: preObservation,
        postObservation: postObservation)
    else {
      fputs("global authority release observation failed\n", stderr)
      connection.invalidate()
      return false
    }

    let peerID = UUID()
    let service = AuthenticatedAuthorityPeerService(
      peerID: peerID, peer: peer,
      reauthorize: { [authorize, core] in
        try authorize(
          peer.role, peer.pid, peer.euid, peer.auditSessionID,
          core.leaseOwnerUID)
      }, core: core, concurrency: concurrency, events: events,
      liveness: livenessRuntime.supervisor,
      recordOperationDecision: {
        try ReleaseObservationLogger.emitAuthorityOperationDecision($0)
      })
    connection.remoteObjectInterface = NSXPCInterface(
      with: CFWGlobalAuthorityEventSinkProtocol.self)
    let sink = connection.remoteObjectProxy as? CFWGlobalAuthorityEventSinkProtocol
    let connectionBox = AuthorityWeakConnectionBox(connection)
    let channel = AuthorityPeerEventChannel(
      sink: sink, invalidate: { connectionBox.connection?.invalidate() })
    events.register(channel, peerID: peerID)
    connection.exportedInterface = NSXPCInterface(
      with: CFWGlobalAuthorityXPCProtocol.self)
    connection.exportedObject = service
    let termination = AuthorityConnectionTermination(
      peerID: peerID, role: peer.role, core: core,
      events: events, liveness: livenessRuntime.supervisor)
    connection.interruptionHandler = {
      connectionBox.connection?.invalidate()
    }
    connection.invalidationHandler = { termination.terminate() }
    connection.activate()
    return true
  }

  private func recordPeerAuthorizationDecision(
    pid: pid_t,
    euid: uid_t,
    auditSessionID: UInt32,
    peer: PeerIdentity?,
    preObservation: (state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?),
    postObservation: (state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?)
  ) -> Bool {
    do {
      let preDigest = try ReleaseObservationLogger.authorityStateSHA256(
        state: preObservation.state,
        revision: preObservation.revision,
        leaseOwnerUID: preObservation.leaseOwnerUID)
      let postDigest = try ReleaseObservationLogger.authorityStateSHA256(
        state: postObservation.state,
        revision: postObservation.revision,
        leaseOwnerUID: postObservation.leaseOwnerUID)
      let accepted = peer != nil
      let decision = try ReleaseObservationPeerDecision(
        role: role,
        peerPID: pid,
        effectiveUserIdentifier: UInt32(euid),
        auditSessionIdentifier: auditSessionID,
        connectionIdentitySHA256: peer?.connectionIdentityDigest.hex,
        accepted: accepted,
        actualCode: accepted ? .accepted : .globalAuthorityIdentityRejected,
        preStateSHA256: preDigest,
        postStateSHA256: postDigest,
        cleanupState: postObservation.state)
      try ReleaseObservationLogger.emitAuthorityPeerDecision(decision)
      return true
    } catch {
      return false
    }
  }
}
