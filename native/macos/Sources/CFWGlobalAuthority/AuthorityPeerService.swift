import CFWSharedProtocol
import Darwin
import Foundation
import OSLog
@preconcurrency import SystemConfiguration

import struct CryptoKit.SHA256

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
  /// Admits the connection's peer again for one call, with what the call
  /// needs of the lease when the peer is a ProxyAgent.
  public typealias Reauthorize = @Sendable (ProxyAgentLeaseRequirement) throws -> PeerIdentity
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
      let peer = try reauthorize(.ownedLease)
      let result = try concurrency.withMutation { () -> GlobalAuthorityServiceCore.RedeemResult in
        guard case .redeemTunnelTicket(let value) = envelope.command else {
          throw AuthorityDomainError(code: .invalidMessage)
        }
        let result = try core.redeemTunnelTicket(
          value, peer: peer, peerID: peerID)
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
      let peer = try reauthorize(.ownedLease)
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

  public func installationRecoveryIdentity(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: .installationRecoveryIdentity)
      let peer = try reauthorize(.ownedLease)
      let response = try concurrency.withRead {
        try self.response(
          self.core.installationRecoveryIdentity(peer: peer),
          envelope: envelope, operationID: nil)
      }
      reply(response, nil)
    } catch {
      let observationError = recordRejectedOperation(
        request: request, error: error, preObservation: preObservation)
      reply(nil, observationError ?? xpcError(error))
    }
  }

  public func snapshot(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: .snapshot)
      let peer = try reauthorize(.ownedLease)
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

  public func ownerLeaseStatus(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    let preObservation = core.releaseObservationState()
    do {
      let envelope = try decode(request, expected: .ownerLeaseStatus)
      // An agent asks this once its lease may have ended, so it needs none.
      let peer = try reauthorize(.ownedLeaseOrNone)
      guard case .ownerLeaseStatus(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let response = try concurrency.withRead {
        try self.response(
          OwnerLeaseStatusResponse(status: self.core.ownerLeaseStatus(value, peer: peer)),
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
      let peer = try reauthorize(.ownedLease)
      try concurrency.withRead {
        try core.recordOwnerHeartbeat(peer: peer, peerID: peerID)
      }
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
      let peer = try reauthorize(.ownedLease)
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
    case .installationRecoveryIdentity: .installationRecoveryIdentity
    case .ownerLeaseStatus: .ownerLeaseStatus
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
