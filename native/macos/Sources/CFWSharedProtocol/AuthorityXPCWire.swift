import Foundation

public enum AuthorityXPCMethod: Equatable, Sendable {
  case handshake
  case prepareStart
  case bindProxyOwner
  case redeemTunnelTicket
  case attestReady
  case beginStop
  case completeStop
  case reconcileOff
  case attestStopped
  case cancelPrepared
  case snapshot

  public var operationClass: AuthorityOperationClass {
    switch self {
    case .handshake, .snapshot: .idempotentReadOnly
    default: .mutation
    }
  }
}

public struct AuthorityXPCReply: Sendable {
  public let response: Data
  public let configuration: Data?
  public let secretPayload: Data?

  public init(response: Data, configuration: Data? = nil, secretPayload: Data? = nil) {
    self.response = response
    self.configuration = configuration
    self.secretPayload = secretPayload
  }
}

public protocol AuthorityRemoteCalling: Sendable {
  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply
  /// Starts owner liveness only after the typed client has validated the exact
  /// claim response. A transport-level reply alone is not ownership proof.
  func confirmOwnerClaim() async throws
  /// Stops owner liveness as soon as the caller has locally proven teardown,
  /// before the stopped attestation can time out or lose its reply.
  func noteOwnerStopped() async
  func invalidate() async
}

extension AuthorityRemoteCalling {
  public func confirmOwnerClaim() async throws {}
  public func noteOwnerStopped() async {}
}

public protocol AuthorityClient: Sendable {
  func prepare(
    _ request: PrepareStartRequest,
    configuration: SensitiveBytes, secrets: SensitiveBytes?
  ) async throws -> PreparedStart
  func cancelPrepared(_ context: OperationContext, revision: UInt64) async throws
  func beginStop(_ request: BeginStopRequest) async throws -> StopDirective
  func completeStop(_ request: CompleteStopRequest) async throws
  func reconcileOff(_ request: ReconcileOffRequest) async throws -> ReconcileOffReceipt
  func snapshot() async throws -> AuthoritySnapshot
}
public protocol EngineOwnerAuthorityClient: Sendable {
  func bind(_ capability: OwnerCapability, context: ProxyOwnerContext) async throws -> LeaseView
  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart
  func attestReady(_ attestation: ReadyAttestation) async throws
  func attestStopped(_ attestation: StoppedAttestation) async throws
}

public struct RedeemedTunnelMetadata: Codable, Equatable, Sendable {
  public let operation: OperationContext
  public let lease: LeaseView
  public let configuration: AuthorityConfigurationDescriptor

  public init(
    operation: OperationContext, lease: LeaseView,
    configuration: AuthorityConfigurationDescriptor
  ) throws {
    guard operation.mode == .tunnel, lease.operation == operation,
      lease.state == .starting,
      configuration.configSHA256 == operation.configSHA256,
      configuration.identitySHA256 == operation.identitySHA256
    else { throw AuthorityV1ValidationError.invalidState }
    self.operation = operation
    self.lease = lease
    self.configuration = configuration
  }
}

extension RedeemedTunnelMetadata: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    try lease.validateAuthorityV1()
    try configuration.validateAuthorityV1()
    _ = try RedeemedTunnelMetadata(
      operation: operation, lease: lease, configuration: configuration)
  }
}

public enum AuthorityXPCErrorContract {
  public static let domain = "com.bill.clashformac.global-authority"
  public static let stableCodeKey = "authority_error_code"

  public static func error(_ code: AuthorityErrorCode) -> NSError {
    let index = AuthorityErrorCode.allCases.firstIndex(of: code) ?? 0
    return NSError(
      domain: domain, code: index + 1,
      userInfo: [
        stableCodeKey: code.rawValue,
        NSLocalizedDescriptionKey: code.stableMessage,
      ])
  }

  public static func domainError(_ error: Error) -> AuthorityDomainError {
    if let value = error as? AuthorityDomainError { return value }
    let value = error as NSError
    if value.domain == domain,
      let raw = value.userInfo[stableCodeKey] as? String,
      let code = AuthorityErrorCode(rawValue: raw)
    {
      return AuthorityDomainError(code: code)
    }
    return AuthorityDomainError(code: .globalAuthorityInterrupted)
  }
}
private struct PreparedStartWire: Codable, Sendable {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
  let ticket: [UInt8]?
  let ownerCapability: [UInt8]?
  let expiresMonotonic: UInt64
  let preferenceDescriptorSHA256: SHA256Digest

  enum CodingKeys: String, CodingKey {
    case operation
    case leaseID = "lease_id"
    case ticket
    case ownerCapability = "owner_capability"
    case expiresMonotonic = "expires_monotonic_ms"
    case preferenceDescriptorSHA256 = "preference_descriptor_sha256"
  }
}

extension PreparedStartWire: AuthorityV1WireModel {
  func validateAuthorityV1() throws {
    try operation.validateAuthorityV1()
    guard expiresMonotonic > 0,
      (operation.mode == .tunnel) == (ticket != nil),
      (operation.mode == .systemProxy) == (ownerCapability != nil),
      preferenceDescriptorSHA256 == operation.identitySHA256,
      ticket?.count ?? AuthorityV1Limits.ticketBytes == AuthorityV1Limits.ticketBytes,
      ownerCapability?.count ?? AuthorityV1Limits.capabilityBytes
        == AuthorityV1Limits.capabilityBytes
    else { throw AuthorityV1ValidationError.invalidState }
  }
}

public enum AuthorityPreparedStartCodec {
  public static func encode(
    _ prepared: PreparedStart, requestID: AuthorityIdentifier
  ) throws -> Data {
    let ticket: [UInt8]? = try prepared.ticket.map { try Array($0.transportCopy()) }
    let capability: [UInt8]? = try prepared.ownerCapability.map {
      try Array($0.transportCopy())
    }
    let wire = PreparedStartWire(
      operation: prepared.operation, leaseID: prepared.leaseID,
      ticket: ticket, ownerCapability: capability,
      expiresMonotonic: prepared.expiresMonotonic,
      preferenceDescriptorSHA256: prepared.preferenceDescriptorSHA256)
    return try AuthorityV1Codec.encodeResponse(
      AuthorityResponseEnvelope(
        requestID: requestID, operationID: prepared.operation.operationID,
        result: wire))
  }

  public static func decode(
    _ data: Data, requestID: AuthorityIdentifier,
    operationID: AuthorityIdentifier
  ) throws -> PreparedStart {
    let envelope = try AuthorityV1Codec.decodeResponse(PreparedStartWire.self, from: data)
    guard envelope.requestID == requestID, envelope.operationID == operationID else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    let wire = envelope.result
    return try PreparedStart(
      operation: wire.operation, leaseID: wire.leaseID,
      ticket: try wire.ticket.map { try StartTicket(copying: Data($0)) },
      ownerCapability: try wire.ownerCapability.map { try OwnerCapability(copying: Data($0)) },
      expiresMonotonic: wire.expiresMonotonic,
      preferenceDescriptorSHA256: wire.preferenceDescriptorSHA256)
  }
}
public enum AuthoritySecretPayloadCodec {
  private static let magic = Data("CFWASV01".utf8)
  private static let headerBytes = 10

  public static func encode(_ material: AuthoritySecretMaterial) throws -> SensitiveBytes? {
    guard !material.slots.isEmpty else { return nil }
    var data = Data()
    data.append(magic)
    append(UInt16(material.slots.count), to: &data)
    for slot in material.slots {
      append(UInt32(slot.byteCount), to: &data)
      data.append(try slot.transportCopy())
    }
    guard
      data.count <= headerBytes + 4 * AuthorityV1Limits.maximumCredentialSlots
        + AuthorityV1Limits.maximumTotalSecretBytes
    else { throw AuthorityV1ValidationError.boundViolation }
    defer { data.resetBytes(in: data.startIndex..<data.endIndex) }
    return try SensitiveBytes(copying: data, maximumCount: data.count)
  }

  public static func decode(
    _ payload: Data?, descriptor: AuthorityConfigurationDescriptor
  ) throws -> AuthoritySecretMaterial {
    if descriptor.credentialSlots.isEmpty {
      guard payload == nil else { throw AuthorityV1ValidationError.invalidConfiguration }
      return try AuthoritySecretMaterial(slots: [])
    }
    guard var payload, payload.count >= headerBytes,
      payload.count <= headerBytes + 4 * AuthorityV1Limits.maximumCredentialSlots
        + AuthorityV1Limits.maximumTotalSecretBytes
    else { throw AuthorityV1ValidationError.boundViolation }
    defer { payload.resetBytes(in: payload.startIndex..<payload.endIndex) }
    var offset = 0
    guard payload.prefix(magic.count) == magic else {
      throw AuthorityV1ValidationError.noncanonicalRepresentation
    }
    offset += magic.count
    let count: UInt16 = try read(from: payload, offset: &offset)
    guard Int(count) == descriptor.credentialSlots.count else {
      throw AuthorityV1ValidationError.invalidConfiguration
    }
    var slots: [AuthoritySecretSlot] = []
    do {
      for descriptorSlot in descriptor.credentialSlots {
        let length: UInt32 = try read(from: payload, offset: &offset)
        guard length > 0,
          length <= UInt32(AuthorityV1Limits.maximumIndividualSecretBytes),
          Int(length) <= payload.count - offset
        else { throw AuthorityV1ValidationError.boundViolation }
        let bytes = payload.subdata(in: offset..<(offset + Int(length)))
        offset += Int(length)
        slots.append(
          try AuthoritySecretSlot(
            reference: descriptorSlot.reference, copying: bytes))
      }
      guard offset == payload.count else {
        throw AuthorityV1ValidationError.noncanonicalRepresentation
      }
      return try AuthoritySecretMaterial(slots: slots)
    } catch {
      for slot in slots { slot.erase() }
      throw error
    }
  }
  private static func append<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }

  private static func read<T: FixedWidthInteger>(
    from data: Data, offset: inout Int
  ) throws -> T {
    let count = MemoryLayout<T>.size
    guard count <= data.count - offset else {
      throw AuthorityV1ValidationError.boundViolation
    }
    var value: T = 0
    withUnsafeMutableBytes(of: &value) { destination in
      _ = data.copyBytes(to: destination, from: offset..<(offset + count))
    }
    offset += count
    return T(bigEndian: value)
  }
}

public struct AuthorityQueuedEvent: Equatable, Sendable {
  public let event: AuthorityEvent
  public init(_ event: AuthorityEvent) { self.event = event }
}

public enum AuthorityEventEnqueueResult: Equatable, Sendable {
  case queued
  case peerMustDisconnect
}

public final class BoundedAuthorityEventQueue: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [AuthorityEvent] = []

  public init() {}

  public var count: Int { lock.withLock { events.count } }

  public func enqueue(_ event: AuthorityEvent) -> AuthorityEventEnqueueResult {
    lock.withLock {
      if case .snapshot = event {
        if let index = events.lastIndex(where: { if case .snapshot = $0 { true } else { false } }) {
          events[index] = event
          return .queued
        }
        guard events.count < AuthorityV1Limits.maximumQueuedEventsPerPeer else {
          return .peerMustDisconnect
        }
        events.append(event)
        return .queued
      }
      if events.count == AuthorityV1Limits.maximumQueuedEventsPerPeer,
        let snapshotIndex = events.firstIndex(where: {
          if case .snapshot = $0 { true } else { false }
        })
      {
        events.remove(at: snapshotIndex)
      }
      guard events.count < AuthorityV1Limits.maximumQueuedEventsPerPeer else {
        return .peerMustDisconnect
      }
      events.append(event)
      return .queued
    }
  }

  public func dequeue() -> AuthorityEvent? {
    lock.withLock { events.isEmpty ? nil : events.removeFirst() }
  }
}
