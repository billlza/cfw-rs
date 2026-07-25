import CFWSharedProtocol
import CryptoKit
import Foundation
import Security

private typealias SHA256Digest = CFWSharedProtocol.SHA256Digest

public protocol AuthorityTicketRandomness: Sendable {
  func randomBytes(count: Int) throws -> Data
}

public struct SystemAuthorityTicketRandomness: AuthorityTicketRandomness {
  public init() {}

  public func randomBytes(count: Int) throws -> Data {
    guard count > 0 else { throw AuthoritySecretLifecycleError.randomGenerationFailed }
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { buffer -> OSStatus in
      guard let address = buffer.baseAddress else { return errSecParam }
      return SecRandomCopyBytes(kSecRandomDefault, count, address)
    }
    guard status == errSecSuccess else {
      bytes.securelyErase()
      throw AuthoritySecretLifecycleError.randomGenerationFailed
    }
    return bytes
  }
}

public protocol AuthorityMonotonicClock: Sendable {
  func nowMilliseconds() -> UInt64
}

public struct SystemAuthorityMonotonicClock: AuthorityMonotonicClock {
  public init() {}
  public func nowMilliseconds() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds / 1_000_000
  }
}

public enum AuthoritySecretTerminalPath: CaseIterable, Sendable {
  case rejection, cancellation, expiry, interruption, crashRecovery, error
}

public enum AuthoritySecretLifecycleError: Error, Equatable, Sendable, CustomStringConvertible {
  case invalidPreparation
  case unavailable
  case ticketExpired
  case ticketAlreadyRedeemed
  case ticketInvalid
  case transportConsumed
  case randomGenerationFailed

  public var description: String {
    switch self {
    case .invalidPreparation: "authority_secret_invalid_preparation"
    case .unavailable: "authority_secret_unavailable"
    case .ticketExpired: "authority_ticket_expired"
    case .ticketAlreadyRedeemed: "authority_ticket_already_redeemed"
    case .ticketInvalid: "authority_ticket_invalid"
    case .transportConsumed: "authority_secret_transport_consumed"
    case .randomGenerationFailed: "authority_ticket_random_generation_failed"
    }
  }
}

/// Owns the outbound Authority ticket until the synchronous XPC encoder borrows it.
/// The raw ticket is erased whether encoding succeeds or throws.
public final class AuthorityIssuedTicketTransport: @unchecked Sendable {
  public let expiresMonotonic: UInt64
  private let lock = NSLock()
  private let ticket: StartTicket
  private var available = true

  fileprivate init(ticket: StartTicket, expiresMonotonic: UInt64) {
    self.ticket = ticket
    self.expiresMonotonic = expiresMonotonic
  }

  deinit { erase() }

  public func withTicket<Result>(
    _ body: (StartTicket) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      guard available else { throw AuthoritySecretLifecycleError.transportConsumed }
      available = false
    }
    defer { ticket.erase() }
    return try body(ticket)
  }

  public func erase() {
    lock.withLock { available = false }
    ticket.erase()
  }

  var isErasedForTesting: Bool {
    (try? ticket.withUnsafeBytes { _ in false }) ?? true
  }
}

/// Owns redeemed Authority material at the transport boundary. Consumers get one
/// synchronous borrow; configuration and credentials are erased on every exit.
public final class AuthorityRedeemedTunnelTransport: @unchecked Sendable {
  private let lock = NSLock()
  private let configuration: SensitiveBytes
  private let secrets: AuthoritySecretMaterial
  private var available = true

  fileprivate init(configuration: SensitiveBytes, secrets: AuthoritySecretMaterial) {
    self.configuration = configuration
    self.secrets = secrets
  }

  deinit { erase() }

  public func withMaterial<Result>(
    _ body: (SensitiveBytes, AuthoritySecretMaterial) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      guard available else { throw AuthoritySecretLifecycleError.transportConsumed }
      available = false
    }
    defer { eraseOwnedBuffers() }
    return try body(configuration, secrets)
  }

  public func erase() {
    lock.withLock { available = false }
    eraseOwnedBuffers()
  }

  private func eraseOwnedBuffers() {
    configuration.erase()
    secrets.erase()
  }

  var isErasedForTesting: Bool {
    configuration.isErased && secrets.slots.allSatisfy(\.isErased)
  }
}

/// Machine-global in-memory owner for one pending Tunnel preparation.
/// Only a ticket digest and bounded mutable buffers are retained.
public final class TunnelSecretLifecycle: @unchecked Sendable {
  private struct Pending {
    let operation: OperationContext
    let leaseID: AuthorityIdentifier
    let ticketSHA256: SHA256Digest
    let expiresMonotonic: UInt64
    let configuration: SensitiveBytes
    let secrets: AuthoritySecretMaterial

    func erase() {
      configuration.erase()
      secrets.erase()
    }
  }

  private enum RedemptionDecision {
    case redeem(Pending)
    case reject(Pending?, AuthoritySecretLifecycleError)
  }

  private let lock = NSLock()
  private let randomness: any AuthorityTicketRandomness
  private let clock: any AuthorityMonotonicClock
  private var pending: Pending?
  private var consumedTicketHashes: [SHA256Digest: UInt64] = [:]

  public init(
    randomness: any AuthorityTicketRandomness = SystemAuthorityTicketRandomness(),
    clock: any AuthorityMonotonicClock = SystemAuthorityMonotonicClock()
  ) {
    self.randomness = randomness
    self.clock = clock
  }

  deinit { terminate(.crashRecovery) }

  public func prepare(
    request: PrepareStartRequest,
    leaseID: AuthorityIdentifier,
    configuration: SensitiveBytes,
    secrets: AuthoritySecretMaterial,
    lifetimeMilliseconds: UInt64 = AuthorityV1Limits.preparationLifetimeMilliseconds
  ) throws -> AuthorityIssuedTicketTransport {
    var accepted = false
    defer {
      if !accepted {
        configuration.erase()
        secrets.erase()
      }
    }
    try validatePreparation(
      request: request, configuration: configuration, secrets: secrets,
      lifetimeMilliseconds: lifetimeMilliseconds)
    _ = expireIfNeeded()

    let issued = clock.nowMilliseconds()
    let (expires, overflow) = issued.addingReportingOverflow(lifetimeMilliseconds)
    guard !overflow else { throw AuthoritySecretLifecycleError.invalidPreparation }

    var randomBytes = try randomness.randomBytes(count: AuthorityV1Limits.ticketBytes)
    defer { randomBytes.securelyErase() }
    guard randomBytes.count == AuthorityV1Limits.ticketBytes else {
      throw AuthoritySecretLifecycleError.randomGenerationFailed
    }
    let digest = try Self.digest(randomBytes)
    let ticket = try StartTicket(copying: randomBytes)
    var installed = false
    defer {
      if !installed { ticket.erase() }
    }

    try lock.withLock {
      purgeConsumed(at: issued)
      guard pending == nil else { throw AuthoritySecretLifecycleError.unavailable }
      guard consumedTicketHashes[digest] == nil else {
        throw AuthoritySecretLifecycleError.randomGenerationFailed
      }
      pending = Pending(
        operation: request.operation, leaseID: leaseID,
        ticketSHA256: digest, expiresMonotonic: expires,
        configuration: configuration, secrets: secrets)
      installed = true
      accepted = true
    }
    return AuthorityIssuedTicketTransport(ticket: ticket, expiresMonotonic: expires)
  }

  public func redeem(
    ticket: StartTicket,
    operation: OperationContext,
    leaseID: AuthorityIdentifier
  ) throws -> AuthorityRedeemedTunnelTransport {
    defer { ticket.erase() }
    let digest: SHA256Digest
    do {
      digest = try ticket.withUnsafeBytes { raw in
        var copy = Data(raw)
        defer { copy.securelyErase() }
        return try Self.digest(copy)
      }
    } catch {
      throw AuthoritySecretLifecycleError.ticketInvalid
    }
    let now = clock.nowMilliseconds()
    let decision: RedemptionDecision = lock.withLock {
      purgeConsumed(at: now)
      if consumedTicketHashes[digest] != nil {
        return .reject(nil, .ticketAlreadyRedeemed)
      }
      guard let value = pending else { return .reject(nil, .ticketInvalid) }
      pending = nil
      guard now < value.expiresMonotonic else {
        return .reject(value, .ticketExpired)
      }
      guard value.ticketSHA256 == digest,
        value.operation == operation, value.leaseID == leaseID
      else { return .reject(value, .ticketInvalid) }
      consumedTicketHashes[digest] = value.expiresMonotonic
      return .redeem(value)
    }
    switch decision {
    case .redeem(let value):
      return AuthorityRedeemedTunnelTransport(
        configuration: value.configuration, secrets: value.secrets)
    case .reject(let value, let error):
      value?.erase()
      throw error
    }
  }

  @discardableResult
  public func expireIfNeeded() -> Bool {
    let now = clock.nowMilliseconds()
    let expired: Pending? = lock.withLock {
      purgeConsumed(at: now)
      guard let value = pending, now >= value.expiresMonotonic else { return nil }
      pending = nil
      return value
    }
    expired?.erase()
    return expired != nil
  }

  public func terminate(_ path: AuthoritySecretTerminalPath) {
    _ = path
    let value: Pending? = lock.withLock {
      let value = pending
      pending = nil
      consumedTicketHashes.removeAll(keepingCapacity: false)
      return value
    }
    value?.erase()
  }

  private func validatePreparation(
    request: PrepareStartRequest,
    configuration: SensitiveBytes,
    secrets: AuthoritySecretMaterial,
    lifetimeMilliseconds: UInt64
  ) throws {
    guard request.operation.mode == .tunnel,
      lifetimeMilliseconds > 0,
      lifetimeMilliseconds <= AuthorityV1Limits.preparationLifetimeMilliseconds,
      configuration.count == Int(request.configuration.byteCount),
      secrets.slots.count <= AuthorityV1Limits.maximumCredentialSlots,
      secrets.totalByteCount <= AuthorityV1Limits.maximumTotalSecretBytes,
      secrets.slots.allSatisfy({
        $0.byteCount > 0
          && $0.byteCount <= AuthorityV1Limits.maximumIndividualSecretBytes
      })
    else { throw AuthoritySecretLifecycleError.invalidPreparation }

    let actualDigest = try configuration.withUnsafeBytes { raw -> SHA256Digest in
      var copy = Data(raw)
      defer { copy.securelyErase() }
      return try Self.digest(copy)
    }
    guard actualDigest == request.configuration.configSHA256 else {
      throw AuthoritySecretLifecycleError.invalidPreparation
    }

    var expected: [UUID: CredentialKind] = [:]
    for slot in request.configuration.credentialSlots {
      if let existing = expected[slot.reference.id], existing != slot.reference.kind {
        throw AuthoritySecretLifecycleError.invalidPreparation
      }
      expected[slot.reference.id] = slot.reference.kind
    }
    let supplied = Dictionary(
      uniqueKeysWithValues: secrets.slots.map {
        ($0.reference.id, $0.reference.kind)
      })
    guard supplied == expected else {
      throw AuthoritySecretLifecycleError.invalidPreparation
    }
  }

  private func purgeConsumed(at now: UInt64) {
    consumedTicketHashes = consumedTicketHashes.filter { now < $0.value }
  }

  private static func digest(_ data: Data) throws -> SHA256Digest {
    try SHA256Digest(hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
  }

  var retainedTicketHashForTesting: CFWSharedProtocol.SHA256Digest? {
    lock.withLock { pending?.ticketSHA256 }
  }

  var hasPendingMaterialForTesting: Bool {
    lock.withLock { pending != nil }
  }
}

extension Data {
  fileprivate mutating func securelyErase() {
    resetBytes(in: startIndex..<endIndex)
    removeAll(keepingCapacity: false)
  }
}
