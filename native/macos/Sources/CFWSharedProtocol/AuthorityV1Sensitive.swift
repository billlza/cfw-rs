import Darwin
import Foundation

/// Mutable, exclusively owned bytes for Authority capabilities and secret material.
/// This type intentionally has no Codable, printable, or persistence conformance.
public final class SensitiveBytes: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: UnsafeMutableRawPointer?
  public let count: Int

  public init(copying data: Data, maximumCount: Int) throws {
    guard !data.isEmpty, data.count <= maximumCount else {
      throw AuthorityV1ValidationError.boundViolation
    }
    count = data.count
    let pointer = UnsafeMutableRawPointer.allocate(byteCount: data.count, alignment: 1)
    data.copyBytes(to: pointer.assumingMemoryBound(to: UInt8.self), count: data.count)
    _ = Darwin.mlock(pointer, data.count)
    storage = pointer
  }

  deinit { erase() }

  public var isErased: Bool { lock.withLock { storage == nil } }

  public func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      guard let storage else { throw AuthorityV1ValidationError.secretUnavailable }
      return try body(UnsafeRawBufferPointer(start: storage, count: count))
    }
  }

  public func erase() {
    lock.withLock {
      guard let pointer = storage else { return }
      pointer.initializeMemory(as: UInt8.self, repeating: 0, count: count)
      _ = Darwin.munlock(pointer, count)
      pointer.deallocate()
      storage = nil
    }
  }

  func transportCopy() throws -> Data {
    try withUnsafeBytes { Data($0) }
  }
}

/// Random 32-byte, single-use Tunnel bootstrap capability.
/// It intentionally cannot be encoded except by AuthorityV1Codec's bounded transport path.
public final class StartTicket: @unchecked Sendable {
  private let bytes: SensitiveBytes

  public init(copying data: Data) throws {
    guard data.count == AuthorityV1Limits.ticketBytes else {
      throw AuthorityV1ValidationError.invalidTicket
    }
    bytes = try SensitiveBytes(copying: data, maximumCount: AuthorityV1Limits.ticketBytes)
  }

  public func erase() { bytes.erase() }

  /// Borrows the ticket without creating a persistent or printable representation.
  /// Callers must not retain the buffer beyond the synchronous closure.
  public func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }

  func transportCopy() throws -> Data { try bytes.transportCopy() }
}

/// Random ProxyAgent owner capability. Like StartTicket, it is memory-only and non-Codable.
public final class OwnerCapability: @unchecked Sendable {
  private let bytes: SensitiveBytes

  public init(copying data: Data) throws {
    guard data.count == AuthorityV1Limits.capabilityBytes else {
      throw AuthorityV1ValidationError.invalidCapability
    }
    bytes = try SensitiveBytes(copying: data, maximumCount: AuthorityV1Limits.capabilityBytes)
  }

  public func erase() { bytes.erase() }

  public func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }

  func transportCopy() throws -> Data { try bytes.transportCopy() }
}

public final class AuthoritySecretSlot: @unchecked Sendable {
  public let reference: CredentialReference
  public var byteCount: Int { bytes.count }
  private let bytes: SensitiveBytes

  public init(reference: CredentialReference, copying secret: Data) throws {
    bytes = try SensitiveBytes(
      copying: secret,
      maximumCount: AuthorityV1Limits.maximumIndividualSecretBytes
    )
    self.reference = reference
  }

  public var isErased: Bool { bytes.isErased }
  public func erase() { bytes.erase() }
  public func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }
  func transportCopy() throws -> Data { try bytes.transportCopy() }
}

/// Bounded credential material supplied only as the separate prepare/redeem XPC Data argument.
/// It has no Codable or printable conformance and erases every owned slot together.
public final class AuthoritySecretMaterial: @unchecked Sendable {
  public let slots: [AuthoritySecretSlot]
  public let totalByteCount: Int

  public init(slots: [AuthoritySecretSlot]) throws {
    var accepted = false
    defer {
      if !accepted {
        for slot in slots { slot.erase() }
      }
    }
    guard slots.count <= AuthorityV1Limits.maximumCredentialSlots else {
      throw AuthorityV1ValidationError.boundViolation
    }
    var references = Set<UUID>()
    var total = 0
    for slot in slots {
      guard references.insert(slot.reference.id).inserted else {
        throw AuthorityV1ValidationError.duplicateCredentialSlot
      }
      let count = slot.byteCount
      let (next, overflow) = total.addingReportingOverflow(count)
      guard !overflow, next <= AuthorityV1Limits.maximumTotalSecretBytes else {
        throw AuthorityV1ValidationError.boundViolation
      }
      total = next
    }
    self.slots = slots
    totalByteCount = total
    accepted = true
  }

  deinit { erase() }

  public func erase() {
    for slot in slots { slot.erase() }
  }
}
