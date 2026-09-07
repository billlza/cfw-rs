import CFWSharedProtocol
import Foundation

/// One-use System Proxy start authorization returned by the Global Authority.
/// The capability is never Codable and is erased when consumed or abandoned.
public final class HostPreparedSystemProxyStart: @unchecked Sendable {
  public let context: ProxyOwnerContext
  private let lock = NSLock()
  private var capability: OwnerCapability?

  init(context: ProxyOwnerContext, capability: OwnerCapability) {
    self.context = context
    self.capability = capability
  }

  deinit { erase() }

  func consumeCapabilityData() throws -> Data {
    let value: OwnerCapability = try lock.withLock {
      guard let capability else {
        throw AuthorityDomainError(code: .ticketAlreadyRedeemed)
      }
      self.capability = nil
      return capability
    }
    defer { value.erase() }
    return try value.withUnsafeBytes { Data($0) }
  }

  public func erase() {
    let value = lock.withLock {
      let value = capability
      capability = nil
      return value
    }
    value?.erase()
  }
}

public protocol SystemProxyStartPreparing: Sendable {
  func prepareSystemProxyStart(
    configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws -> HostPreparedSystemProxyStart

  func cancelSystemProxyStart(
    _ prepared: HostPreparedSystemProxyStart
  ) async throws
}

/// Host-side System Proxy preparation. A successful return is the only Host
/// authorization accepted by ProxyAgent; no Boolean or process-global flag can
/// bypass the Authority transaction.
public struct AuthorityBackedSystemProxyStartPreparer: SystemProxyStartPreparing {
  private let authority: any AuthorityClient
  private let enrollment: AuthorityInstallationEnrollment
  private let ownerUID: UInt32

  public init(
    authority: any AuthorityClient,
    enrollment: AuthorityInstallationEnrollment = AuthorityInstallationEnrollment(),
    ownerUID: UInt32 = UInt32(getuid())
  ) {
    self.authority = authority
    self.enrollment = enrollment
    self.ownerUID = ownerUID
  }

  public func prepareSystemProxyStart(
    configuration: Data,
    descriptor: ConfigurationDescriptor
  ) async throws -> HostPreparedSystemProxyStart {
    guard descriptor.slot == .systemProxy, descriptor.tunnelOptions == nil else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    _ = try await enrollment.enroll(descriptor.installationID)
    let snapshot = try await authority.snapshot()
    guard snapshot.state == .off, snapshot.leaseView == nil else {
      throw AuthorityDomainError(code: .globalAuthorityRecovering)
    }
    if let cursor = snapshot.replayCursor {
      guard cursor.installationID.rawValue == descriptor.installationID else {
        throw AuthorityDomainError(code: .replayRejected)
      }
    }

    let root = try RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch,
      generation: descriptor.generation)
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: root,
      mode: .systemProxy,
      configSHA256: descriptor.sha256,
      identitySHA256: descriptor.identitySHA256,
      ownerUID: ownerUID,
      authorityRevision: snapshot.revision)
    let authorityDescriptor = try AuthorityConfigurationDescriptor(
      byteCount: UInt32(descriptor.byteCount),
      configSHA256: descriptor.sha256,
      identitySHA256: descriptor.identitySHA256,
      credentialAudience: descriptor.credentialAudience,
      credentialSlots: descriptor.credentialSlots,
      tunnelOptions: nil)
    let request = try PrepareStartRequest(
      operation: operation,
      expectedRevision: snapshot.revision,
      configuration: authorityDescriptor)
    let sensitiveConfiguration = try SensitiveBytes(
      copying: configuration,
      maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
    let prepared = try await authority.prepare(
      request,
      configuration: sensitiveConfiguration,
      secrets: nil)
    defer { prepared.erase() }
    guard let issued = prepared.ownerCapability,
      prepared.operation == operation
    else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    let capability = try issued.withUnsafeBytes {
      try OwnerCapability(copying: Data($0))
    }
    return HostPreparedSystemProxyStart(
      context: try ProxyOwnerContext(
        operation: prepared.operation,
        leaseID: prepared.leaseID),
      capability: capability)
  }

  public func cancelSystemProxyStart(
    _ prepared: HostPreparedSystemProxyStart
  ) async throws {
    defer { prepared.erase() }
    let snapshot = try await authority.snapshot()
    if snapshot.state == .off, snapshot.leaseView == nil {
      return
    }
    guard let lease = snapshot.leaseView,
      lease.operation == prepared.context.operation,
      lease.leaseID == prepared.context.leaseID,
      snapshot.state == .preparing
    else {
      throw AuthorityDomainError(code: .compensationConflict)
    }
    try await authority.cancelPrepared(
      prepared.context.operation,
      revision: snapshot.revision)
  }
}
