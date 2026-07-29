import CFWSharedProtocol
import Foundation

/// Explicit, immutable installation-enrollment state held by the Host.
///
/// The immutable installation ID is enrolled exactly once into the empty root
/// store by an authenticated console Host (Requirement 2.6). This actor is the
/// Host-side guard mirroring the Authority's durable replay-cursor immutability:
/// the first installation ID it observes is bound for the object's lifetime, a
/// second *different* installation ID is rejected, and re-enrolling the same ID
/// is idempotent. It never stores configuration or secret bytes.
public actor AuthorityInstallationEnrollment {
  public enum EnrollmentError: Error, Equatable, Sendable {
    /// A different installation ID is already enrolled; enrollment is immutable.
    case installationImmutable
  }

  private var enrolled: UUID?

  public init(enrolledInstallationID: UUID? = nil) {
    enrolled = enrolledInstallationID
  }

  /// The immutable installation ID, once enrolled.
  public var installationID: UUID? { enrolled }

  /// Enrolls exactly one immutable installation ID. Re-enrolling the same ID is
  /// idempotent; a different ID fails closed with `installationImmutable`.
  @discardableResult
  public func enroll(_ installationID: UUID) throws -> UUID {
    if let enrolled {
      guard enrolled == installationID else {
        throw EnrollmentError.installationImmutable
      }
      return enrolled
    }
    enrolled = installationID
    return installationID
  }
}

/// Concrete `TunnelStartPreparing` that prepares a Tunnel start through the
/// Global Authority over the typed, bounded Host Authority client. It replaces
/// the Host's fail-closed placeholder for the preparation step only: it obtains
/// the single-use opaque Start Ticket and never returns configuration or secret
/// bytes to the Host.
///
/// Every step fails closed. Enrollment immutability, a bounded per-request
/// timeout, an interrupted connection, a recovering/quarantined Authority, or an
/// out-of-bounds request all surface as a stable typed Authority error to Rust;
/// none of them mutate preferences or the network. Configuration and credential
/// bytes are wrapped in `SensitiveBytes`, which the client erases on every path.
public struct AuthorityBackedTunnelStartPreparer: TunnelStartPreparing {
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

  public func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart {
    do {
      return try await prepareThrowingTyped(preparation)
    } catch {
      throw Self.failClosed(error)
    }
  }

  private func prepareThrowingTyped(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart {
    let descriptor = preparation.descriptor
    guard descriptor.slot == .tunnel, let tunnelOptions = descriptor.tunnelOptions else {
      throw AppleNetworkError.invalidConfigurationSlot
    }

    // (1) Enroll one immutable installation ID before any Authority mutation. A
    // second, different installation is rejected fail-closed and never reaches
    // the Authority.
    _ = try await enrollment.enroll(descriptor.installationID)

    // (2) Read the current durable Authority revision to compare-and-swap
    // against. This bounded read fails closed on timeout/interruption/recovery.
    let snapshot = try await authority.snapshot()
    if let cursor = snapshot.replayCursor {
      guard cursor.installationID.rawValue == descriptor.installationID else {
        // The durable root store is enrolled to a different installation lineage.
        throw AuthorityDomainError(code: .replayRejected)
      }
    } else {
      guard snapshot.state == .off, snapshot.leaseView == nil else {
        throw AuthorityDomainError(code: .globalAuthorityRecovering)
      }
    }

    // (3) Build the typed, bounded prepare request from the non-secret descriptor.
    let root = try RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch,
      generation: descriptor.generation)
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: root,
      mode: .tunnel,
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
      tunnelOptions: tunnelOptions)
    let request = try PrepareStartRequest(
      operation: operation,
      expectedRevision: snapshot.revision,
      configuration: authorityDescriptor)

    // (4) Wrap sensitive material for the bounded transport. The client erases
    // these buffers on every success/error/cancel path.
    let configuration = try SensitiveBytes(
      copying: preparation.configuration,
      maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
    let secrets = try preparation.credentialPayload.map {
      try SensitiveBytes(
        copying: $0, maximumCount: AuthorityV1Limits.maximumTotalSecretBytes)
    }

    // (5) Prepare with the Authority. A Tunnel preparation must return the
    // single-use opaque ticket; the owner capability is Proxy-only.
    let prepared = try await authority.prepare(
      request, configuration: configuration, secrets: secrets)
    defer { prepared.erase() }
    guard let preparedTicket = prepared.ticket else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    // Copy the ticket bytes out before `prepared` erases its backing buffer.
    let ticket = try preparedTicket.withUnsafeBytes { try StartTicket(copying: Data($0)) }
    return HostPreparedTunnelStart(ticket: ticket, descriptor: descriptor)
  }

  /// Normalizes any failure into a stable typed error suitable for the Rust
  /// boundary. Typed Authority and Apple network errors pass through unchanged so
  /// their specific stable code (timeout, interrupted, recovering, replay, etc.)
  /// is preserved; cancellation is preserved for the caller's bounded wait; every
  /// other failure fails closed as an unavailable Authority.
  static func failClosed(_ error: Error) -> Error {
    if error is CancellationError { return error }
    if error is AuthorityDomainError { return error }
    if error is AppleNetworkError { return error }
    if let error = error as? AuthorityInstallationEnrollment.EnrollmentError {
      switch error {
      case .installationImmutable:
        // A different installation ID cannot consume the enrolled lineage.
        return AuthorityDomainError(code: .replayRejected)
      }
    }
    if error is AuthorityV1ValidationError || error is ProtocolValidationError {
      return AuthorityDomainError(code: .invalidMessage)
    }
    return AuthorityDomainError(code: .globalAuthorityUnavailable)
  }
}
