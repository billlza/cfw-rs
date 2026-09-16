import CFWSharedProtocol
import Foundation
import ServiceManagement

public enum GlobalAuthorityRegistrationStatus: Equatable, Sendable {
  case enabled
  case requiresApproval
  case notRegistered
  case notFound
  case unknown
}

public enum GlobalAuthorityRegistrationError: Error, Equatable, Sendable {
  case approvalRequired
  case serviceNotFound
  case registrationFailed
}

public protocol GlobalAuthorityServiceControlling: Sendable {
  func registrationStatus() -> GlobalAuthorityRegistrationStatus
  func ensureRegistered() throws
}

public protocol GlobalAuthorityDaemonServicing: Sendable {
  var registrationStatus: GlobalAuthorityRegistrationStatus { get }
  func register() throws
  func unregister() throws
}

public struct SMGlobalAuthorityDaemonService: GlobalAuthorityDaemonServicing {
  public static let plistName = "com.bill.clashformac.global-authority.plist"

  public init() {}

  public var registrationStatus: GlobalAuthorityRegistrationStatus {
    switch SMAppService.daemon(plistName: Self.plistName).status {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notRegistered: .notRegistered
    case .notFound: .notFound
    @unknown default: .unknown
    }
  }

  public func register() throws {
    try SMAppService.daemon(plistName: Self.plistName).register()
  }

  public func unregister() throws {
    try SMAppService.daemon(plistName: Self.plistName).unregister()
  }
}

public struct SMGlobalAuthorityServiceController: GlobalAuthorityServiceControlling {
  private let service: any GlobalAuthorityDaemonServicing

  public init(service: any GlobalAuthorityDaemonServicing = SMGlobalAuthorityDaemonService()) {
    self.service = service
  }

  public func registrationStatus() -> GlobalAuthorityRegistrationStatus {
    service.registrationStatus
  }

  public func ensureRegistered() throws {
    switch service.registrationStatus {
    case .enabled:
      return
    case .requiresApproval:
      throw GlobalAuthorityRegistrationError.approvalRequired
    case .notFound, .notRegistered:
      do {
        try service.register()
      } catch {
        switch service.registrationStatus {
        case .requiresApproval:
          throw GlobalAuthorityRegistrationError.approvalRequired
        case .notFound:
          throw GlobalAuthorityRegistrationError.serviceNotFound
        case .enabled, .notRegistered, .unknown:
          throw GlobalAuthorityRegistrationError.registrationFailed
        }
      }
      switch service.registrationStatus {
      case .enabled: return
      case .requiresApproval: throw GlobalAuthorityRegistrationError.approvalRequired
      case .notFound: throw GlobalAuthorityRegistrationError.serviceNotFound
      case .notRegistered, .unknown: throw GlobalAuthorityRegistrationError.registrationFailed
      }
    case .unknown:
      throw GlobalAuthorityRegistrationError.registrationFailed
    }
  }
}

/// Host-side Authority client boundary that establishes the embedded launchd
/// daemon registration before any XPC operation. Approval and packaging absence
/// remain distinct typed Authority errors so the UI can present the existing
/// System Settings action without treating either state as an empty result.
public actor RegistrationGatedAuthorityClient: AuthorityClient {
  private let serviceController: any GlobalAuthorityServiceControlling
  private let authority: any AuthorityClient

  public init(
    serviceController: any GlobalAuthorityServiceControlling =
      SMGlobalAuthorityServiceController(),
    authority: any AuthorityClient
  ) {
    self.serviceController = serviceController
    self.authority = authority
  }

  public func prepare(
    _ request: PrepareStartRequest,
    configuration: SensitiveBytes,
    secrets: SensitiveBytes?
  ) async throws -> PreparedStart {
    try ensureRegistered()
    return try await authority.prepare(
      request, configuration: configuration, secrets: secrets)
  }

  public func cancelPrepared(
    _ context: OperationContext,
    revision: UInt64
  ) async throws {
    try ensureRegistered()
    try await authority.cancelPrepared(context, revision: revision)
  }

  public func beginStop(_ request: BeginStopRequest) async throws -> StopDirective {
    try ensureRegistered()
    return try await authority.beginStop(request)
  }

  public func completeStop(_ request: CompleteStopRequest) async throws {
    try ensureRegistered()
    try await authority.completeStop(request)
  }

  public func reconcileOff(
    _ request: ReconcileOffRequest
  ) async throws -> ReconcileOffReceipt {
    try ensureRegistered()
    return try await authority.reconcileOff(request)
  }

  public func snapshot() async throws -> AuthoritySnapshot {
    try ensureRegistered()
    return try await authority.snapshot()
  }

  private func ensureRegistered() throws {
    do {
      try serviceController.ensureRegistered()
    } catch let error as GlobalAuthorityRegistrationError {
      switch error {
      case .approvalRequired:
        throw AuthorityDomainError(code: .globalAuthorityApprovalRequired)
      case .serviceNotFound, .registrationFailed:
        throw AuthorityDomainError(code: .globalAuthorityRegistrationRequired)
      }
    } catch {
      throw AuthorityDomainError(code: .globalAuthorityRegistrationRequired)
    }
  }
}
