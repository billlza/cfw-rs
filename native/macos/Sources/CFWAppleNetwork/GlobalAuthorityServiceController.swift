import Foundation
import ServiceManagement

public enum GlobalAuthorityRegistrationStatus: Equatable, Sendable {
  case enabled
  case requiresApproval
  case notRegistered
  case notFound
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
    @unknown default: .notFound
    }
  }

  public func register() throws {
    try SMAppService.daemon(plistName: Self.plistName).register()
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
    case .notFound:
      throw GlobalAuthorityRegistrationError.serviceNotFound
    case .notRegistered:
      do { try service.register() } catch {
        throw GlobalAuthorityRegistrationError.registrationFailed
      }
      switch service.registrationStatus {
      case .enabled: return
      case .requiresApproval: throw GlobalAuthorityRegistrationError.approvalRequired
      case .notFound: throw GlobalAuthorityRegistrationError.serviceNotFound
      case .notRegistered: throw GlobalAuthorityRegistrationError.registrationFailed
      }
    }
  }
}
