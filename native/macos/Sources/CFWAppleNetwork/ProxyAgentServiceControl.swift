import CFWSharedProtocol
import Foundation
import ServiceManagement

public enum ProxyAgentRegistrationStatus: Equatable, Sendable {
  case enabled
  case requiresApproval
  case notRegistered
  case notFound
  case unknown
}

public enum ProxyAgentHostError: Error, Equatable, Sendable {
  case registrationRequiresApproval
  case registrationUnavailable
  case registrationFailed(String)
  case transportUnavailable(String)
  case transportTimedOut
  case transportCapacityExceeded
  case authorizationDenied
  case authorizationPending
  case authorizationFailed
  case malformedResponse
  case responseMismatch
  case agentFailure(EngineFailure)
}

extension ProxyAgentHostError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .registrationRequiresApproval:
      "ProxyAgent requires approval in System Settings > Login Items."
    case .registrationUnavailable:
      "The signed ProxyAgent launch service is missing from the application bundle."
    case .registrationFailed:
      "ProxyAgent registration failed."
    case .transportUnavailable:
      "ProxyAgent XPC transport is unavailable."
    case .transportTimedOut:
      "ProxyAgent did not reply before the bounded timeout."
    case .transportCapacityExceeded:
      "ProxyAgent request capacity is exhausted."
    case .authorizationDenied:
      "macOS network authorization was not granted."
    case .authorizationPending:
      "A macOS network authorization dialog is already pending."
    case .authorizationFailed:
      "macOS network authorization could not be requested."
    case .malformedResponse:
      "ProxyAgent returned a malformed response."
    case .responseMismatch:
      "ProxyAgent response does not match the request identity."
    case .agentFailure(let failure):
      "ProxyAgent rejected the operation (\(failure.code)): \(failure.message)"
    }
  }
}

public protocol ProxyAgentServiceControlling: Sendable {
  func registrationStatus() -> ProxyAgentRegistrationStatus
  func ensureRegistered() throws
}

public protocol ProxyAgentServicing: Sendable {
  var registrationStatus: ProxyAgentRegistrationStatus { get }
  func requireRegistrationReady() throws
  func register() throws
  func unregister() async throws
}

public struct SMProxyAgentService: ProxyAgentServicing {
  public static let launchAgentPlistName = "com.bill.clashformac.proxy-agent.plist"
  private let unregistration = ServiceUnregistrationBarrier()

  public init() {}

  public var registrationStatus: ProxyAgentRegistrationStatus {
    switch SMAppService.agent(plistName: Self.launchAgentPlistName).status {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notRegistered: .notRegistered
    case .notFound: .notFound
    @unknown default: .unknown
    }
  }

  public func requireRegistrationReady() throws {
    try unregistration.requireRegistrationReady()
  }

  public func register() throws {
    try unregistration.register {
      try SMAppService.agent(plistName: Self.launchAgentPlistName).register()
    }
  }

  public func unregister() async throws {
    try await unregistration.unregister { finish in
      SMAppService.agent(plistName: Self.launchAgentPlistName).unregister { error in
        finish(error.map { .failure($0) } ?? .success(()))
      }
    }
  }
}

public struct SMProxyAgentServiceController: ProxyAgentServiceControlling, Sendable {
  private let service: any ProxyAgentServicing

  public init(service: any ProxyAgentServicing = SMProxyAgentService()) {
    self.service = service
  }

  public func registrationStatus() -> ProxyAgentRegistrationStatus {
    service.registrationStatus
  }

  public func ensureRegistered() throws {
    do { try service.requireRegistrationReady() } catch {
      throw ProxyAgentHostError.registrationFailed("service unregistration remains pending")
    }
    switch service.registrationStatus {
    case .enabled:
      return
    case .requiresApproval:
      throw ProxyAgentHostError.registrationRequiresApproval
    case .notFound, .notRegistered:
      do {
        try service.register()
      } catch {
        switch service.registrationStatus {
        case .requiresApproval:
          throw ProxyAgentHostError.registrationRequiresApproval
        case .notFound:
          throw ProxyAgentHostError.registrationUnavailable
        case .enabled, .notRegistered, .unknown:
          throw ProxyAgentHostError.registrationFailed(error.localizedDescription)
        }
      }
      switch service.registrationStatus {
      case .enabled:
        return
      case .requiresApproval:
        throw ProxyAgentHostError.registrationRequiresApproval
      case .notRegistered, .notFound, .unknown:
        throw ProxyAgentHostError.registrationUnavailable
      }
    case .unknown:
      throw ProxyAgentHostError.registrationUnavailable
    }
  }
}
