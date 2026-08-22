import Foundation

public enum NativeServiceMaintenanceAction: String, Codable, Equatable, Sendable {
  case status
  case proveOff = "prove_off"
  case unregisterProxyAgent = "unregister_proxy_agent"
  case unregisterGlobalAuthority = "unregister_global_authority"
  case registerGlobalAuthority = "register_global_authority"
  case registerProxyAgent = "register_proxy_agent"
}

public enum NativeServiceRegistrationStatus: String, Codable, Equatable, Sendable {
  case enabled
  case requiresApproval = "requires_approval"
  case notRegistered = "not_registered"
  case notFound = "not_found"
  case unknown
}

public enum NativeServiceEngineStatus: String, Codable, Equatable, Sendable {
  case off
}

public struct NativeServiceMaintenanceResult: Codable, Equatable, Sendable {
  public let action: NativeServiceMaintenanceAction
  public let engineStatus: NativeServiceEngineStatus?
  public let globalAuthority: NativeServiceRegistrationStatus
  public let proxyAgent: NativeServiceRegistrationStatus

  public init(
    action: NativeServiceMaintenanceAction,
    engineStatus: NativeServiceEngineStatus?,
    globalAuthority: NativeServiceRegistrationStatus,
    proxyAgent: NativeServiceRegistrationStatus
  ) {
    self.action = action
    self.engineStatus = engineStatus
    self.globalAuthority = globalAuthority
    self.proxyAgent = proxyAgent
  }

  private enum CodingKeys: String, CodingKey {
    case action
    case engineStatus = "engine_status"
    case globalAuthority = "global_authority"
    case proxyAgent = "proxy_agent"
  }
}
