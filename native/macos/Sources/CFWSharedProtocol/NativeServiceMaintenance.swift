import Foundation

public enum NativeServiceMaintenanceAction: String, Codable, Equatable, Sendable {
  case status
  case proveOff = "prove_off"
  case proveInstalled40019Off = "prove_installed_40019_off"
  case unregisterProxyAgent = "unregister_proxy_agent"
  case unregisterInstalled40019ProxyAgent = "unregister_installed_40019_proxy_agent"
  case unregisterGlobalAuthority = "unregister_global_authority"
  case unregisterInstalled40019GlobalAuthority =
    "unregister_installed_40019_global_authority"
  case recoverInstalled40019GlobalAuthority =
    "recover_installed_40019_global_authority"
  case registerGlobalAuthority = "register_global_authority"
  case registerProxyAgent = "register_proxy_agent"
}

public enum NativeServiceOffProofProfile: String, Codable, Equatable, Sendable {
  case installed40019EngineV5AuthorityV10 =
    "installed_40019_engine_v5_authority_v1_0"
  case installed40019RecoveryCurrentAuthorityV11 =
    "installed_40019_recovery_current_authority_v1_1"
  case currentEngineV6AuthorityV11 = "current_engine_v6_authority_v1_1"
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
  public let offProofProfile: NativeServiceOffProofProfile?
  public let proxyAgent: NativeServiceRegistrationStatus

  public init(
    action: NativeServiceMaintenanceAction,
    engineStatus: NativeServiceEngineStatus?,
    globalAuthority: NativeServiceRegistrationStatus,
    offProofProfile: NativeServiceOffProofProfile?,
    proxyAgent: NativeServiceRegistrationStatus
  ) {
    self.action = action
    self.engineStatus = engineStatus
    self.globalAuthority = globalAuthority
    self.offProofProfile = offProofProfile
    self.proxyAgent = proxyAgent
  }

  private enum CodingKeys: String, CodingKey {
    case action
    case engineStatus = "engine_status"
    case globalAuthority = "global_authority"
    case offProofProfile = "off_proof_profile"
    case proxyAgent = "proxy_agent"
  }
}
