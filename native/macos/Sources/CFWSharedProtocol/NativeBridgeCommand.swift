import Foundation

public enum NativeBridgeCommand: Equatable, Sendable {
  case queryStatus
  case maintainCurrentServices(NativeServiceMaintenanceAction)
  case startSystemProxy(EngineStartRequest)
  case stopSystemProxy(EngineCommandContext)
  case installTunnel(EngineCommandContext)
  case cancelTunnelInstall(EngineCommandContext)
  case startTunnel(EngineStartRequest)
  case stopTunnel(EngineCommandContext)
  case provisionCredentials(CredentialProvisionRequest)
  case queryCredentialPresence(CredentialPresenceRequest)
  case preflightCutover(CutoverPreflightRequest)
  case previewCredentialGarbageCollection(CredentialGarbageCollectionRequest)
  case commitCredentialGarbageCollection(CredentialGarbageCollectionCommitRequest)
}

extension NativeBridgeCommand: Codable {
  private enum CodingKeys: String, CodingKey {
    case opcode
    case payload
  }

  private enum PayloadKeys: String, CodingKey {
    case action
    case request
    case context
  }

  private enum Opcode: String, Codable {
    case queryStatus = "query_status"
    case maintainCurrentServices = "maintain_current_services"
    case startSystemProxy = "start_system_proxy"
    case stopSystemProxy = "stop_system_proxy"
    case installTunnel = "install_tunnel"
    case cancelTunnelInstall = "cancel_tunnel_install"
    case startTunnel = "start_tunnel"
    case stopTunnel = "stop_tunnel"
    case provisionCredentials = "provision_credentials"
    case queryCredentialPresence = "query_credential_presence"
    case preflightCutover = "preflight_cutover"
    case previewCredentialGarbageCollection = "preview_credential_garbage_collection"
    case commitCredentialGarbageCollection = "commit_credential_garbage_collection"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let opcode = try container.decode(Opcode.self, forKey: .opcode)
    switch opcode {
    case .queryStatus:
      guard !container.contains(.payload) else {
        throw NativeBridgeProtocolError.invalidCommand
      }
      self = .queryStatus
    case .maintainCurrentServices:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      self = .maintainCurrentServices(
        try payload.decode(NativeServiceMaintenanceAction.self, forKey: .action)
      )
    case .startSystemProxy, .startTunnel:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      let request = try payload.decode(EngineStartRequest.self, forKey: .request)
      if opcode == .startSystemProxy {
        guard request.tunnelOptions == nil else {
          throw NativeBridgeProtocolError.invalidCommand
        }
        self = .startSystemProxy(request)
      } else {
        guard request.tunnelOptions != nil else {
          throw NativeBridgeProtocolError.invalidCommand
        }
        self = .startTunnel(request)
      }
    case .stopSystemProxy, .installTunnel, .cancelTunnelInstall, .stopTunnel:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      let context = try payload.decode(EngineCommandContext.self, forKey: .context)
      switch opcode {
      case .stopSystemProxy: self = .stopSystemProxy(context)
      case .installTunnel: self = .installTunnel(context)
      case .cancelTunnelInstall: self = .cancelTunnelInstall(context)
      case .stopTunnel: self = .stopTunnel(context)
      case .queryStatus, .maintainCurrentServices, .startSystemProxy, .startTunnel,
        .provisionCredentials,
        .queryCredentialPresence, .previewCredentialGarbageCollection,
        .commitCredentialGarbageCollection, .preflightCutover:
        throw NativeBridgeProtocolError.invalidCommand
      }
    case .provisionCredentials:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      self = .provisionCredentials(
        try payload.decode(CredentialProvisionRequest.self, forKey: .request)
      )
    case .queryCredentialPresence:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      self = .queryCredentialPresence(
        try payload.decode(CredentialPresenceRequest.self, forKey: .request)
      )
    case .preflightCutover:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      self = .preflightCutover(
        try payload.decode(CutoverPreflightRequest.self, forKey: .request)
      )
    case .previewCredentialGarbageCollection:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      self = .previewCredentialGarbageCollection(
        try payload.decode(CredentialGarbageCollectionRequest.self, forKey: .request)
      )
    case .commitCredentialGarbageCollection:
      let payload = try container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      self = .commitCredentialGarbageCollection(
        try payload.decode(CredentialGarbageCollectionCommitRequest.self, forKey: .request)
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .queryStatus:
      try container.encode(Opcode.queryStatus, forKey: .opcode)
    case .maintainCurrentServices(let action):
      try container.encode(Opcode.maintainCurrentServices, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(action, forKey: .action)
    case .startSystemProxy(let request):
      try container.encode(Opcode.startSystemProxy, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    case .stopSystemProxy(let context):
      try container.encode(Opcode.stopSystemProxy, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(context, forKey: .context)
    case .installTunnel(let context):
      try container.encode(Opcode.installTunnel, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(context, forKey: .context)
    case .cancelTunnelInstall(let context):
      try container.encode(Opcode.cancelTunnelInstall, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(context, forKey: .context)
    case .startTunnel(let request):
      try container.encode(Opcode.startTunnel, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    case .stopTunnel(let context):
      try container.encode(Opcode.stopTunnel, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(context, forKey: .context)
    case .provisionCredentials(let request):
      try container.encode(Opcode.provisionCredentials, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    case .queryCredentialPresence(let request):
      try container.encode(Opcode.queryCredentialPresence, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    case .preflightCutover(let request):
      try container.encode(Opcode.preflightCutover, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    case .previewCredentialGarbageCollection(let request):
      try container.encode(Opcode.previewCredentialGarbageCollection, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    case .commitCredentialGarbageCollection(let request):
      try container.encode(Opcode.commitCredentialGarbageCollection, forKey: .opcode)
      var payload = container.nestedContainer(keyedBy: PayloadKeys.self, forKey: .payload)
      try payload.encode(request, forKey: .request)
    }
  }
}
