import CFWLibboxRuntime
import CFWPacketTransport
import CFWSharedProtocol
import Foundation

public enum PacketTunnelProviderError: Error, Equatable, Sendable {
  case providerUnavailable
  case globalAuthorityUnavailable
  case invalidStartTicket
  case expiredStartTicket
  case malformedProviderConfiguration
  case invalidConfigurationSlot
  case lifecycleConflict
  case startupCancelled
  case configuration(String)
  case engineCreation(String)
  case packetPumpSetup(String)
  case packetPump(PacketPumpError)
  case engineStart(String)
  /// libbox did not finish starting by the start deadline and was interrupted.
  case engineStartTimedOut
  case controllerEndpointConflict(port: UInt16)
  case mixedEndpointConflict(port: UInt16)
  /// libbox could not close the engine, so the extension is spent.
  case engineUnclosable(LibboxInstanceUnclosable)
  case networkSettings(String)
}

extension PacketTunnelProviderError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .providerUnavailable:
      return "Packet tunnel provider lifecycle is unavailable."
    case .globalAuthorityUnavailable:
      return GlobalAuthorityGateError.stableMessage
    case .invalidStartTicket:
      return "Packet tunnel start ticket is missing or invalid."
    case .expiredStartTicket:
      return TunnelStartupFailure.ticketExpired.message
    case .malformedProviderConfiguration:
      return "Packet tunnel provider configuration is malformed."
    case .invalidConfigurationSlot:
      return "Packet tunnel received a configuration for another engine slot."
    case .lifecycleConflict:
      return "Packet tunnel already owns a starting, active, or failed runtime."
    case .startupCancelled:
      return "Packet tunnel startup was cancelled."
    case .configuration:
      return "Packet tunnel configuration validation failed."
    case .engineCreation:
      return "Packet tunnel engine creation failed."
    case .packetPumpSetup:
      return "Packet pump setup failed."
    case .packetPump(let error):
      return "Packet pump failed: \(error)"
    case .engineStart:
      return "Packet tunnel engine start failed."
    case .engineStartTimedOut:
      return TunnelStartupFailure.engineStartTimedOut.message
    case .mixedEndpointConflict(let port):
      return "The Packet Tunnel mixed endpoint could not bind to port \(port)."
    case .controllerEndpointConflict(let port):
      return "The Packet Tunnel controller endpoint could not bind to port \(port)."
    case .engineUnclosable:
      return TunnelStartupFailure.engineUnclosable.message
    case .networkSettings:
      return "Packet tunnel network settings failed."
    }
  }
}

extension PacketTunnelProviderError {
  var engineFailure: EngineFailure {
    switch self {
    case .providerUnavailable:
      EngineFailure(
        .providerUnavailable, message: "Packet tunnel provider lifecycle is unavailable.")
    case .globalAuthorityUnavailable:
      EngineFailure(
        .globalAuthorityUnavailable, message: GlobalAuthorityGateError.stableMessage)
    case .invalidStartTicket:
      EngineFailure(
        .startTicketInvalid, message: "Packet tunnel start ticket is missing or invalid.")
    case .expiredStartTicket:
      TunnelStartupFailure.ticketExpired
    case .malformedProviderConfiguration:
      EngineFailure(
        .providerConfigurationMalformed,
        message: "Packet tunnel provider configuration is malformed.")
    case .invalidConfigurationSlot:
      EngineFailure(
        .configurationSlotInvalid,
        message: "Packet tunnel received a configuration for another engine slot.")
    case .lifecycleConflict:
      EngineFailure(
        .lifecycleConflict,
        message: "Packet tunnel already owns a starting, active, or failed runtime.")
    case .startupCancelled:
      EngineFailure(.startupCancelled, message: "Packet tunnel startup was cancelled.")
    case .configuration:
      EngineFailure(
        .configurationInvalid, message: "Packet tunnel configuration validation failed.")
    case .engineCreation:
      EngineFailure(.engineCreationFailed, message: "Packet tunnel engine creation failed.")
    case .packetPumpSetup:
      EngineFailure(
        .packetPumpSetupFailed, message: "Packet tunnel packet pump setup failed.")
    case .packetPump:
      EngineFailure(.packetPumpFailed, message: "Packet tunnel packet transport failed.")
    case .engineStart:
      EngineFailure(.engineStartFailed, message: "Packet tunnel engine startup failed.")
    case .engineStartTimedOut:
      TunnelStartupFailure.engineStartTimedOut
    case .mixedEndpointConflict(let port):
      EngineFailure(
        .mixedEndpointInUse,
        message: "The Packet Tunnel mixed endpoint could not bind to port \(port).")
    case .controllerEndpointConflict(let port):
      EngineFailure(
        .controllerEndpointInUse,
        message: "The Packet Tunnel controller endpoint could not bind to port \(port).")
    case .engineUnclosable:
      TunnelStartupFailure.engineUnclosable
    case .networkSettings:
      EngineFailure(.networkSettingsFailed, message: "Packet tunnel network settings failed.")
    }
  }
}
