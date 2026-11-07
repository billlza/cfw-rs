import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Foundation

protocol PacketPumping: AnyObject {
  func takeEngineFileDescriptor() throws -> Int32
  func start() throws
  func stop()
}

extension PacketPump: PacketPumping {}

protocol EngineLeaseHolding: AnyObject {
  func release() throws
}

struct PreparedTunnelConfiguration {
  let descriptor: ConfigurationDescriptor
  let configuration: Data
  let lease: any EngineLeaseHolding
}

struct PacketTunnelSessionDependencies: @unchecked Sendable {
  let prepareConfiguration:
    (ConfigurationDescriptor, Data, CredentialMaterial) throws -> PreparedTunnelConfiguration
  let resolveConfiguration: (Data, ConfigurationDescriptor, CredentialMaterial) throws -> Data
  let makePump:
    (ConfigurationDescriptor, @escaping PacketPump.FailureHandler) throws -> any PacketPumping
  let applyNetworkSettings: (ConfigurationDescriptor, @escaping @Sendable (Error?) -> Void) -> Void
  let recordAcceptance: (ConfigurationDescriptor) throws -> Void

  init(
    prepareConfiguration:
      @escaping (ConfigurationDescriptor, Data, CredentialMaterial) throws
      -> PreparedTunnelConfiguration,
    resolveConfiguration:
      @escaping (Data, ConfigurationDescriptor, CredentialMaterial) throws -> Data = {
        configuration,
        _,
        _ in configuration
      },
    makePump:
      @escaping (
        ConfigurationDescriptor, @escaping PacketPump.FailureHandler
      ) throws -> any PacketPumping,
    applyNetworkSettings:
      @escaping (ConfigurationDescriptor, @escaping @Sendable (Error?) -> Void) -> Void,
    recordAcceptance: @escaping (ConfigurationDescriptor) throws -> Void = { _ in }
  ) {
    self.prepareConfiguration = prepareConfiguration
    self.resolveConfiguration = resolveConfiguration
    self.makePump = makePump
    self.applyNetworkSettings = applyNetworkSettings
    self.recordAcceptance = recordAcceptance
  }

}
