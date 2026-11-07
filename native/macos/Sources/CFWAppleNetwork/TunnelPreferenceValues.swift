import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension

extension NetworkExtensionHostBridge {
  static func managedPreferenceValues(
    _ manager: NETunnelProviderManager
  ) throws -> ManagedTunnelPreferenceValues {
    let hasOnDemandRules = manager.onDemandRules?.isEmpty == false
    guard !manager.isOnDemandEnabled, !hasOnDemandRules else {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel contains unauthorized on-demand settings."
      )
    }
    guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
      let providerBundleIdentifier = tunnelProtocol.providerBundleIdentifier,
      !providerBundleIdentifier.isEmpty
    else {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel protocol cannot be decoded completely."
      )
    }
    let protocolSettings = Self.protocolSettings(tunnelProtocol)
    guard protocolSettings.isDescriptorOnly else {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel contains unauthorized protocol fields."
      )
    }
    let descriptor: ConfigurationDescriptor
    do {
      descriptor = try manager.configurationDescriptor()
    } catch {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel descriptor cannot be decoded completely."
      )
    }
    return ManagedTunnelPreferenceValues(
      descriptor: descriptor,
      providerBundleIdentifier: providerBundleIdentifier,
      serverAddress: tunnelProtocol.serverAddress,
      isEnabled: manager.isEnabled,
      isOnDemandEnabled: manager.isOnDemandEnabled,
      hasOnDemandRules: hasOnDemandRules,
      localizedDescription: manager.localizedDescription,
      protocolSettings: protocolSettings
    )
  }

  static func applyDescriptorOnlyPreferences(
    _ values: ManagedTunnelPreferenceValues,
    to manager: NETunnelProviderManager
  ) throws {
    guard values.isDescriptorOnly else {
      throw AppleNetworkError.compensationConflict(
        "A managed tunnel receipt contains unauthorized manager or protocol settings."
      )
    }
    manager.protocolConfiguration = try Self.descriptorOnlyProtocol(for: values)
    manager.localizedDescription = values.localizedDescription
    manager.isEnabled = values.isEnabled
    manager.isOnDemandEnabled = false
    manager.onDemandRules = nil
  }

  static func descriptorOnlyProtocol(
    for values: ManagedTunnelPreferenceValues
  ) throws -> NETunnelProviderProtocol {
    guard values.isDescriptorOnly else {
      throw AppleNetworkError.compensationConflict(
        "A managed tunnel receipt contains unauthorized manager or protocol settings."
      )
    }
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = values.providerBundleIdentifier
    tunnelProtocol.serverAddress = values.serverAddress
    tunnelProtocol.providerConfiguration = try values.descriptor.providerConfiguration()
    tunnelProtocol.username = nil
    tunnelProtocol.passwordReference = nil
    tunnelProtocol.identityReference = nil
    tunnelProtocol.identityData = nil
    tunnelProtocol.identityDataPassword = nil
    tunnelProtocol.proxySettings = nil
    tunnelProtocol.disconnectOnSleep = false
    tunnelProtocol.includeAllNetworks = false
    tunnelProtocol.excludeLocalNetworks = false
    tunnelProtocol.excludeCellularServices = false
    tunnelProtocol.excludeAPNs = false
    tunnelProtocol.excludeDeviceCommunication = false
    tunnelProtocol.enforceRoutes = false
    return tunnelProtocol
  }

  static func protocolSettings(
    _ tunnelProtocol: NETunnelProviderProtocol
  ) -> ManagedTunnelProtocolSettings {
    ManagedTunnelProtocolSettings(
      usernamePresent: tunnelProtocol.username != nil,
      passwordReferencePresent: tunnelProtocol.passwordReference != nil,
      identityReferencePresent: tunnelProtocol.identityReference != nil,
      identityDataPresent: tunnelProtocol.identityData != nil,
      identityDataPasswordPresent: tunnelProtocol.identityDataPassword != nil,
      proxySettingsPresent: tunnelProtocol.proxySettings != nil,
      disconnectOnSleep: tunnelProtocol.disconnectOnSleep,
      includeAllNetworks: tunnelProtocol.includeAllNetworks,
      excludeLocalNetworks: tunnelProtocol.excludeLocalNetworks,
      excludeCellularServices: tunnelProtocol.excludeCellularServices,
      excludeAPNs: tunnelProtocol.excludeAPNs,
      excludeDeviceCommunication: tunnelProtocol.excludeDeviceCommunication,
      enforceRoutes: tunnelProtocol.enforceRoutes
    )
  }

}
