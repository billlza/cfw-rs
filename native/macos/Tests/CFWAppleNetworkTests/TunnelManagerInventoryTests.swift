import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

private func inventoryDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(
      ipv6Enabled: true,
      bypassPrivateNetworks: true,
      mtu: 1_500
    ),
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
    epoch: 1,
    generation: 2,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

private func inventoryValues() throws -> ManagedTunnelPreferenceValues {
  ManagedTunnelPreferenceValues(
    descriptor: try inventoryDescriptor(),
    providerBundleIdentifier: "com.bill.clashformac.packet-tunnel",
    serverAddress: "Clash for Mac",
    isEnabled: true,
    localizedDescription: "Clash for Mac Tunnel"
  )
}

private func inventoryManager() throws -> NETunnelProviderManager {
  let manager = NETunnelProviderManager()
  manager.protocolConfiguration = try NetworkExtensionHostBridge.descriptorOnlyProtocol(
    for: inventoryValues()
  )
  manager.localizedDescription = "Clash for Mac Tunnel"
  manager.isEnabled = true
  return manager
}

@Test func callingApplicationInventoryClassifiesZeroOneAndEveryDuplicate() throws {
  #expect(try NetworkExtensionHostBridge.classifyManagerInventory([]) == nil)

  let sole = NETunnelProviderManager()
  #expect(
    try NetworkExtensionHostBridge.classifyManagerInventory([sole]) === sole
  )

  let changedProvider = NETunnelProviderManager()
  let changedProtocol = NETunnelProviderProtocol()
  changedProtocol.providerBundleIdentifier = "example.external-provider"
  changedProvider.protocolConfiguration = changedProtocol
  #expect(throws: AppleNetworkError.duplicateTunnelManagers(2)) {
    _ = try NetworkExtensionHostBridge.classifyManagerInventory([sole, changedProvider])
  }
}

@Test func freshDescriptorProtocolClearsEveryUnauthorizedInheritedField() throws {
  let values = try inventoryValues()
  let fresh = try NetworkExtensionHostBridge.descriptorOnlyProtocol(for: values)
  #expect(NetworkExtensionHostBridge.protocolSettings(fresh).isDescriptorOnly)
  #expect(fresh.providerBundleIdentifier == values.providerBundleIdentifier)
  #expect(fresh.serverAddress == values.serverAddress)

  let legacy = NETunnelProviderProtocol()
  legacy.username = "legacy-user"
  legacy.passwordReference = Data([1])
  legacy.identityReference = Data([2])
  legacy.identityData = Data([3])
  legacy.identityDataPassword = "legacy-password"
  legacy.proxySettings = NEProxySettings()
  legacy.disconnectOnSleep = true
  legacy.includeAllNetworks = true
  legacy.excludeLocalNetworks = true
  legacy.excludeCellularServices = true
  legacy.excludeAPNs = true
  legacy.excludeDeviceCommunication = true
  legacy.enforceRoutes = true
  let settings = NetworkExtensionHostBridge.protocolSettings(legacy)
  #expect(!settings.isDescriptorOnly)
  #expect(settings.usernamePresent)
  #expect(settings.passwordReferencePresent)
  #expect(settings.identityReferencePresent)
  #expect(settings.identityDataPresent)
  #expect(settings.identityDataPasswordPresent)
  #expect(settings.proxySettingsPresent)
  #expect(settings.disconnectOnSleep)
  #expect(settings.includeAllNetworks)
  #expect(settings.excludeLocalNetworks)
  #expect(settings.excludeCellularServices)
  #expect(settings.excludeAPNs)
  #expect(settings.excludeDeviceCommunication)
  #expect(settings.enforceRoutes)
}

@Test func inheritedEnabledOnDemandManagerIsRejectedBeforeSnapshot() throws {
  let manager = try inventoryManager()
  manager.isOnDemandEnabled = true

  #expect(throws: AppleNetworkError.self) {
    _ = try NetworkExtensionHostBridge.managedPreferenceValues(manager)
  }
}

@Test func inheritedNonEmptyOnDemandRulesAreRejectedBeforeSnapshot() throws {
  let manager = try inventoryManager()
  manager.onDemandRules = [NEOnDemandRuleConnect()]

  #expect(throws: AppleNetworkError.self) {
    _ = try NetworkExtensionHostBridge.managedPreferenceValues(manager)
  }
}

@Test func emptyOnDemandRulesAreAcceptedAndNormalizedAsDescriptorOnly() throws {
  let manager = try inventoryManager()
  manager.onDemandRules = []

  let values = try NetworkExtensionHostBridge.managedPreferenceValues(manager)
  #expect(!values.isOnDemandEnabled)
  #expect(!values.hasOnDemandRules)
  #expect(values.isDescriptorOnly)
}

@Test func descriptorOnlyWriteExplicitlyClearsManagerOnDemandState() throws {
  let manager = try inventoryManager()
  manager.isOnDemandEnabled = true
  manager.onDemandRules = [NEOnDemandRuleConnect()]
  let expected = try inventoryValues()

  try NetworkExtensionHostBridge.applyDescriptorOnlyPreferences(expected, to: manager)

  #expect(!manager.isOnDemandEnabled)
  #expect(manager.onDemandRules == nil)
  #expect(try NetworkExtensionHostBridge.managedPreferenceValues(manager) == expected)
}

@Test func existingMalformedOrUnauthorizedManagerIsConflictNeverAbsence() throws {
  let malformed = NETunnelProviderManager()
  #expect(throws: AppleNetworkError.self) {
    _ = try NetworkExtensionHostBridge.managedPreferenceValues(malformed)
  }

  let unauthorized = NETunnelProviderManager()
  let unauthorizedProtocol = try NetworkExtensionHostBridge.descriptorOnlyProtocol(
    for: inventoryValues()
  )
  unauthorizedProtocol.passwordReference = Data([1])
  unauthorized.protocolConfiguration = unauthorizedProtocol
  unauthorized.isEnabled = true
  #expect(throws: AppleNetworkError.self) {
    _ = try NetworkExtensionHostBridge.managedPreferenceValues(unauthorized)
  }

  let changedProvider = NETunnelProviderManager()
  let changedProtocol = try NetworkExtensionHostBridge.descriptorOnlyProtocol(
    for: inventoryValues()
  )
  changedProtocol.providerBundleIdentifier = "example.external-provider"
  changedProvider.protocolConfiguration = changedProtocol
  changedProvider.isEnabled = true
  let changed = try NetworkExtensionHostBridge.managedPreferenceValues(changedProvider)
  let expected = try inventoryValues()
  #expect(changed.providerBundleIdentifier == "example.external-provider")
  #expect(changed != expected)
}
