import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Security
import SystemConfiguration
import Testing

@testable import CFWProxyAgentCore

// Restoring the original proxy settings: retries after a failed apply, whole
// proxy groups and their enable flags, and values another app changed.
@Test func restoreRetriesApplyAfterCommitSucceededButApplyFailed() throws {
  let recorder = PreferencesOperationRecorder(applyResults: [false, true])
  let preferences = try #require(
    SCPreferencesCreate(nil, "CFW restore publication test" as CFString, nil)
  )
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(recorder: recorder),
    authorizationOperations: testingAuthorizationOperations(
      recorder: AuthorizationOperationRecorder())
  )
  let journal = try proxyJournal(originalProxyEnabled: false)
  let service = try #require(journal.services.first)
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: appliedEffectiveProxies())
  #expect(restoration.changed)
  #expect(restoration.conflicts.isEmpty)

  #expect(throws: SystemProxyPreferencesError.applyFailed(987)) {
    try subject.publishRestoration(
      preferences, changed: restoration.changed, conflicts: restoration.conflicts)
  }
  let retry = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: restoration.configuration)
  #expect(!retry.changed)
  #expect(retry.conflicts.isEmpty)
  #expect(
    try subject.publishRestoration(preferences, changed: retry.changed, conflicts: retry.conflicts)
  )
  #expect(recorder.commitCount == 1)
  #expect(recorder.applyCount == 2)
}

@Test func incompleteRestoreDoesNotRepublishUnrelatedPreferences() throws {
  let recorder = PreferencesOperationRecorder(applyResults: [])
  let preferences = try #require(
    SCPreferencesCreate(nil, "CFW incomplete restoration test" as CFString, nil)
  )
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(recorder: recorder)
  )
  let conflict = ProxyOwnershipConflict(
    serviceID: "service-1",
    field: .httpHost,
    reason: .valueChanged(current: .string("external"))
  )

  #expect(
    try !subject.publishRestoration(
      preferences,
      changed: false,
      conflicts: [conflict]
    )
  )
  #expect(recorder.commitCount == 0)
  #expect(recorder.applyCount == 0)
}

@Test(arguments: SystemProxyField.allCases.filter(\.isEnableFlag))
func explicitProxyActivationCanTakeOverValidExistingSettings(field: SystemProxyField) throws {
  for value: Any in [true, false, 0, 1] {
    try SCPreferencesSystemProxyPreferences.validateProxyEnableFlags(
      [field.rawValue: value], serviceID: "previous-proxy-service")
  }
}

@Test func disabledProxyEndpointsDoNotBlockNewOwnership() throws {
  try SCPreferencesSystemProxyPreferences.validateProxyEnableFlags(
    [
      "HTTPEnable": 0,
      "HTTPProxy": "127.0.0.1",
      "HTTPPort": 7_890,
      "HTTPSEnable": false,
      "HTTPSProxy": "old-proxy.invalid",
      "SOCKSEnable": 0,
      "ProxyAutoConfigEnable": 0,
      "ProxyAutoConfigURLString": "https://old-proxy.invalid/proxy.pac",
      "ProxyAutoDiscoveryEnable": 0,
    ],
    serviceID: "inactive-service")
  try SCPreferencesSystemProxyPreferences.validateProxyEnableFlags(
    [:], serviceID: "unconfigured-service")
}

@Test(arguments: [-1, 2, 255])
func numericEnableFlagsKeepSystemConfigurationBooleanSemantics(value: Int) throws {
  try SCPreferencesSystemProxyPreferences.validateProxyEnableFlags(
    ["HTTPEnable": value], serviceID: "previous-proxy-service")
}

@Test(arguments: ["1", "false", ""])
func malformedProxyEnableFlagsAreNotTreatedAsInactive(value: String) {
  #expect(
    throws: SystemProxyPreferencesError.unsupportedValue(
      serviceID: "malformed-service", field: .httpEnabled)
  ) {
    try SCPreferencesSystemProxyPreferences.validateProxyEnableFlags(
      ["HTTPEnable": value], serviceID: "malformed-service")
  }
}

@Test func preparedJournalDoesNotDisableProxyEnabledByAnotherApp() throws {
  let journal = try proxyJournal(
    originalProxyEnabled: false,
    originalValues: [
      .httpEnabled: .integer(0), .httpHost: .string("127.0.0.1"), .httpPort: .integer(7_890),
      .httpsEnabled: .integer(0), .httpsHost: .string("127.0.0.1"), .httpsPort: .integer(7_890),
      .socksEnabled: .integer(0), .socksHost: .string("127.0.0.1"), .socksPort: .integer(7_890),
      .proxyAutoConfigEnabled: .integer(0), .proxyAutoDiscoveryEnabled: .integer(0),
    ],
    appliedPort: 17_890,
    phase: .prepared)
  let service = try #require(journal.services.first)
  let foreignConfiguration = appliedEffectiveProxies()

  try SCPreferencesSystemProxyPreferences.validateProxyEnableFlags(
    foreignConfiguration, serviceID: service.serviceID)
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: foreignConfiguration)

  #expect(!restoration.changed)
  #expect(NSDictionary(dictionary: restoration.configuration).isEqual(to: foreignConfiguration))
  #expect(Set(restoration.conflicts.map(\.field)) == [.httpPort, .httpsPort, .socksPort])
  #expect(
    Set(restoration.restoredFields.map(\.field))
      == [.proxyAutoConfigEnabled, .proxyAutoDiscoveryEnabled])
}

@Test(arguments: [false, true])
func fullyOwnedProxyGroupsRestoreOriginalEndpoints(originalProxyEnabled: Bool) throws {
  let journal = try proxyJournal(originalProxyEnabled: originalProxyEnabled)
  let service = try #require(journal.services.first)
  var configuration = appliedEffectiveProxies()
  configuration["ExceptionsList"] = ["localhost", "*.local"]
  configuration["ProxyAutoConfigURLString"] = "https://retained.invalid/proxy.pac"

  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: configuration)

  #expect(restoration.changed)
  #expect(restoration.conflicts.isEmpty)
  #expect(Set(restoration.restoredFields.map(\.field)) == Set(SystemProxyField.allCases))
  for prefix in ["HTTP", "HTTPS", "SOCKS"] {
    #expect(restoration.configuration[prefix + "Enable"] as? Int == (originalProxyEnabled ? 1 : 0))
    #expect(
      restoration.configuration[prefix + "Proxy"] as? String
        == (originalProxyEnabled ? "10.0.0.1" : nil))
    #expect(
      restoration.configuration[prefix + "Port"] as? Int
        == (originalProxyEnabled ? 8_080 : nil))
  }
  #expect(restoration.configuration["ExceptionsList"] as? [String] == ["localhost", "*.local"])
  #expect(
    restoration.configuration["ProxyAutoConfigURLString"] as? String
      == "https://retained.invalid/proxy.pac")

  let repeated = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: restoration.configuration)
  #expect(!repeated.changed)
  #expect(repeated.conflicts.isEmpty)
  #expect(
    NSDictionary(dictionary: repeated.configuration).isEqual(to: restoration.configuration))
}

@Test func absentOriginalProxyFieldsAreRemovedTogether() throws {
  let journal = try proxyJournal(originalProxyEnabled: false, originalValues: [:])
  let service = try #require(journal.services.first)
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: appliedEffectiveProxies())

  #expect(restoration.changed)
  #expect(restoration.configuration.isEmpty)
  #expect(restoration.conflicts.isEmpty)
  #expect(restoration.restoredFields.count == SystemProxyField.allCases.count)
  let repeated = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: restoration.configuration)
  #expect(!repeated.changed)
  #expect(repeated.conflicts.isEmpty)
}

@Test func originalBooleanEnableFlagsRemainValidDuringRecovery() throws {
  let journal = try proxyJournal(
    originalProxyEnabled: false,
    originalValues: [
      .httpEnabled: .boolean(false), .httpsEnabled: .boolean(false),
      .socksEnabled: .boolean(false), .proxyAutoConfigEnabled: .boolean(false),
      .proxyAutoDiscoveryEnabled: .boolean(false),
    ])
  let service = try #require(journal.services.first)
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: appliedEffectiveProxies())
  #expect(restoration.changed)
  #expect(restoration.conflicts.isEmpty)
  #expect(restoration.configuration["HTTPEnable"] as? Bool == false)

  let repeated = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: restoration.configuration)
  #expect(!repeated.changed)
  #expect(repeated.conflicts.isEmpty)
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(effectiveProxies: restoration.configuration))
  try subject.verifyEffectiveRestoredValues(journal)
}

@Test(arguments: [SystemProxyField.httpPort, .httpsPort, .socksPort])
func externalEndpointChangePreservesItsWholeProxyGroup(portField: SystemProxyField) throws {
  let journal = try proxyJournal(originalProxyEnabled: false)
  let service = try #require(journal.services.first)
  var configuration = appliedEffectiveProxies()
  configuration[portField.rawValue] = 19_090

  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: configuration)
  #expect(restoration.changed)
  #expect(
    restoration.conflicts == [
      ProxyOwnershipConflict(
        serviceID: service.serviceID, field: portField,
        reason: .valueChanged(current: .integer(19_090)))
    ])
  let prefix = String(portField.rawValue.dropLast("Port".count))
  #expect(restoration.configuration[prefix + "Enable"] as? Int == 1)
  #expect(restoration.configuration[prefix + "Proxy"] as? String == "127.0.0.1")
  #expect(restoration.configuration[portField.rawValue] as? Int == 19_090)
  #expect(restoration.restoredFields.count == SystemProxyField.allCases.count - 3)
  for otherPrefix in ["HTTP", "HTTPS", "SOCKS"] where otherPrefix != prefix {
    #expect(restoration.configuration[otherPrefix + "Enable"] as? Int == 0)
    #expect(restoration.configuration[otherPrefix + "Proxy"] == nil)
    #expect(restoration.configuration[otherPrefix + "Port"] == nil)
  }
}

@Test func partiallyAppliedProtocolsRecoverOnlyCompleteOwnershipGroups() throws {
  let journal = try proxyJournal(originalProxyEnabled: false, phase: .prepared)
  let service = try #require(journal.services.first)
  let partialConfiguration: [String: Any] = [
    "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 7_890,
    "HTTPSEnable": 0, "SOCKSEnable": 0,
    "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0,
  ]
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: partialConfiguration)
  #expect(restoration.changed)
  #expect(restoration.conflicts.isEmpty)
  #expect(restoration.restoredFields.count == SystemProxyField.allCases.count)
  #expect(restoration.configuration["HTTPEnable"] as? Int == 0)
  #expect(restoration.configuration["HTTPProxy"] == nil)
  #expect(restoration.configuration["HTTPPort"] == nil)
}

@Test func mixedValuesWithinOneProtocolArePreservedAsAConflict() throws {
  let journal = try proxyJournal(originalProxyEnabled: false, phase: .prepared)
  let service = try #require(journal.services.first)
  let mixedConfiguration: [String: Any] = [
    "HTTPEnable": 1, "HTTPProxy": "127.0.0.1",
    "HTTPSEnable": 0, "SOCKSEnable": 0,
    "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0,
  ]
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: mixedConfiguration)
  #expect(!restoration.changed)
  #expect(NSDictionary(dictionary: restoration.configuration).isEqual(to: mixedConfiguration))
  #expect(
    restoration.conflicts == [
      ProxyOwnershipConflict(
        serviceID: service.serviceID, field: .httpPort, reason: .valueChanged(current: nil))
    ])
}

@Test func malformedRestorationValuesFailBeforeReturningChanges() throws {
  let journal = try proxyJournal(originalProxyEnabled: false)
  let service = try #require(journal.services.first)
  let malformedValues: [(SystemProxyField, Any)] = [
    (.httpEnabled, "1"), (.httpPort, "7890"), (.httpHost, 42),
    (.socksPort, [1, 2]),
  ]
  for (field, value) in malformedValues {
    var configuration = appliedEffectiveProxies()
    configuration[field.rawValue] = value
    #expect(
      throws: SystemProxyPreferencesError.unsupportedValue(
        serviceID: service.serviceID, field: field)
    ) {
      try SCPreferencesSystemProxyPreferences.restoration(
        for: service, configuration: configuration)
    }
  }
}

@Test func externalAutomaticProxyFlagsAndURLArePreserved() throws {
  let journal = try proxyJournal(originalProxyEnabled: false)
  let service = try #require(journal.services.first)
  let configuration: [String: Any] = [
    "HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0,
    "ProxyAutoConfigEnable": 1, "ProxyAutoDiscoveryEnable": 1,
    "ProxyAutoConfigURLString": "https://external.invalid/proxy.pac",
  ]
  let restoration = try SCPreferencesSystemProxyPreferences.restoration(
    for: service, configuration: configuration)
  #expect(!restoration.changed)
  #expect(NSDictionary(dictionary: restoration.configuration).isEqual(to: configuration))
  #expect(
    Set(restoration.conflicts.map(\.field))
      == [.proxyAutoConfigEnabled, .proxyAutoDiscoveryEnabled])
}
