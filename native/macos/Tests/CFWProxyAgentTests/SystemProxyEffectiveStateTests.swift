import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Security
import SystemConfiguration
import Testing

@testable import CFWProxyAgentCore

// The effective proxy state: waits until settings become visible, readback
// before ownership is released, and an applied state that must match the owned
// endpoint.
private final class DelayedEffectivePreferences: @unchecked Sendable {
  private let lock = NSLock()
  private var observations: [[String: Any]?]
  private var count = 0

  init(_ observations: [[String: Any]?]) { self.observations = observations }

  var readCount: Int { lock.withLock { count } }

  func read() -> [String: Any]? {
    lock.withLock {
      count += 1
      if observations.count > 1 { return observations.removeFirst() }
      return observations[0]
    }
  }

  var operations: SCPreferencesOperations {
    SCPreferencesOperations(
      commitChanges: { _ in
        Issue.record("Observation must not commit preferences")
        return false
      },
      applyChanges: { _ in
        Issue.record("Observation must not reapply preferences")
        return false
      },
      synchronize: { _ in }, errorCode: { 987 },
      effectiveProxies: { self.read() }, primaryServiceID: { "service-1" })
  }
}

@Test func effectiveActivationWaitsForCommittedSettingsToBecomeVisible() throws {
  var previous = appliedEffectiveProxies()
  previous["HTTPProxy"] = "localhost"
  let observations = DelayedEffectivePreferences([
    previous, previous, appliedEffectiveProxies(),
  ])
  let subject = SCPreferencesSystemProxyPreferences(operations: observations.operations)

  try subject.verifyEffectiveAppliedValues(proxyJournal(originalProxyEnabled: true))

  #expect(observations.readCount == 3)
}

@Test func effectiveRestorationWaitsForOriginalSettingsToBecomeVisible() throws {
  let observations = DelayedEffectivePreferences([
    appliedEffectiveProxies(), appliedEffectiveProxies(), [:],
  ])
  let subject = SCPreferencesSystemProxyPreferences(operations: observations.operations)

  try subject.verifyEffectiveRestoredValues(proxyJournal(originalProxyEnabled: false))

  #expect(observations.readCount == 3)
}

@Test func unavailableEffectiveProxyStateIsNotRetriedAsAValueMismatch() throws {
  let observations = DelayedEffectivePreferences([nil, appliedEffectiveProxies()])
  let subject = SCPreferencesSystemProxyPreferences(operations: observations.operations)
  #expect(throws: SystemProxyPreferencesError.effectiveProxyStateUnavailable) {
    try subject.verifyEffectiveAppliedValues(proxyJournal(originalProxyEnabled: false))
  }
  #expect(observations.readCount == 1)
}

@Test func malformedEffectiveProxyStateIsNotRetriedAsAValueMismatch() throws {
  var malformed = appliedEffectiveProxies()
  malformed["HTTPProxy"] = ["invalid-host"]
  let observations = DelayedEffectivePreferences([malformed, appliedEffectiveProxies()])
  let subject = SCPreferencesSystemProxyPreferences(operations: observations.operations)
  #expect(
    throws: SystemProxyPreferencesError.unsupportedValue(
      serviceID: "effective-primary-service", field: .httpHost)
  ) {
    try subject.verifyEffectiveAppliedValues(proxyJournal(originalProxyEnabled: false))
  }
  #expect(observations.readCount == 1)
}

private func inMemoryProxyPreferences(_ configuration: [String: Any]) throws -> SCPreferences {
  let preferences = try #require(
    SCPreferencesCreate(
      nil, "Restored proxy observation" as CFString,
      "cfm-restore-test-\(UUID().uuidString).plist" as CFString))
  // An in-memory SCPreferences session: no commit, system mutation or live
  // network interface is needed to exercise the real service enumeration.
  #expect(
    SCPreferencesSetValue(preferences, "CurrentSet" as CFString, "/Sets/test-set" as CFString))
  #expect(
    SCPreferencesSetValue(
      preferences, "Sets" as CFString,
      [
        "test-set": [
          "Network": ["Service": ["service-1": ["__LINK__": "/NetworkServices/service-1"]]]
        ]
      ] as CFDictionary))
  #expect(
    SCPreferencesSetValue(
      preferences, "NetworkServices" as CFString,
      [
        "service-1": [
          "Interface": ["Type": "Ethernet", "DeviceName": "en0", "Hardware": "Ethernet"],
          "Proxies": configuration,
        ]
      ] as CFDictionary))
  return preferences
}

@Test(arguments: [true, false])
func restorationSkipsAuthorizationOnlyWhenStoredAndEffectiveValuesAreRestored(
  effectiveRestored: Bool
) throws {
  let recorder = AuthorizationOperationRecorder()
  let writes = PreferencesOperationRecorder(applyResults: [])
  let preferences = try inMemoryProxyPreferences([
    "HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0,
    "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0,
  ])
  let base = testingAuthorizationOperations(
    recorder: recorder, rightsStatus: errAuthorizationInteractionNotAllowed)
  let authorization = SCPreferencesAuthorizationOperations(
    createAuthorization: base.createAuthorization,
    copyRights: base.copyRights,
    createPreferences: { _ in preferences },
    freeAuthorization: base.freeAuthorization)
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(
      recorder: writes, effectiveProxies: effectiveRestored ? [:] : appliedEffectiveProxies()),
    authorizationOperations: authorization)

  if effectiveRestored {
    let result = try subject.restore(proxyJournal(originalProxyEnabled: false))
    #expect(result.isComplete)
    #expect(recorder.interactionFlags.isEmpty)
  } else {
    #expect(
      throws: SystemProxyPreferencesError.authorizationDenied(errAuthorizationInteractionNotAllowed)
    ) {
      try subject.restore(proxyJournal(originalProxyEnabled: false))
    }
    #expect(recorder.interactionFlags == [false])
  }
  #expect(writes.commitCount == 0)
  #expect(writes.applyCount == 0)
}

@Test(arguments: [true, false], [true, false])
func externallyReplacedProxyReleasesOwnershipOnlyAfterEffectiveReadback(
  enabled: Bool, effectiveMatches: Bool
) throws {
  var replacement = appliedEffectiveProxies()
  for prefix in ["HTTP", "HTTPS", "SOCKS"] {
    replacement[prefix + "Enable"] = enabled ? 1 : 0
    replacement[prefix + "Port"] = enabled ? 19_090 : 7_890
  }
  let preferences = try inMemoryProxyPreferences(replacement)
  let recorder = AuthorizationOperationRecorder()
  let writes = PreferencesOperationRecorder(applyResults: [])
  let base = testingAuthorizationOperations(
    recorder: recorder, rightsStatus: errAuthorizationInteractionNotAllowed)
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(
      recorder: writes, effectiveProxies: effectiveMatches ? replacement : appliedEffectiveProxies()
    ),
    authorizationOperations: SCPreferencesAuthorizationOperations(
      createAuthorization: base.createAuthorization, copyRights: base.copyRights,
      createPreferences: { _ in preferences }, freeAuthorization: base.freeAuthorization))

  if effectiveMatches {
    let result = try subject.restore(proxyJournal(originalProxyEnabled: false))
    #expect(result.isComplete)
    #expect(result.conflicts.isEmpty)
    let fields = Set(result.preservedExternalChanges.map(\.field))
    #expect(
      fields
        == (enabled
          ? [.httpPort, .httpsPort, .socksPort]
          : [.httpEnabled, .httpsEnabled, .socksEnabled]))
    #expect(result.preservedExternalChanges.count == 3)
    #expect(recorder.interactionFlags.isEmpty)
  } else {
    #expect(
      throws: SystemProxyPreferencesError.authorizationDenied(errAuthorizationInteractionNotAllowed)
    ) {
      try subject.restore(proxyJournal(originalProxyEnabled: false))
    }
    #expect(recorder.interactionFlags == [false])
  }
  #expect(writes.commitCount == 0)
  #expect(writes.applyCount == 0)
  let services = try #require(
    SCPreferencesGetValue(preferences, "NetworkServices" as CFString) as? [String: [String: Any]])
  let retained = try #require(services["service-1"]?["Proxies"] as? [String: Any])
  #expect(NSDictionary(dictionary: retained).isEqual(to: replacement))
}

@Test(arguments: [7_890, 0, 65_536])
func changedHostnameOrInvalidPortCannotReleaseAnEnabledProxy(port: Int) throws {
  var unresolved = appliedEffectiveProxies()
  for prefix in ["HTTP", "HTTPS", "SOCKS"] {
    unresolved[prefix + "Proxy"] = "localhost"
    unresolved[prefix + "Port"] = port
  }
  let preferences = try inMemoryProxyPreferences(unresolved)
  let recorder = AuthorizationOperationRecorder()
  let writes = PreferencesOperationRecorder(applyResults: [])
  let base = testingAuthorizationOperations(
    recorder: recorder, rightsStatus: errAuthorizationInteractionNotAllowed)
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(recorder: writes, effectiveProxies: unresolved),
    authorizationOperations: SCPreferencesAuthorizationOperations(
      createAuthorization: base.createAuthorization, copyRights: base.copyRights,
      createPreferences: { _ in preferences }, freeAuthorization: base.freeAuthorization))
  #expect(
    throws: SystemProxyPreferencesError.authorizationDenied(errAuthorizationInteractionNotAllowed)
  ) {
    try subject.restore(proxyJournal(originalProxyEnabled: false))
  }
  #expect(recorder.interactionFlags == [false])
  #expect(writes.commitCount == 0)
  #expect(writes.applyCount == 0)
}

@Test func effectiveAppliedProxyStateMustMatchOwnedEndpoint() throws {
  let journal = try proxyJournal(originalProxyEnabled: false)
  let matching = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(effectiveProxies: appliedEffectiveProxies())
  )
  try matching.verifyEffectiveAppliedValues(journal)

  var mismatchedProxies = appliedEffectiveProxies()
  mismatchedProxies["HTTPEnable"] = 0
  let mismatching = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(effectiveProxies: mismatchedProxies)
  )
  #expect(
    throws: SystemProxyPreferencesError.effectiveVerificationFailed(
      field: .httpEnabled
    )
  ) {
    try mismatching.verifyEffectiveAppliedValues(journal)
  }
}

@Test func effectiveRestoreTreatsDisabledProxyEndpointsAsInactive() throws {
  let journal = try proxyJournal(originalProxyEnabled: false)
  let effective: [String: Any] = [
    "HTTPEnable": 0,
    "HTTPProxy": "stale-but-disabled",
    "HTTPPort": 65_535,
    "HTTPSEnable": 0,
    "HTTPSProxy": "stale-but-disabled",
    "HTTPSPort": 65_535,
    "SOCKSEnable": 0,
    "SOCKSProxy": "stale-but-disabled",
    "SOCKSPort": 65_535,
    "ProxyAutoConfigEnable": 0,
    "ProxyAutoDiscoveryEnable": 0,
  ]
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(effectiveProxies: effective)
  )

  try subject.verifyEffectiveRestoredValues(journal)
}
