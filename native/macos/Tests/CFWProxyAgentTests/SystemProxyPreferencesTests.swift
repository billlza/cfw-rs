import CFWSharedProtocol
import Foundation
import SystemConfiguration
import Testing

@testable import CFWProxyAgentCore

private final class PreferencesOperationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var commitCountValue = 0
  private var applyCountValue = 0
  private var applyResults: [Bool]

  init(applyResults: [Bool]) {
    self.applyResults = applyResults
  }

  var commitCount: Int {
    lock.withLock { commitCountValue }
  }

  var applyCount: Int {
    lock.withLock { applyCountValue }
  }

  func commit(_ preferences: SCPreferences) -> Bool {
    lock.withLock {
      commitCountValue += 1
      return true
    }
  }

  func apply(_ preferences: SCPreferences) -> Bool {
    lock.withLock {
      applyCountValue += 1
      guard !applyResults.isEmpty else {
        return true
      }
      return applyResults.removeFirst()
    }
  }
}

private func testingOperations(
  recorder: PreferencesOperationRecorder = PreferencesOperationRecorder(applyResults: []),
  effectiveProxies: [String: Any]? = [:],
  primaryServiceID: String? = "service-1"
) -> SCPreferencesOperations {
  SCPreferencesOperations(
    commitChanges: { recorder.commit($0) },
    applyChanges: { recorder.apply($0) },
    synchronize: { _ in },
    errorCode: { 987 },
    effectiveProxies: { effectiveProxies },
    primaryServiceID: { primaryServiceID }
  )
}

private func proxyJournal(originalProxyEnabled: Bool) throws -> ProxyOwnershipJournal {
  let installationID = try #require(
    UUID(uuidString: "33333333-3333-3333-3333-333333333333")
  )
  let configuration = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
  let applied: [SystemProxyField: ProxyPreferenceValue] = [
    .httpEnabled: .integer(1),
    .httpHost: .string("127.0.0.1"),
    .httpPort: .integer(7_890),
    .httpsEnabled: .integer(1),
    .httpsHost: .string("127.0.0.1"),
    .httpsPort: .integer(7_890),
    .socksEnabled: .integer(1),
    .socksHost: .string("127.0.0.1"),
    .socksPort: .integer(7_890),
    .proxyAutoConfigEnabled: .integer(0),
    .proxyAutoDiscoveryEnabled: .integer(0),
  ]
  let original: [SystemProxyField: ProxyPreferenceValue] =
    if originalProxyEnabled {
      [
        .httpEnabled: .integer(1),
        .httpHost: .string("10.0.0.1"),
        .httpPort: .integer(8_080),
        .httpsEnabled: .integer(1),
        .httpsHost: .string("10.0.0.1"),
        .httpsPort: .integer(8_080),
        .socksEnabled: .integer(1),
        .socksHost: .string("10.0.0.1"),
        .socksPort: .integer(8_080),
        .proxyAutoConfigEnabled: .integer(0),
        .proxyAutoDiscoveryEnabled: .integer(0),
      ]
    } else {
      [
        .httpEnabled: .integer(0),
        .httpsEnabled: .integer(0),
        .socksEnabled: .integer(0),
        .proxyAutoConfigEnabled: .integer(0),
        .proxyAutoDiscoveryEnabled: .integer(0),
      ]
    }
  let fields = try SystemProxyField.allCases.map { field in
    let appliedValue = try #require(applied[field])
    return OwnedSystemProxyField(
      field: field,
      originalValue: original[field],
      appliedValue: appliedValue
    )
  }
  return try ProxyOwnershipJournal(
    phase: .applied,
    configuration: configuration,
    services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)]
  )
}

private func appliedEffectiveProxies() -> [String: Any] {
  [
    "HTTPEnable": 1,
    "HTTPProxy": "127.0.0.1",
    "HTTPPort": 7_890,
    "HTTPSEnable": 1,
    "HTTPSProxy": "127.0.0.1",
    "HTTPSPort": 7_890,
    "SOCKSEnable": 1,
    "SOCKSProxy": "127.0.0.1",
    "SOCKSPort": 7_890,
    "ProxyAutoConfigEnable": 0,
    "ProxyAutoDiscoveryEnable": 0,
  ]
}

@Test func restoreRetriesApplyAfterCommitSucceededButApplyFailed() throws {
  let recorder = PreferencesOperationRecorder(applyResults: [false, true])
  let preferences = try #require(
    SCPreferencesCreate(nil, "CFW restore publication test" as CFString, nil)
  )
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(recorder: recorder)
  )

  #expect(throws: SystemProxyPreferencesError.applyFailed(987)) {
    try subject.publishRestoration(preferences, changed: true, conflicts: [])
  }
  #expect(
    try subject.publishRestoration(preferences, changed: false, conflicts: [])
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
