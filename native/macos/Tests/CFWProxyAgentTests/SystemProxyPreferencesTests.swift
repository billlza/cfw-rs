import CFWSharedProtocol
import Foundation
import Security
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

private final class AuthorizationOperationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var createCountValue = 0
  private var createPreferencesCountValue = 0
  private var freeFlagsValue: [AuthorizationFlags] = []

  var createCount: Int {
    lock.withLock { createCountValue }
  }

  var createPreferencesCount: Int {
    lock.withLock { createPreferencesCountValue }
  }

  var freeFlags: [AuthorizationFlags] {
    lock.withLock { freeFlagsValue }
  }

  func recordCreate() {
    lock.withLock { createCountValue += 1 }
  }

  func recordCreatePreferences() {
    lock.withLock { createPreferencesCountValue += 1 }
  }

  func recordFree(flags: AuthorizationFlags) {
    lock.withLock { freeFlagsValue.append(flags) }
  }
}

private func testingAuthorizationOperations(
  recorder: AuthorizationOperationRecorder,
  creationStatus: OSStatus = errAuthorizationSuccess,
  returnsReference: Bool = true,
  createsPreferences: Bool = true,
  releaseStatus: OSStatus = errAuthorizationSuccess
) -> SCPreferencesAuthorizationOperations {
  SCPreferencesAuthorizationOperations(
    createAuthorization: {
      recorder.recordCreate()
      guard creationStatus == errAuthorizationSuccess else {
        return (creationStatus, nil)
      }
      guard returnsReference else {
        return (errAuthorizationSuccess, nil)
      }
      var reference: AuthorizationRef?
      let status = AuthorizationCreate(nil, nil, [], &reference)
      return (status, reference)
    },
    createPreferences: { _ in
      recorder.recordCreatePreferences()
      guard createsPreferences else {
        return nil
      }
      return SCPreferencesCreate(
        nil,
        "CFW authorization lifecycle test" as CFString,
        nil
      )
    },
    freeAuthorization: { reference, flags in
      recorder.recordFree(flags: flags)
      let actualStatus = AuthorizationFree(reference, flags)
      guard actualStatus == errAuthorizationSuccess else {
        return actualStatus
      }
      return releaseStatus
    }
  )
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
    credentialAudience: CredentialAudience(
      profileID: installationID,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
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

@Test func authorizedPreferencesTransactionDestroysRightsAfterSuccess() throws {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(recorder: recorder)
  )

  let value = try subject.withAuthorizedPreferences { _ in 42 }

  #expect(value == 42)
  #expect(recorder.createCount == 1)
  #expect(recorder.createPreferencesCount == 1)
  #expect(recorder.freeFlags == [[.destroyRights]])
}

@Test func authorizedPreferencesTransactionDestroysRightsAfterOperationFailure() {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(recorder: recorder)
  )

  #expect(throws: SystemProxyPreferencesError.applyFailed(611)) {
    try subject.withAuthorizedPreferences { _ in
      throw SystemProxyPreferencesError.applyFailed(611)
    }
  }
  #expect(recorder.freeFlags == [[.destroyRights]])
}

@Test func authorizationCreationFailuresAreTypedAndDoNotCreatePreferences() {
  let denied: OSStatus = errAuthorizationDenied
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      creationStatus: denied
    )
  )

  #expect(throws: SystemProxyPreferencesError.authorizationCreationFailed(denied)) {
    try subject.withAuthorizedPreferences { _ in () }
  }
  #expect(recorder.createPreferencesCount == 0)
  #expect(recorder.freeFlags.isEmpty)
}

@Test func missingAuthorizationReferenceFailsClosed() {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      returnsReference: false
    )
  )

  #expect(throws: SystemProxyPreferencesError.authorizationReferenceUnavailable) {
    try subject.withAuthorizedPreferences { _ in () }
  }
  #expect(recorder.createPreferencesCount == 0)
  #expect(recorder.freeFlags.isEmpty)
}

@Test func unavailablePreferencesReleaseAuthorizationBeforeFailing() {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      createsPreferences: false
    )
  )

  #expect(throws: SystemProxyPreferencesError.preferencesUnavailable) {
    try subject.withAuthorizedPreferences { _ in () }
  }
  #expect(recorder.freeFlags == [[.destroyRights]])
}

@Test func authorizationReleaseFailurePreservesOriginalErrorContext() {
  let recorder = AuthorizationOperationRecorder()
  let releaseFailure: OSStatus = errAuthorizationInternal
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      releaseStatus: releaseFailure
    )
  )

  do {
    try subject.withAuthorizedPreferences { _ in
      throw SystemProxyPreferencesError.applyFailed(612)
    }
    Issue.record("Expected authorization release failure")
  } catch let error as SystemProxyPreferencesError {
    guard case .authorizationReleaseFailed(let code, let originalError) = error else {
      Issue.record("Expected typed authorization release failure, got \(error)")
      return
    }
    #expect(code == releaseFailure)
    #expect(originalError?.contains("applyFailed(612)") == true)
  } catch {
    Issue.record("Expected SystemProxyPreferencesError, got \(error)")
  }
  #expect(recorder.freeFlags == [[.destroyRights]])
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
