import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Security
import SystemConfiguration
import Testing

@testable import CFWProxyAgentCore

// Shared by the proxy preferences tests: operation and authorization
// recorders, the testing operations built on them, a prepared ownership
// journal and the effective proxies it applies.
final class PreferencesOperationRecorder: @unchecked Sendable {
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

final class AuthorizationOperationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var createCountValue = 0
  private var createPreferencesCountValue = 0
  private var freeFlagsValue: [AuthorizationFlags] = []
  private var interactionFlagsValue: [Bool] = []

  var interactionFlags: [Bool] { lock.withLock { interactionFlagsValue } }

  func recordRights(interactionAllowed: Bool) {
    lock.withLock { interactionFlagsValue.append(interactionAllowed) }
  }

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

func testingAuthorizationOperations(
  recorder: AuthorizationOperationRecorder,
  creationStatus: OSStatus = errAuthorizationSuccess,
  returnsReference: Bool = true,
  createsPreferences: Bool = true,
  releaseStatus: OSStatus = errAuthorizationSuccess,
  rightsStatus: OSStatus = errAuthorizationSuccess
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
    copyRights: { _, interactionAllowed in
      recorder.recordRights(interactionAllowed: interactionAllowed)
      return rightsStatus
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

func testingOperations(
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

func proxyJournal(
  originalProxyEnabled: Bool,
  originalValues: [SystemProxyField: ProxyPreferenceValue]? = nil,
  appliedPort: Int = 7_890,
  phase: ProxyOwnershipJournalPhase = .applied
) throws -> ProxyOwnershipJournal {
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
    .httpPort: .integer(appliedPort),
    .httpsEnabled: .integer(1),
    .httpsHost: .string("127.0.0.1"),
    .httpsPort: .integer(appliedPort),
    .socksEnabled: .integer(1),
    .socksHost: .string("127.0.0.1"),
    .socksPort: .integer(appliedPort),
    .proxyAutoConfigEnabled: .integer(0),
    .proxyAutoDiscoveryEnabled: .integer(0),
  ]
  let defaultOriginal: [SystemProxyField: ProxyPreferenceValue] =
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
  let original = originalValues ?? defaultOriginal
  let fields = try SystemProxyField.allCases.map { field in
    let appliedValue = try #require(applied[field])
    return OwnedSystemProxyField(
      field: field,
      originalValue: original[field],
      appliedValue: appliedValue
    )
  }
  return try ProxyOwnershipJournal(
    phase: phase,
    configuration: configuration,
    services: [try SystemProxyServiceOwnership(serviceID: "service-1", fields: fields)]
  )
}

func appliedEffectiveProxies() -> [String: Any] {
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
