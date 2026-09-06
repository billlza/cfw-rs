import CFWSharedProtocol
import CoreFoundation
import Foundation
import Security
import SystemConfiguration

enum SystemProxyPreferencesError: Error, Equatable, Sendable {
  case authorizationCreationFailed(OSStatus)
  case authorizationReferenceUnavailable
  case authorizationReleaseFailed(code: OSStatus, originalError: String?)
  case preferencesUnavailable
  case preferencesLockFailed(Int32)
  case preferencesUnlockFailed(code: Int32, originalError: String?)
  case currentNetworkSetUnavailable
  case noEligibleNetworkServices
  case serviceMissing(String)
  case proxyProtocolMissing(String)
  case missingAppliedValue(SystemProxyField)
  case unsupportedValue(serviceID: String, field: SystemProxyField)
  case concurrentModification(serviceID: String, field: SystemProxyField)
  case setConfigurationFailed(serviceID: String, code: Int32)
  case commitFailed(Int32)
  case applyFailed(Int32)
  case verificationFailed(serviceID: String, field: SystemProxyField)
  case effectiveProxyStateUnavailable
  case effectiveVerificationFailed(field: SystemProxyField)
}

extension SystemProxyPreferencesError: LocalizedError {
  var errorDescription: String? {
    switch self {
    case .authorizationCreationFailed(let status):
      return "Creating the System Configuration authorization session failed with status \(status)."
    case .authorizationReferenceUnavailable:
      return "Authorization Services returned success without an authorization reference."
    case .authorizationReleaseFailed(let status, let originalError):
      let context = originalError.map { " Original error: \($0)" } ?? ""
      return
        "Releasing the System Configuration authorization failed with status \(status).\(context)"
    case .preferencesUnavailable:
      return "System proxy preferences are unavailable."
    case .preferencesLockFailed(let code):
      return "System proxy preferences lock failed with SystemConfiguration code \(code)."
    case .preferencesUnlockFailed(let code, let originalError):
      let context = originalError.map { " Original error: \($0)" } ?? ""
      return "System proxy preferences unlock failed with code \(code).\(context)"
    case .currentNetworkSetUnavailable:
      return "The current macOS network set is unavailable."
    case .noEligibleNetworkServices:
      return "No enabled network service exposes proxy preferences."
    case .serviceMissing(let serviceID):
      return "Network service \(serviceID) no longer exists."
    case .proxyProtocolMissing(let serviceID):
      return "Network service \(serviceID) no longer exposes proxy preferences."
    case .missingAppliedValue(let field):
      return "The product proxy value for \(field.rawValue) is missing."
    case .unsupportedValue(let serviceID, let field):
      return "Network service \(serviceID) has an unsupported \(field.rawValue) value."
    case .concurrentModification(let serviceID, let field):
      return "Network service \(serviceID) changed \(field.rawValue) during proxy activation."
    case .setConfigurationFailed(let serviceID, let code):
      return "Writing proxy preferences for \(serviceID) failed with code \(code)."
    case .commitFailed(let code):
      return "Committing system proxy preferences failed with code \(code)."
    case .applyFailed(let code):
      return "Applying system proxy preferences failed with code \(code)."
    case .verificationFailed(let serviceID, let field):
      return "Persisted proxy verification failed for \(serviceID) \(field.rawValue)."
    case .effectiveProxyStateUnavailable:
      return "The effective macOS proxy state is unavailable."
    case .effectiveVerificationFailed(let field):
      return "Effective proxy verification failed for \(field.rawValue)."
    }
  }
}

protocol SystemProxyPreferences: Sendable {
  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal

  func apply(_ journal: ProxyOwnershipJournal) throws
  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult
}

struct SCPreferencesOperations: @unchecked Sendable {
  let commitChanges: (SCPreferences) -> Bool
  let applyChanges: (SCPreferences) -> Bool
  let synchronize: (SCPreferences) -> Void
  let errorCode: () -> Int32
  let effectiveProxies: () -> [String: Any]?
  let primaryServiceID: () -> String?

  static let live = SCPreferencesOperations(
    commitChanges: { SCPreferencesCommitChanges($0) },
    applyChanges: { SCPreferencesApplyChanges($0) },
    synchronize: { SCPreferencesSynchronize($0) },
    errorCode: { SCError() },
    effectiveProxies: { SCDynamicStoreCopyProxies(nil) as? [String: Any] },
    primaryServiceID: {
      guard
        let store = SCDynamicStoreCreate(
          nil,
          "Clash for Mac ProxyAgent verification" as CFString,
          nil,
          nil
        )
      else {
        return nil
      }
      for key in ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] {
        guard
          let state = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
          let serviceID = state[kSCDynamicStorePropNetPrimaryService as String] as? String,
          !serviceID.isEmpty
        else {
          continue
        }
        return serviceID
      }
      return nil
    }
  )
}

/// Authorization Services is the public privilege boundary used by
/// `SCPreferencesCreateWithAuthorization`. The ProxyAgent is a per-user
/// `SMAppService.agent`, not the root Global Authority daemon, so each
/// preferences transaction owns a distinct authorization reference and
/// destroys any acquired rights when the transaction ends.
struct SCPreferencesAuthorizationOperations: @unchecked Sendable {
  let createAuthorization: () -> (status: OSStatus, reference: AuthorizationRef?)
  let createPreferences: (AuthorizationRef) -> SCPreferences?
  let freeAuthorization: (AuthorizationRef, AuthorizationFlags) -> OSStatus

  static let live = SCPreferencesAuthorizationOperations(
    createAuthorization: {
      var reference: AuthorizationRef?
      let status = AuthorizationCreate(nil, nil, [], &reference)
      return (status, reference)
    },
    createPreferences: { authorization in
      SCPreferencesCreateWithAuthorization(
        nil,
        "Clash for Mac ProxyAgent" as CFString,
        nil,
        authorization
      )
    },
    freeAuthorization: { AuthorizationFree($0, $1) }
  )
}

struct SCPreferencesSystemProxyPreferences: SystemProxyPreferences {
  private struct ServiceRecord {
    let serviceID: String
    let proxyProtocol: SCNetworkProtocol?
    let configuration: [String: Any]
  }

  private let operations: SCPreferencesOperations
  private let authorizationOperations: SCPreferencesAuthorizationOperations

  init(
    operations: SCPreferencesOperations = .live,
    authorizationOperations: SCPreferencesAuthorizationOperations = .live
  ) {
    self.operations = operations
    self.authorizationOperations = authorizationOperations
  }

  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal {
    let appliedValues = Self.appliedValues(endpoint: endpoint)
    return try withAuthorizedPreferences { preferences in
      let records = try loadServiceRecords(
        preferences: preferences,
        enabledOnly: true
      )
      guard !records.isEmpty else {
        throw SystemProxyPreferencesError.noEligibleNetworkServices
      }
      let services = try records.map { record in
        try SystemProxyServiceOwnership(
          serviceID: record.serviceID,
          fields: try SystemProxyField.allCases.map { field in
            guard let appliedValue = appliedValues[field] else {
              throw SystemProxyPreferencesError.missingAppliedValue(field)
            }
            return OwnedSystemProxyField(
              field: field,
              originalValue: try Self.value(
                record.configuration[field.rawValue],
                serviceID: record.serviceID,
                field: field
              ),
              appliedValue: appliedValue
            )
          }
        )
      }
      return try ProxyOwnershipJournal(
        phase: .prepared,
        configuration: configuration,
        services: services
      )
    }
  }

  func apply(_ journal: ProxyOwnershipJournal) throws {
    try withLockedPreferences { preferences in
      let records = try loadServiceRecords(
        preferences: preferences,
        enabledOnly: false
      )
      let recordsByID = Dictionary(uniqueKeysWithValues: records.map { ($0.serviceID, $0) })

      for service in journal.services {
        guard let record = recordsByID[service.serviceID] else {
          throw SystemProxyPreferencesError.serviceMissing(service.serviceID)
        }
        guard record.proxyProtocol != nil else {
          throw SystemProxyPreferencesError.proxyProtocolMissing(service.serviceID)
        }
        for ownedField in service.fields {
          let currentValue = try Self.value(
            record.configuration[ownedField.field.rawValue],
            serviceID: service.serviceID,
            field: ownedField.field
          )
          guard currentValue == ownedField.originalValue else {
            throw SystemProxyPreferencesError.concurrentModification(
              serviceID: service.serviceID,
              field: ownedField.field
            )
          }
        }
      }

      for service in journal.services {
        guard let record = recordsByID[service.serviceID] else {
          throw SystemProxyPreferencesError.serviceMissing(service.serviceID)
        }
        guard let proxyProtocol = record.proxyProtocol else {
          throw SystemProxyPreferencesError.proxyProtocolMissing(service.serviceID)
        }
        var updated = record.configuration
        for ownedField in service.fields {
          updated[ownedField.field.rawValue] = Self.foundationValue(ownedField.appliedValue)
        }
        guard SCNetworkProtocolSetConfiguration(proxyProtocol, updated as CFDictionary) else {
          throw SystemProxyPreferencesError.setConfigurationFailed(
            serviceID: service.serviceID,
            code: SCError()
          )
        }
      }

      try commitAndApply(preferences)
      operations.synchronize(preferences)
      let verificationRecords = try loadServiceRecords(
        preferences: preferences,
        enabledOnly: false
      )
      let verificationByID = Dictionary(
        uniqueKeysWithValues: verificationRecords.map { ($0.serviceID, $0) }
      )
      for service in journal.services {
        guard let record = verificationByID[service.serviceID] else {
          throw SystemProxyPreferencesError.serviceMissing(service.serviceID)
        }
        guard record.proxyProtocol != nil else {
          throw SystemProxyPreferencesError.proxyProtocolMissing(service.serviceID)
        }
        for ownedField in service.fields {
          let currentValue = try Self.value(
            record.configuration[ownedField.field.rawValue],
            serviceID: service.serviceID,
            field: ownedField.field
          )
          guard currentValue == ownedField.appliedValue else {
            throw SystemProxyPreferencesError.verificationFailed(
              serviceID: service.serviceID,
              field: ownedField.field
            )
          }
        }
      }
    }
    try verifyEffectiveAppliedValues(journal)
  }

  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult {
    let outcome: (result: ProxyRestoreResult, didPublish: Bool) = try withLockedPreferences {
      preferences in
      let records = try loadServiceRecords(
        preferences: preferences,
        enabledOnly: false
      )
      let recordsByID = Dictionary(uniqueKeysWithValues: records.map { ($0.serviceID, $0) })
      var conflicts: [ProxyOwnershipConflict] = []
      var restoredFields: [(String, OwnedSystemProxyField)] = []
      var changed = false

      for service in journal.services {
        guard let record = recordsByID[service.serviceID] else {
          conflicts.append(
            contentsOf: service.fields.map {
              ProxyOwnershipConflict(
                serviceID: service.serviceID,
                field: $0.field,
                reason: .serviceMissing
              )
            }
          )
          continue
        }
        guard let proxyProtocol = record.proxyProtocol else {
          conflicts.append(
            contentsOf: service.fields.map {
              ProxyOwnershipConflict(
                serviceID: service.serviceID,
                field: $0.field,
                reason: .proxyProtocolMissing
              )
            }
          )
          continue
        }
        var updated = record.configuration
        var serviceChanged = false
        for ownedField in service.fields {
          let currentValue = try Self.value(
            record.configuration[ownedField.field.rawValue],
            serviceID: service.serviceID,
            field: ownedField.field
          )
          if currentValue == ownedField.appliedValue {
            Self.set(ownedField.originalValue, field: ownedField.field, in: &updated)
            restoredFields.append((service.serviceID, ownedField))
            serviceChanged = true
          } else if currentValue == ownedField.originalValue {
            restoredFields.append((service.serviceID, ownedField))
          } else {
            conflicts.append(
              ProxyOwnershipConflict(
                serviceID: service.serviceID,
                field: ownedField.field,
                reason: .valueChanged(current: currentValue)
              )
            )
          }
        }
        if serviceChanged {
          guard SCNetworkProtocolSetConfiguration(proxyProtocol, updated as CFDictionary)
          else {
            throw SystemProxyPreferencesError.setConfigurationFailed(
              serviceID: service.serviceID,
              code: SCError()
            )
          }
          changed = true
        }
      }

      let didPublish = try publishRestoration(
        preferences,
        changed: changed,
        conflicts: conflicts
      )
      if didPublish {
        operations.synchronize(preferences)
        let verificationRecords = try loadServiceRecords(
          preferences: preferences,
          enabledOnly: false
        )
        let verificationByID = Dictionary(
          uniqueKeysWithValues: verificationRecords.map { ($0.serviceID, $0) }
        )
        for (serviceID, ownedField) in restoredFields {
          guard let record = verificationByID[serviceID] else {
            throw SystemProxyPreferencesError.serviceMissing(serviceID)
          }
          guard record.proxyProtocol != nil else {
            throw SystemProxyPreferencesError.proxyProtocolMissing(serviceID)
          }
          let currentValue = try Self.value(
            record.configuration[ownedField.field.rawValue],
            serviceID: serviceID,
            field: ownedField.field
          )
          guard currentValue == ownedField.originalValue else {
            throw SystemProxyPreferencesError.verificationFailed(
              serviceID: serviceID,
              field: ownedField.field
            )
          }
        }
      }

      return (
        ProxyRestoreResult(
          conflicts: conflicts.sorted {
            ($0.serviceID, $0.field) < ($1.serviceID, $1.field)
          }
        ),
        didPublish
      )
    }
    if outcome.didPublish, outcome.result.isComplete {
      try verifyEffectiveRestoredValues(journal)
    }
    return outcome.result
  }

  func withAuthorizedPreferences<T>(
    _ operation: (SCPreferences) throws -> T
  ) throws -> T {
    let creation = authorizationOperations.createAuthorization()
    guard creation.status == errAuthorizationSuccess else {
      throw SystemProxyPreferencesError.authorizationCreationFailed(creation.status)
    }
    guard let authorization = creation.reference else {
      throw SystemProxyPreferencesError.authorizationReferenceUnavailable
    }
    guard let preferences = authorizationOperations.createPreferences(authorization) else {
      let originalError = SystemProxyPreferencesError.preferencesUnavailable
      let releaseStatus = authorizationOperations.freeAuthorization(
        authorization,
        [.destroyRights]
      )
      guard releaseStatus == errAuthorizationSuccess else {
        throw SystemProxyPreferencesError.authorizationReleaseFailed(
          code: releaseStatus,
          originalError: String(describing: originalError)
        )
      }
      throw originalError
    }

    operations.synchronize(preferences)
    let operationResult: Result<T, Error>
    do {
      operationResult = .success(try operation(preferences))
    } catch {
      operationResult = .failure(error)
    }
    let releaseStatus = authorizationOperations.freeAuthorization(
      authorization,
      [.destroyRights]
    )
    switch operationResult {
    case .success(let result):
      guard releaseStatus == errAuthorizationSuccess else {
        throw SystemProxyPreferencesError.authorizationReleaseFailed(
          code: releaseStatus,
          originalError: nil
        )
      }
      return result
    case .failure(let originalError):
      guard releaseStatus == errAuthorizationSuccess else {
        throw SystemProxyPreferencesError.authorizationReleaseFailed(
          code: releaseStatus,
          originalError: String(describing: originalError)
        )
      }
      throw originalError
    }
  }

  private func withLockedPreferences<T>(
    _ operation: (SCPreferences) throws -> T
  ) throws -> T {
    try withAuthorizedPreferences { preferences in
      guard SCPreferencesLock(preferences, false) else {
        throw SystemProxyPreferencesError.preferencesLockFailed(SCError())
      }
      operations.synchronize(preferences)
      let operationResult: Result<T, Error>
      do {
        operationResult = .success(try operation(preferences))
      } catch {
        operationResult = .failure(error)
      }
      let didUnlock = SCPreferencesUnlock(preferences)
      switch operationResult {
      case .success(let result):
        guard didUnlock else {
          throw SystemProxyPreferencesError.preferencesUnlockFailed(
            code: SCError(),
            originalError: nil
          )
        }
        return result
      case .failure(let originalError):
        guard didUnlock else {
          throw SystemProxyPreferencesError.preferencesUnlockFailed(
            code: SCError(),
            originalError: String(describing: originalError)
          )
        }
        throw originalError
      }
    }
  }

  private func loadServiceRecords(
    preferences: SCPreferences,
    enabledOnly: Bool
  ) throws -> [ServiceRecord] {
    guard let networkSet = SCNetworkSetCopyCurrent(preferences) else {
      throw SystemProxyPreferencesError.currentNetworkSetUnavailable
    }
    let services = SCNetworkSetCopyServices(networkSet) as? [SCNetworkService] ?? []
    var records: [ServiceRecord] = []
    for service in services {
      if enabledOnly, !SCNetworkServiceGetEnabled(service) {
        continue
      }
      guard let serviceID = SCNetworkServiceGetServiceID(service) as String? else {
        continue
      }
      let proxyProtocol = SCNetworkServiceCopyProtocol(
        service,
        kSCNetworkProtocolTypeProxies
      )
      if enabledOnly, proxyProtocol == nil {
        continue
      }
      let configuration =
        proxyProtocol.flatMap { SCNetworkProtocolGetConfiguration($0) as? [String: Any] }
        ?? [:]
      records.append(
        ServiceRecord(
          serviceID: serviceID,
          proxyProtocol: proxyProtocol,
          configuration: configuration
        )
      )
    }
    return records.sorted { $0.serviceID < $1.serviceID }
  }

  private func commitAndApply(_ preferences: SCPreferences) throws {
    guard operations.commitChanges(preferences) else {
      throw SystemProxyPreferencesError.commitFailed(operations.errorCode())
    }
    try applyWithoutCommit(preferences)
  }

  func publishRestoration(
    _ preferences: SCPreferences,
    changed: Bool,
    conflicts: [ProxyOwnershipConflict]
  ) throws -> Bool {
    if changed {
      try commitAndApply(preferences)
      return true
    }
    guard conflicts.isEmpty else {
      return false
    }
    try applyWithoutCommit(preferences)
    return true
  }

  private func applyWithoutCommit(_ preferences: SCPreferences) throws {
    guard operations.applyChanges(preferences) else {
      throw SystemProxyPreferencesError.applyFailed(operations.errorCode())
    }
  }

  func verifyEffectiveAppliedValues(_ journal: ProxyOwnershipJournal) throws {
    guard let service = journal.services.first else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    try verifyEffectiveValues(
      service.fields.map { ($0.field, Optional($0.appliedValue)) }
    )
  }

  func verifyEffectiveRestoredValues(_ journal: ProxyOwnershipJournal) throws {
    guard let primaryServiceID = operations.primaryServiceID() else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    guard let service = journal.services.first(where: { $0.serviceID == primaryServiceID }) else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    try verifyEffectiveValues(
      service.fields.map { ($0.field, $0.originalValue) }
    )
  }

  func observeEffectiveAppliedValues(
    descriptor: ConfigurationDescriptor,
    journalStore: any ProxyOwnershipJournalStoring
  ) throws -> EffectiveSystemProxyObservation {
    guard let journal = try journalStore.load(),
      journal.phase == .applied,
      journal.configuration == descriptor
    else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    try verifyEffectiveAppliedValues(journal)
    return EffectiveSystemProxyObservation(
      httpApplied: true,
      httpsApplied: true,
      socksApplied: true)
  }

  private func verifyEffectiveValues(
    _ expectedValues: [(SystemProxyField, ProxyPreferenceValue?)]
  ) throws {
    guard let effectiveProxies = operations.effectiveProxies() else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    let expectedByField = Dictionary(uniqueKeysWithValues: expectedValues)
    for (field, expectedValue) in expectedValues {
      if let enableField = Self.controllingEnableField(for: field),
        !Self.isEffectivelyEnabled(expectedByField[enableField] ?? nil)
      {
        continue
      }
      let actualValue = try Self.value(
        effectiveProxies[field.rawValue],
        serviceID: "effective-primary-service",
        field: field
      )
      let matches =
        if field.isEnableFlag {
          Self.isEffectivelyEnabled(actualValue) == Self.isEffectivelyEnabled(expectedValue)
        } else {
          actualValue == expectedValue
        }
      guard matches else {
        throw SystemProxyPreferencesError.effectiveVerificationFailed(field: field)
      }
    }
  }

  private static func isEffectivelyEnabled(_ value: ProxyPreferenceValue?) -> Bool {
    switch value {
    case .boolean(let enabled):
      return enabled
    case .integer(let enabled):
      return enabled != 0
    case .none, .string:
      return false
    }
  }

  private static func controllingEnableField(
    for field: SystemProxyField
  ) -> SystemProxyField? {
    switch field {
    case .httpHost, .httpPort:
      return .httpEnabled
    case .httpsHost, .httpsPort:
      return .httpsEnabled
    case .socksHost, .socksPort:
      return .socksEnabled
    case .httpEnabled, .httpsEnabled, .socksEnabled, .proxyAutoConfigEnabled,
      .proxyAutoDiscoveryEnabled:
      return nil
    }
  }

  private static func appliedValues(
    endpoint: MixedListenerEndpoint
  ) -> [SystemProxyField: ProxyPreferenceValue] {
    [
      .httpEnabled: .integer(1),
      .httpHost: .string(endpoint.host),
      .httpPort: .integer(Int(endpoint.port)),
      .httpsEnabled: .integer(1),
      .httpsHost: .string(endpoint.host),
      .httpsPort: .integer(Int(endpoint.port)),
      .socksEnabled: .integer(1),
      .socksHost: .string(endpoint.host),
      .socksPort: .integer(Int(endpoint.port)),
      .proxyAutoConfigEnabled: .integer(0),
      .proxyAutoDiscoveryEnabled: .integer(0),
    ]
  }

  private static func value(
    _ value: Any?,
    serviceID: String,
    field: SystemProxyField
  ) throws -> ProxyPreferenceValue? {
    guard let value else {
      return nil
    }
    if let string = value as? String {
      return .string(string)
    }
    if let number = value as? NSNumber {
      if field.isEnableFlag {
        return .integer(number.boolValue ? 1 : 0)
      }
      if CFGetTypeID(number) == CFBooleanGetTypeID() {
        return .boolean(number.boolValue)
      }
      return .integer(number.intValue)
    }
    throw SystemProxyPreferencesError.unsupportedValue(
      serviceID: serviceID,
      field: field
    )
  }

  private static func foundationValue(_ value: ProxyPreferenceValue) -> Any {
    switch value {
    case .boolean(let value):
      NSNumber(value: value)
    case .integer(let value):
      NSNumber(value: value)
    case .string(let value):
      value
    }
  }

  private static func set(
    _ value: ProxyPreferenceValue?,
    field: SystemProxyField,
    in configuration: inout [String: Any]
  ) {
    if let value {
      configuration[field.rawValue] = foundationValue(value)
    } else {
      configuration.removeValue(forKey: field.rawValue)
    }
  }
}
