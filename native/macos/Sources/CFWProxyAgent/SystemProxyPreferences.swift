import CFWSharedProtocol
import CoreFoundation
import Foundation
import Security
import SystemConfiguration

protocol SystemProxyPreferences: Sendable {
  func requireAuthorization() throws
  func prepareOwnership(
    configuration: ConfigurationDescriptor,
    endpoint: MixedListenerEndpoint
  ) throws -> ProxyOwnershipJournal

  func apply(_ journal: ProxyOwnershipJournal) throws
  func restore(_ journal: ProxyOwnershipJournal) throws -> ProxyRestoreResult
}

struct SCPreferencesSystemProxyPreferences: SystemProxyPreferences {
  struct ServiceRestoration {
    let configuration: [String: Any]
    let restoredFields: [OwnedSystemProxyField]
    let conflicts: [ProxyOwnershipConflict]
    let changed: Bool
  }

  private struct ServiceRecord {
    let serviceID: String
    let proxyProtocol: SCNetworkProtocol?
    let configuration: [String: Any]
  }

  private let operations: SCPreferencesOperations
  private let authorization: SystemProxyAuthorizationSession

  init(
    operations: SCPreferencesOperations = .live,
    authorizationOperations: SCPreferencesAuthorizationOperations = .live
  ) {
    self.operations = operations
    authorization = SystemProxyAuthorizationSession(operations: authorizationOperations)
  }

  func authorizeForStart() throws { try authorization.authorize() }

  func requireAuthorization() throws { try authorization.verify() }

  func releaseAuthorization() throws { try authorization.close() }

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
        try Self.validateProxyEnableFlags(
          record.configuration, serviceID: record.serviceID)
        return try SystemProxyServiceOwnership(
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
        try Self.validateProxyEnableFlags(
          record.configuration, serviceID: service.serviceID)
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
    // SCPreferencesLock itself asks SCHelper for write authorization. Observe
    // an already-restored journal without taking that privileged lock; a real
    // restoration re-reads the preferences under the lock below.
    if let released = try observeReleasedPreferences(journal) { return released }

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
        let restoration = try Self.restoration(
          for: service, configuration: record.configuration)
        conflicts.append(contentsOf: restoration.conflicts)
        restoredFields.append(
          contentsOf: restoration.restoredFields.map { (service.serviceID, $0) })
        if restoration.changed {
          guard
            SCNetworkProtocolSetConfiguration(
              proxyProtocol, restoration.configuration as CFDictionary)
          else {
            throw SystemProxyPreferencesError.setConfigurationFailed(
              serviceID: service.serviceID,
              code: SCError()
            )
          }
          changed = true
        }
      }

      let alreadyRestored =
        try !changed && conflicts.isEmpty
        && firstEffectiveMismatch(restoredValues(journal)) == nil
      let didPublish =
        try alreadyRestored
        ? false
        : publishRestoration(
          preferences, changed: changed, conflicts: conflicts)
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
          let originalValue = try Self.value(
            ownedField.originalValue.map(Self.foundationValue),
            serviceID: serviceID,
            field: ownedField.field)
          guard currentValue == originalValue else {
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
    } else if !outcome.result.conflicts.isEmpty,
      let released = try observeReleasedPreferences(journal)
    {
      return released
    }
    return outcome.result
  }

  /// A user may already have disabled our proxy or selected another port.
  /// Prove that both stored and effective settings reflect that replacement
  /// without acquiring write authorization or reapplying an obsolete snapshot.
  private func observeReleasedPreferences(_ journal: ProxyOwnershipJournal) throws
    -> ProxyRestoreResult?
  {
    try withAuthorizedPreferences { preferences in
      let records = try loadServiceRecords(preferences: preferences, enabledOnly: false)
      let recordsByID = Dictionary(uniqueKeysWithValues: records.map { ($0.serviceID, $0) })
      var externalChanges: [ProxyOwnershipConflict] = []
      for service in journal.services {
        guard let record = recordsByID[service.serviceID], record.proxyProtocol != nil else {
          return nil
        }
        let restoration = try Self.restoration(for: service, configuration: record.configuration)
        guard !restoration.changed else { return nil }
        for conflict in restoration.conflicts {
          guard
            try Self.isReleasedProxyGroup(
              conflict.field, service: service, configuration: record.configuration)
          else { return nil }
        }
        externalChanges.append(contentsOf: restoration.conflicts)
      }
      guard let primaryServiceID = operations.primaryServiceID(),
        let service = journal.services.first(where: { $0.serviceID == primaryServiceID }),
        let record = recordsByID[primaryServiceID]
      else {
        throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
      }
      let expectedValues = try service.fields.map { ownedField in
        (
          ownedField.field,
          try Self.value(
            record.configuration[ownedField.field.rawValue],
            serviceID: primaryServiceID, field: ownedField.field)
        )
      }
      guard try firstEffectiveMismatch(expectedValues) == nil else { return nil }
      return ProxyRestoreResult(conflicts: [], preservedExternalChanges: externalChanges)
    }
  }

  func withAuthorizedPreferences<T>(
    _ operation: (SCPreferences) throws -> T
  ) throws -> T {
    try authorization.withPreferences { preferences in
      operations.synchronize(preferences)
      return try operation(preferences)
    }
  }

  private func withLockedPreferences<T>(
    _ operation: (SCPreferences) throws -> T
  ) throws -> T {
    // Locking is a privileged SCHelper operation too, even before any write.
    // A restarted Agent must report missing authorization instead of blocking
    // its initialization (and XPC listener) on an implicit system dialog.
    try authorization.verify()
    return try withAuthorizedPreferences { preferences in
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
    try authorization.verify()
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
    try authorization.verify()
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
    try verifyEffectiveValues(restoredValues(journal))
  }

  private func restoredValues(_ journal: ProxyOwnershipJournal) throws
    -> [(SystemProxyField, ProxyPreferenceValue?)]
  {
    guard let primaryServiceID = operations.primaryServiceID() else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    guard let service = journal.services.first(where: { $0.serviceID == primaryServiceID }) else {
      throw SystemProxyPreferencesError.effectiveProxyStateUnavailable
    }
    return service.fields.map { ($0.field, $0.originalValue) }
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
    // SCPreferencesApplyChanges publishes the request before configd finishes
    // updating SCDynamicStore. Both activation and restoration must wait for
    // that observation to converge after releasing the preferences lock.
    // Only a value mismatch is transient; unavailable or malformed state still
    // throws immediately, and a persistent mismatch never counts as success.
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while let field = try firstEffectiveMismatch(expectedValues) {
      guard clock.now < deadline else {
        throw SystemProxyPreferencesError.effectiveVerificationFailed(field: field)
      }
      Thread.sleep(forTimeInterval: 0.02)
    }
  }

  private func firstEffectiveMismatch(
    _ expectedValues: [(SystemProxyField, ProxyPreferenceValue?)]
  ) throws -> SystemProxyField? {
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
      if !matches { return field }
    }
    return nil
  }
}
