import CFWSharedProtocol
import CoreFoundation
import Foundation

extension SCPreferencesSystemProxyPreferences {
  static func isReleasedProxyGroup(
    _ field: SystemProxyField,
    service: SystemProxyServiceOwnership,
    configuration: [String: Any]
  ) throws -> Bool {
    let enableField: SystemProxyField
    let portField: SystemProxyField
    switch field {
    case .httpEnabled, .httpHost, .httpPort:
      (enableField, portField) = (.httpEnabled, .httpPort)
    case .httpsEnabled, .httpsHost, .httpsPort:
      (enableField, portField) = (.httpsEnabled, .httpsPort)
    case .socksEnabled, .socksHost, .socksPort:
      (enableField, portField) = (.socksEnabled, .socksPort)
    case .proxyAutoConfigEnabled, .proxyAutoDiscoveryEnabled:
      // PAC/WPAD can still select our listener; preserve the unresolved conflict.
      return false
    }
    let enabled = try value(
      configuration[enableField.rawValue], serviceID: service.serviceID, field: enableField)
    if !isEffectivelyEnabled(enabled) { return true }
    let currentPort = try value(
      configuration[portField.rawValue], serviceID: service.serviceID, field: portField)
    guard case .integer(let port) = currentPort, (1...65_535).contains(port),
      let ownedPort = service.fields.first(where: { $0.field == portField })
    else { return false }
    // A hostname edit on the same port may be a loopback alias for our listener.
    return currentPort != ownedPort.appliedValue
  }

  static func restoration(
    for service: SystemProxyServiceOwnership,
    configuration: [String: Any]
  ) throws -> ServiceRestoration {
    var updated = configuration
    var restoredFields: [OwnedSystemProxyField] = []
    var conflicts: [ProxyOwnershipConflict] = []
    var changed = false
    let observations = try service.fields.map { ownedField in
      let current = try value(
        configuration[ownedField.field.rawValue],
        serviceID: service.serviceID,
        field: ownedField.field)
      guard ownedField.field.acceptsOriginalValue(current) else {
        throw SystemProxyPreferencesError.unsupportedValue(
          serviceID: service.serviceID, field: ownedField.field)
      }
      let original = try value(
        ownedField.originalValue.map(foundationValue),
        serviceID: service.serviceID,
        field: ownedField.field)
      return (ownership: ownedField, current: current, original: original)
    }
    // An enable flag alone is not ownership: another app can enable the retained
    // original endpoint after preparation, or replace a running proxy's endpoint.
    // Restore each protocol only while its entire endpoint is still ours.
    for enableField in SystemProxyField.allCases where enableField.isEnableFlag {
      let group = observations.filter {
        $0.ownership.field == enableField
          || controllingEnableField(for: $0.ownership.field) == enableField
      }
      if group.allSatisfy({ $0.current == $0.original }) {
        restoredFields.append(contentsOf: group.map(\.ownership))
      } else if group.allSatisfy({ $0.current == $0.ownership.appliedValue }) {
        for observation in group {
          let ownedField = observation.ownership
          set(ownedField.originalValue, field: ownedField.field, in: &updated)
          restoredFields.append(ownedField)
        }
        changed = true
      } else {
        for observation in group where observation.current != observation.ownership.appliedValue {
          conflicts.append(
            ProxyOwnershipConflict(
              serviceID: service.serviceID,
              field: observation.ownership.field,
              reason: .valueChanged(current: observation.current)))
        }
      }
    }
    return ServiceRestoration(
      configuration: updated,
      restoredFields: restoredFields,
      conflicts: conflicts,
      changed: changed)
  }

  static func isEffectivelyEnabled(_ value: ProxyPreferenceValue?) -> Bool {
    switch value {
    case .boolean(let enabled):
      return enabled
    case .integer(let enabled):
      return enabled != 0
    case .none, .string:
      return false
    }
  }

  /// Enabling System Proxy explicitly takes over the selected services. Their
  /// complete original proxy fields are journaled and compared under the lock;
  /// restoration changes only protocol groups still owned by this operation.
  static func validateProxyEnableFlags(
    _ configuration: [String: Any],
    serviceID: String
  ) throws {
    for field in SystemProxyField.allCases where field.isEnableFlag {
      switch try value(configuration[field.rawValue], serviceID: serviceID, field: field) {
      case .none, .boolean, .integer(0), .integer(1):
        continue
      case .integer, .string:
        throw SystemProxyPreferencesError.unsupportedValue(serviceID: serviceID, field: field)
      }
    }
  }

  static func controllingEnableField(
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

  static func appliedValues(
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

  static func value(
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

  static func foundationValue(_ value: ProxyPreferenceValue) -> Any {
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
