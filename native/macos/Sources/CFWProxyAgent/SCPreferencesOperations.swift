import CoreFoundation
import Foundation
import Security
import SystemConfiguration

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
/// authorization is obtained before engine startup and retained by this Agent.
/// Transactions must never open an authorization dialog while owning a runtime.
struct SCPreferencesAuthorizationOperations: @unchecked Sendable {
  let createAuthorization: () -> (status: OSStatus, reference: AuthorizationRef?)
  let copyRights: (AuthorizationRef, Bool) -> OSStatus
  let createPreferences: (AuthorizationRef) -> SCPreferences?
  let freeAuthorization: (AuthorizationRef, AuthorizationFlags) -> OSStatus

  static let live = SCPreferencesAuthorizationOperations(
    createAuthorization: {
      var reference: AuthorizationRef?
      let status = AuthorizationCreate(nil, nil, [], &reference)
      return (status, reference)
    },
    copyRights: { authorization, interactionAllowed in
      "system.services.systemconfiguration.network".withCString { name in
        var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { item in
          var rights = AuthorizationRights(count: 1, items: item)
          var flags: AuthorizationFlags = [.extendRights]
          if interactionAllowed { flags.insert(.interactionAllowed) }
          return AuthorizationCopyRights(authorization, &rights, nil, flags, nil)
        }
      }
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
