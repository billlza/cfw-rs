import Foundation

enum SystemProxyPreferencesError: Error, Equatable, Sendable {
  case authorizationCreationFailed(OSStatus)
  case authorizationReferenceUnavailable
  case authorizationDenied(OSStatus)
  case authorizationRequestFailed(OSStatus)
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
  case existingProxyConfiguration(serviceID: String, field: SystemProxyField)
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
    case .authorizationDenied(let status):
      return "System proxy authorization was not granted (status \(status))."
    case .authorizationRequestFailed(let status):
      return "System proxy authorization request failed (status \(status))."
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
    case .existingProxyConfiguration(let serviceID, let field):
      return
        "Network service \(serviceID) already has \(field.rawValue) enabled. Turn off the existing system proxy in its app or System Settings before enabling Clash for Mac. Existing proxy settings were not changed."
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
