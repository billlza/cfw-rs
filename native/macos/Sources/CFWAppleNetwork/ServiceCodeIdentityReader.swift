import Foundation
@preconcurrency import Security

/// Original Info.plist bytes and CodeDirectory identity of one retained build.
/// These bytes are only a candidate: Security must authenticate them against the
/// running process, and the resulting identity must equal the retained identity.
struct ServiceCodeMetadata: Sendable {
  let identity: CurrentAppServiceCodeIdentity
  let infoPlist: Data

  init(identity: CurrentAppServiceCodeIdentity, infoPlist: Data) throws {
    guard !infoPlist.isEmpty, infoPlist.count <= 64 * 1024 else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    self.identity = identity
    self.infoPlist = infoPlist
  }
}

/// Keeps OS signature validation and authenticated metadata decoding together.
/// Process observations never authorize XPC; each connection still binds its
/// signer, identifier and (for new operations) current CDHash to its audit token.
enum ServiceCodeIdentityReader {
  private static let validationFlags: SecCSFlags = [
    .noNetworkAccess, SecCSFlags(rawValue: kSecCSStrictValidate),
  ]

  static func currentHost(requirement: SecRequirement) throws -> CurrentAppServiceCodeIdentity {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
      SecCodeCheckValidity(code, validationFlags, requirement) == errSecSuccess
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return try runningIdentity(code)
  }

  static func staticCode(_ url: URL, requirement: SecRequirement) throws
    -> CurrentAppServiceCodeIdentity
  {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
      SecStaticCodeCheckValidity(code, validationFlags, requirement) == errSecSuccess
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return try signingIdentity(code)
  }

  static func process(
    _ pid: pid_t, requirement: SecRequirement,
    replacedMetadata: () throws -> [ServiceCodeMetadata] = { [] }
  ) throws -> CurrentAppServiceCodeIdentity {
    let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
    let code = try guest(attributes)
    let status = SecCodeCheckValidity(code, validationFlags, requirement)
    if status == errSecSuccess { return try runningIdentity(code) }
    guard status == errSecCSStaticCodeChanged else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }

    // A Finder replacement can unlink the old executable while its registered
    // service remains alive. The ordinary SecCode object then reads the new
    // disk signature. Ask Security for the kernel-backed signature instead,
    // supplying the original sealed metadata it can no longer read from disk.
    // This is not a retry with weaker flags or an assumed version.
    let candidates = try replacedMetadata()
    guard !candidates.isEmpty, candidates.count <= 8 else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    for metadata in candidates {
      let attributes: [CFString: Any] = [
        kSecGuestAttributePid: NSNumber(value: pid),
        kSecGuestAttributeDynamicCode: NSNumber(value: true),
        kSecGuestAttributeDynamicCodeInfoPlist: metadata.infoPlist,
      ]
      let running = try guest(attributes as CFDictionary)
      let status = SecCodeCheckValidity(running, validationFlags, requirement)
      // A different retained build has a different authenticated Info.plist.
      // Only that specific mismatch permits trying the next bounded candidate.
      if status == errSecCSInfoPlistFailed { continue }
      guard status == errSecSuccess else {
        throw CurrentAppServiceBuildError.identityUnavailable
      }
      let identity = try runningIdentity(running)
      guard identity == metadata.identity else {
        throw CurrentAppServiceBuildError.identityUnavailable
      }
      return identity
    }
    throw CurrentAppServiceBuildError.identityUnavailable
  }

  private static func guest(_ attributes: CFDictionary) throws -> SecCode {
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code
    else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    return code
  }

  private static func runningIdentity(_ code: SecCode) throws -> CurrentAppServiceCodeIdentity {
    var value: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &value) == errSecSuccess, let value else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    return try signingIdentity(value)
  }

  /// Only called after the corresponding strict validity check succeeded.
  /// For a kernel-backed SecCode, its StaticCode retains that signature view.
  private static func signingIdentity(_ code: SecStaticCode) throws
    -> CurrentAppServiceCodeIdentity
  {
    var information: CFDictionary?
    guard
      SecCodeCopySigningInformation(
        code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
      let values = information as? [CFString: Any],
      let plist = values[kSecCodeInfoPList] as? [String: Any],
      let text = plist["CFBundleVersion"] as? String,
      let hash = values[kSecCodeInfoUnique] as? Data
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return try .init(buildText: text, cdHash: hash)
  }
}
