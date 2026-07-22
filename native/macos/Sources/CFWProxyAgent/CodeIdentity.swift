import CFWSharedProtocol
import Foundation

typealias CodeIdentityPolicy = CodeIdentityRequirement

extension CodeIdentityRequirement {

  static func fromMainBundle() throws -> CodeIdentityPolicy {
    guard
      let teamIdentifier = Bundle.main.object(
        forInfoDictionaryKey: "CFWExpectedTeamIdentifier"
      ) as? String,
      !teamIdentifier.isEmpty
    else {
      throw CodeIdentityError.missingBundleSetting("CFWExpectedTeamIdentifier")
    }
    guard
      let bundleIdentifier = Bundle.main.object(
        forInfoDictionaryKey: "CFWExpectedHostBundleIdentifier"
      ) as? String,
      !bundleIdentifier.isEmpty
    else {
      throw CodeIdentityError.missingBundleSetting("CFWExpectedHostBundleIdentifier")
    }
    return try CodeIdentityRequirement(
      expectedTeamIdentifier: teamIdentifier,
      expectedBundleIdentifier: bundleIdentifier
    )
  }
}
