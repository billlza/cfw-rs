import CFWSharedProtocol
import Foundation
import Security
import Testing

@testable import CFWGlobalAuthority

private func nativeRoot() -> URL {
  URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
}

private func plist(_ name: String) throws -> [String: Any] {
  let data = try Data(contentsOf: nativeRoot().appending(path: "Config/\(name)"))
  return try #require(
    PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
}

@Test func daemonIdentityIsFixedToTheDocumentedDeveloperIDRequirement() {
  #expect(GlobalAuthorityProductIdentity.teamIdentifier == "YKUPL7Z869")
  #expect(
    GlobalAuthorityProductIdentity.signingIdentifier
      == "com.bill.clashformac.global-authority")
  #expect(
    GlobalAuthorityProductIdentity.machServiceNames
      == Dictionary(
        uniqueKeysWithValues: AuthorityRole.allCases.map {
          ($0, GlobalAuthorityConnectionContract.machServiceName(for: $0))
        }))
  #expect(
    GlobalAuthorityProductIdentity.designatedRequirement
      == "anchor apple generic and identifier \"com.bill.clashformac.global-authority\" "
      + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
      + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
      + "and certificate leaf[subject.OU] = \"YKUPL7Z869\"")
}

@Test func everyRoleAndDaemonCodeRequirementParsesOnTheMinimumSupportedAPI() {
  let roleRequirements = AuthorityRole.allCases.map {
    GlobalAuthorityConnectionContract.peerRequirement(for: $0)
  }
  let requirements =
    roleRequirements + [GlobalAuthorityConnectionContract.authorityDesignatedRequirement]
  for text in requirements {
    var requirement: SecRequirement?
    #expect(
      SecRequirementCreateWithString(
        text as CFString, [], &requirement) == errSecSuccess)
    #expect(requirement != nil)
  }

  for text in roleRequirements {
    let clauses = text.components(separatedBy: " and ")
    #expect(Set(clauses).count == clauses.count)
  }
}

@Test func roleScopedRequirementsUseOnlyExactDeveloperIDAndAppleCapabilities() throws {
  let requirements = Dictionary(
    uniqueKeysWithValues: AuthorityRole.allCases.map {
      ($0, GlobalAuthorityConnectionContract.peerRequirement(for: $0))
    })
  #expect(Set(GlobalAuthorityProductIdentity.machServiceNames.values).count == 3)

  for role in AuthorityRole.allCases {
    let requirement = try #require(requirements[role])
    let signingIdentifier = GlobalAuthorityConnectionContract.signingIdentifier(for: role)
    #expect(requirement.contains("identifier \"\(signingIdentifier)\""))
    #expect(requirement.contains("certificate leaf[subject.OU] = \"YKUPL7Z869\""))
    #expect(!requirement.contains("com.bill.clashformac.global-authority.client"))
    #expect(!requirement.contains("com.bill.clashformac.global-authority.engine-owner"))

    switch role {
    case .host, .proxyAgent:
      #expect(
        requirement.contains(
          "entitlement[\"com.apple.security.application-groups\"] = "
            + "\"YKUPL7Z869.group.com.bill.clashformac\""))
      #expect(!requirement.contains("com.apple.developer.networking.networkextension"))
    case .provider:
      #expect(
        requirement.contains(
          "entitlement[\"com.apple.developer.networking.networkextension\"] = "
            + "\"packet-tunnel-provider-systemextension\""))
      #expect(
        requirement.contains(
          "entitlement[\"com.apple.security.app-sandbox\"] exists"))
      #expect(!requirement.contains("com.apple.security.application-groups"))
    }
  }
}

@Test func launchDaemonExportsOnlyTheFixedRootControlPlaneService() throws {
  let value = try plist(GlobalAuthorityProductIdentity.launchDaemonPlistName)
  #expect(value["Label"] as? String == GlobalAuthorityProductIdentity.launchdLabel)
  #expect(value["UserName"] as? String == "root")
  #expect(
    value["BundleProgram"] as? String
      == "Contents/Library/HelperTools/CFWGlobalAuthority")
  let services = try #require(value["MachServices"] as? [String: Bool])
  #expect(
    services
      == Dictionary(
        uniqueKeysWithValues: GlobalAuthorityProductIdentity.machServiceNames.values.map {
          ($0, true)
        }))
  for forbidden in ["ProgramArguments", "Sockets", "WatchPaths", "QueueDirectories"] {
    #expect(value[forbidden] == nil)
  }
}

@Test func daemonHasNoDataPlaneOrBroadResourceEntitlements() throws {
  #expect(try plist("GlobalAuthority.entitlements").isEmpty)
}

@Test func appEmbeddingAndNativeSigningGraphContainAuthorityProduct() throws {
  let repository = nativeRoot().deletingLastPathComponent().deletingLastPathComponent()
  let configurationURL = repository.appending(path: "apps/cfw-tauri-shell/tauri.conf.json")
  let object = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: configurationURL))
      as? [String: Any])
  let bundle = try #require(object["bundle"] as? [String: Any])
  let macOS = try #require(bundle["macOS"] as? [String: Any])
  let files = try #require(macOS["files"] as? [String: String])
  #expect(
    files["Library/HelperTools/CFWGlobalAuthority"]
      == "../../target/native-products/CFWGlobalAuthority")
  #expect(
    files["Library/LaunchDaemons/com.bill.clashformac.global-authority.plist"]
      == "../../native/macos/Config/com.bill.clashformac.global-authority.plist")

  let buildScript = try String(
    contentsOf:
      repository.appending(path: "scripts/build_native_products.sh"), encoding: .utf8)
  #expect(buildScript.contains("build_scheme CFWGlobalAuthorityDaemon"))
  #expect(buildScript.contains("native-global-authority-v1"))
  #expect(!buildScript.contains("authority_designated_requirement"))
  #expect(!buildScript.contains("/usr/bin/codesign"))
  #expect(!buildScript.contains("/usr/bin/csreq"))

  let signingScript = try String(
    contentsOf:
      repository.appending(path: "scripts/run_ga_signing_attempt.sh"), encoding: .utf8)
  #expect(
    signingScript.contains(
      "readonly authority_designated_requirement='designated => anchor apple generic and identifier "
        + "\"com.bill.clashformac.global-authority\" and certificate "
        + "1[field.1.2.840.113635.100.6.2.6] exists and certificate "
        + "leaf[field.1.2.840.113635.100.6.1.13] exists and certificate "
        + "leaf[subject.OU] = \"YKUPL7Z869\"'"))
  #expect(
    signingScript.contains(
      "/usr/bin/codesign -d -r \"$authority_requirement_text\" \"$authority\""))
  #expect(
    signingScript.contains(
      "readonly authority_requirement_root=\"$attempt_work/authority-requirement\""))
  #expect(
    signingScript.contains(
      "readonly authority_requirement_text=\"$authority_requirement_root/signed.txt\""))
  #expect(
    signingScript.contains(
      "readonly authority_requirement_expected=\"$authority_requirement_root/expected.csreq\""))
  #expect(
    signingScript.contains(
      "readonly authority_requirement_actual=\"$authority_requirement_root/actual.csreq\""))
  #expect(
    signingScript.contains(
      "--identifier com.bill.clashformac.global-authority \\\n"
        + "  -r=\"$authority_designated_requirement\" \\\n"
        + "  --entitlements \"$authority_entitlements\""))
  #expect(signingScript.contains("cannot extract the Global Authority designated requirement"))
  #expect(
    signingScript.contains(
      "/usr/bin/csreq -r=\"$authority_designated_requirement\" \\\n"
        + "  -b \"$authority_requirement_expected\""))
  #expect(
    signingScript.contains(
      "/usr/bin/csreq -r \"$authority_requirement_text\" \\\n"
        + "  -b \"$authority_requirement_actual\""))
  #expect(signingScript.contains("/usr/bin/cmp -s --"))
  #expect(signingScript.contains("Global Authority designated requirement mismatch"))
  #expect(
    signingScript.contains(
      "cannot remove the Global Authority requirement verification files"))
}

@Test func tauriBundleEmbedsTheCompleteNativeProductGraph() throws {
  let repository = nativeRoot().deletingLastPathComponent().deletingLastPathComponent()
  let configurationURL = repository.appending(path: "apps/cfw-tauri-shell/tauri.conf.json")
  let object = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: configurationURL))
      as? [String: Any])
  let bundle = try #require(object["bundle"] as? [String: Any])
  let macOS = try #require(bundle["macOS"] as? [String: Any])
  #expect(macOS["minimumSystemVersion"] as? String == "15.0")
  let files = try #require(macOS["files"] as? [String: String])
  // Host bridge, Global Authority daemon + launchd plist, ProxyAgent, and the
  // Packet Tunnel system extension are all embedded inside the host app.
  for destination in [
    "Frameworks/CFWNativeBridge.framework",
    "Library/HelperTools/CFWGlobalAuthority",
    "Library/LaunchDaemons/com.bill.clashformac.global-authority.plist",
    "Library/LoginItems/CFWProxyAgent.app",
    "Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension",
  ] {
    #expect(files[destination] != nil)
  }
}

@Test func signingOrderManifestSignsTheOuterAppLastAroundTheProductGraph() throws {
  let manifestURL = nativeRoot().appending(path: "Config/signing-order.json")
  let object = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any])
  #expect(object["schemaVersion"] as? Int == 1)
  #expect(object["teamIdentifier"] as? String == GlobalAuthorityProductIdentity.teamIdentifier)

  let outer = try #require(object["outer"] as? [String: Any])
  #expect(outer["signedLast"] as? Bool == true)
  #expect(outer["bundleIdentifier"] as? String == "com.bill.clashformac")

  let nested = try #require(object["nested"] as? [[String: Any]])
  let destinations = Set(nested.compactMap { $0["destination"] as? String })
  for destination in [
    "Contents/Frameworks/CFWNativeBridge.framework",
    "Contents/Library/HelperTools/CFWGlobalAuthority",
    "Contents/Library/LoginItems/CFWProxyAgent.app",
    "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension",
  ] {
    #expect(destinations.contains(destination))
  }

  let daemon = try #require(
    nested.first {
      $0["destination"] as? String == "Contents/Library/HelperTools/CFWGlobalAuthority"
    }
  )
  #expect(
    daemon["launchdPlist"] as? String
      == "Contents/Library/LaunchDaemons/com.bill.clashformac.global-authority.plist")
  #expect(
    daemon["machServices"] as? [String]
      == AuthorityRole.allCases.map {
        GlobalAuthorityConnectionContract.machServiceName(for: $0)
      })
}

@Test func daemonRuntimeSourceHasNoDataPlaneOrProcessLaunchSurface() throws {
  let source = try String(
    contentsOf:
      nativeRoot().appending(path: "Sources/CFWGlobalAuthority/GlobalAuthorityDaemon.swift"),
    encoding: .utf8)
  for forbidden in [
    "import NetworkExtension", "import SystemConfiguration", "import CFWLibboxRuntime",
    "Process(", "posix_spawn", "NSTask", "dlopen", "system(", "popen(",
  ] {
    #expect(!source.contains(forbidden))
  }
}
