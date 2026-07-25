import Foundation
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
    GlobalAuthorityProductIdentity.machServiceName
      == "YKUPL7Z869.group.com.bill.clashformac.global-authority")
  #expect(
    GlobalAuthorityProductIdentity.designatedRequirement
      == "anchor apple generic and identifier \"com.bill.clashformac.global-authority\" "
      + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
      + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
      + "and certificate leaf[subject.OU] = \"YKUPL7Z869\"")
}

@Test func launchDaemonExportsOnlyTheFixedRootControlPlaneService() throws {
  let value = try plist(GlobalAuthorityProductIdentity.launchDaemonPlistName)
  #expect(value["Label"] as? String == GlobalAuthorityProductIdentity.launchdLabel)
  #expect(value["UserName"] as? String == "root")
  #expect(
    value["BundleProgram"] as? String
      == "Contents/Library/HelperTools/CFWGlobalAuthority")
  let services = try #require(value["MachServices"] as? [String: Bool])
  #expect(services == [GlobalAuthorityProductIdentity.machServiceName: true])
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
  #expect(buildScript.contains("Global Authority designated requirement mismatch"))
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
    "Library/SystemExtensions/CFWPacketTunnel.systemextension",
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
    "Contents/Library/SystemExtensions/CFWPacketTunnel.systemextension",
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
  #expect(daemon["machService"] as? String == GlobalAuthorityProductIdentity.machServiceName)
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
