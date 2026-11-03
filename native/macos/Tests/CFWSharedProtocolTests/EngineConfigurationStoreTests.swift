import CryptoKit
import Darwin
import Foundation
import Security
import Testing

@testable import CFWSharedProtocol

// The engine configuration store: validated round trips, tampered content,
// link substitution, permissions, healing and the app group policy.
func removeEngineProtocolTestDirectory(_ root: URL) {
  guard FileManager.default.fileExists(atPath: root.path) else {
    return
  }
  do {
    try FileManager.default.removeItem(at: root)
  } catch {
    Issue.record("Failed to remove engine protocol test directory: \(error)")
  }
}

@Test func configurationStoreRejectsTamperedContent() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }

  let store = AppGroupConfigurationStore(testingRootURL: root)
  let descriptor = try store.persist(
    Data(#"{"route":{"final":"direct"}}"#.utf8),
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1
  )
  try Data(#"{"route":{"final":"reject"}}"#.utf8).write(
    to: root.appendingPathComponent(ConfigurationSlot.tunnel.fileName)
  )

  #expect(throws: ConfigurationStoreError.self) {
    try store.load(descriptor)
  }
}

@Test func configurationStoreRoundTripsValidatedJSON() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }

  let configuration = Data(#"{"route":{"final":"direct"}}"#.utf8)
  let store = AppGroupConfigurationStore(testingRootURL: root)
  let descriptor = try store.persist(
    configuration,
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 11
  )

  #expect(try store.load(descriptor) == configuration)
}

@Test func configurationStoreRejectsSymlinkAndHardLinkSubstitution() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }
  let configuration = Data(#"{"route":{"final":"direct"}}"#.utf8)
  let store = AppGroupConfigurationStore(testingRootURL: root)
  let descriptor = try store.persist(
    configuration,
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1
  )
  let configurationURL = root.appendingPathComponent(ConfigurationSlot.tunnel.fileName)
  let hardLinkURL = root.appendingPathComponent("hard-linked-config.json")
  try FileManager.default.linkItem(at: configurationURL, to: hardLinkURL)

  #expect(throws: ConfigurationStoreError.unsafeMetadata(.hardLinkedFile)) {
    try store.load(descriptor)
  }

  try FileManager.default.removeItem(at: hardLinkURL)
  try FileManager.default.removeItem(at: configurationURL)
  let targetURL = root.appendingPathComponent("untrusted-target.json")
  try configuration.write(to: targetURL)
  try FileManager.default.createSymbolicLink(at: configurationURL, withDestinationURL: targetURL)

  #expect(throws: ConfigurationStoreError.self) {
    try store.load(descriptor)
  }
}

@Test func configurationStoreHealsDirectoryAndCreatesPrivateFile() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o777],
    ofItemAtPath: root.path
  )
  let store = AppGroupConfigurationStore(testingRootURL: root)

  _ = try store.persist(
    Data(#"{"route":{"final":"direct"}}"#.utf8),
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1
  )

  let directoryAttributes = try FileManager.default.attributesOfItem(atPath: root.path)
  let filePath = root.appendingPathComponent(ConfigurationSlot.tunnel.fileName).path
  let fileAttributes = try FileManager.default.attributesOfItem(atPath: filePath)
  let directoryMode = try #require(directoryAttributes[.posixPermissions] as? NSNumber)
  let fileMode = try #require(fileAttributes[.posixPermissions] as? NSNumber)
  #expect(directoryMode.intValue & 0o7777 == 0o700)
  #expect(fileMode.intValue & 0o7777 == 0o600)
}

@Test func configurationStoreRejectsWideFilePermissions() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }
  let store = AppGroupConfigurationStore(testingRootURL: root)
  let descriptor = try store.persist(
    Data(#"{"route":{"final":"direct"}}"#.utf8),
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1
  )
  let filePath = root.appendingPathComponent(ConfigurationSlot.tunnel.fileName).path
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o666],
    ofItemAtPath: filePath
  )

  #expect(
    throws: ConfigurationStoreError.unsafeMetadata(
      .invalidFilePermissions(actual: mode_t(0o666))
    )
  ) {
    try store.load(descriptor)
  }
}

@Test func configurationStoreRejectsSymlinkedDirectory() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  let target = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer {
    removeEngineProtocolTestDirectory(root)
    removeEngineProtocolTestDirectory(target)
  }
  try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
  try FileManager.default.createSymbolicLink(at: root, withDestinationURL: target)
  let store = AppGroupConfigurationStore(testingRootURL: root)

  #expect(throws: ConfigurationStoreError.self) {
    try store.persist(
      Data(#"{"route":{"final":"direct"}}"#.utf8),
      slot: .tunnel,
      tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
      credentialAudience: try testCredentialAudience(),
      installationID: installationID,
      epoch: 1,
      generation: 1
    )
  }
}

@Test func appGroupPolicyRejectsWrongOwnerExpectationAndPathTraversal() throws {
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }
  let directoryFD = try SecureAppGroupFileSystem.createAndOpenPrivateDirectory(at: root)
  defer { Darwin.close(directoryFD) }
  let actualOwner = geteuid()
  let unexpectedOwner = actualOwner &+ 1

  #expect(
    throws: AppGroupFileSecurityError.invalidDirectoryOwner(
      expected: unexpectedOwner,
      actual: actualOwner
    )
  ) {
    try SecureAppGroupFileSystem.validateAndSecureDirectory(
      directoryFD,
      expectedOwner: unexpectedOwner
    )
  }
  #expect(throws: AppGroupFileSecurityError.invalidRelativeName("../engine.lock")) {
    try SecureAppGroupFileSystem.openPrivateRegularFile(
      in: directoryFD,
      named: "../engine.lock",
      flags: O_RDONLY
    )
  }
}
