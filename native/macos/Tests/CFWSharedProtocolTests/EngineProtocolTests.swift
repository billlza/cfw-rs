import CryptoKit
import Darwin
import Foundation
import Security
import Testing

@testable import CFWSharedProtocol

private struct EngineOwnerSchemaContract: Decodable {
  let configurationIdentitySchemaVersion: UInt16
  let engineOwnerSchemaVersion: UInt16

  private enum CodingKeys: String, CodingKey {
    case configurationIdentitySchemaVersion = "configuration_identity_schema_version"
    case engineOwnerSchemaVersion = "engine_owner_schema_version"
  }
}

func testCredentialAudience() throws -> CredentialAudience {
  CredentialAudience(
    profileID: UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!,
    profileDigest: try SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

private final class MemoryAcceptanceCursorStore:
  JournalDataStoring, @unchecked Sendable
{
  private let lock = NSLock()
  private var data: Data?
  private var failure: JournalAuthenticationError?

  func load() throws(JournalAuthenticationError) -> Data? {
    lock.lock()
    defer { lock.unlock() }
    if let failure {
      throw failure
    }
    return data
  }

  func save(_ data: Data) throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let failure {
      throw failure
    }
    self.data = data
  }

  func remove() throws(JournalAuthenticationError) {
    lock.lock()
    defer { lock.unlock() }
    if let failure {
      throw failure
    }
    data = nil
  }

  func replace(with data: Data) {
    lock.withLock {
      self.data = data
    }
  }

  func setFailure(_ failure: JournalAuthenticationError?) {
    lock.withLock {
      self.failure = failure
    }
  }
}

private func removeEngineProtocolTestDirectory(_ root: URL) {
  guard FileManager.default.fileExists(atPath: root.path) else {
    return
  }
  do {
    try FileManager.default.removeItem(at: root)
  } catch {
    Issue.record("Failed to remove engine protocol test directory: \(error)")
  }
}

@Test func inMemoryConfigurationValidationBindsExactBytesWithoutIO() throws {
  let configuration = Data("{}".utf8)
  let digest = SHA256.hash(data: configuration)
    .map { String(format: "%02x", $0) }
    .joined()
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111"))
  let descriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: UInt64(configuration.count),
    sha256: SHA256Digest(hex: digest)
  )

  try descriptor.validateConfigurationBytes(configuration)
  #expect(throws: ConfigurationBytesValidationError.self) {
    try descriptor.validateConfigurationBytes(Data("[]".utf8))
  }
  #expect(
    throws: ConfigurationBytesValidationError.byteCountMismatch(
      expected: 2,
      actual: 3)
  ) {
    try descriptor.validateConfigurationBytes(Data("{} ".utf8))
  }

  let invalidJSON = Data("xx".utf8)
  let invalidDigest = SHA256.hash(data: invalidJSON)
    .map { String(format: "%02x", $0) }
    .joined()
  let invalidDescriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 2,
    byteCount: UInt64(invalidJSON.count),
    sha256: SHA256Digest(hex: invalidDigest)
  )
  #expect(throws: ConfigurationBytesValidationError.invalidJSON) {
    try invalidDescriptor.validateConfigurationBytes(invalidJSON)
  }
}

@Test func requestEnvelopeRoundTripsWithoutLosingTypeInformation() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  let descriptor = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 7,
    byteCount: 128,
    sha256: digest
  )
  let command = try NativeCommand(kind: .startTunnel, configuration: descriptor)
  let original = RequestEnvelope(command: command)

  let decoded = try ProtocolCodec.decodeRequest(ProtocolCodec.encode(original))

  #expect(decoded == original)
}

@Test func tunnelNetworkOptionsEnforcePublicPacketPumpMTUBound() throws {
  #expect(
    try TunnelNetworkOptions(
      ipv6Enabled: true,
      mtu: TunnelNetworkOptions.maximumMTU
    ).mtu == 1_500
  )
  #expect(throws: ProtocolValidationError.invalidTunnelOptions) {
    try TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_501)
  }
  #expect(throws: ProtocolValidationError.invalidTunnelOptions) {
    try TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_279)
  }
}

@Test func tunnelNetworkOptionsAdmitOnlyTheClosedCanonicalDirectIPv4HostSet() throws {
  let exact = try TunnelNetworkOptions(
    ipv6Enabled: true,
    directIPv4Hosts: [TunnelNetworkOptions.releasePacketTransportIPv4]
  )
  let encoded = try JSONEncoder().encode(exact)
  #expect(try JSONDecoder().decode(TunnelNetworkOptions.self, from: encoded) == exact)
  #expect(String(decoding: encoded, as: UTF8.self).contains("\"direct_ipv4_hosts\""))

  for invalid in [
    ["35.194.216.98", "35.194.216.98"],
    ["035.194.216.98"],
    ["35.194.216.99"],
    ["35.194.216.98", "1.1.1.1"],
  ] {
    #expect(throws: ProtocolValidationError.invalidTunnelOptions) {
      try TunnelNetworkOptions(ipv6Enabled: true, directIPv4Hosts: invalid)
    }
  }

  let missingRouteField = Data(
    #"{"ipv6_enabled":true,"bypass_private_networks":true,"mtu":1500}"#.utf8
  )
  #expect(throws: (any Error).self) {
    try JSONDecoder().decode(TunnelNetworkOptions.self, from: missingRouteField)
  }
}

@Test func commandRejectsConfigurationForWrongMode() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let descriptor = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )

  #expect(throws: ProtocolValidationError.invalidCommand) {
    try NativeCommand(kind: .startTunnel, configuration: descriptor)
  }
}

@Test func systemProxyStartRequiresExactConfigurationDescriptor() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let configuration = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
  let command = try NativeCommand(
    kind: .startSystemProxy,
    configuration: configuration
  )
  #expect(command.configuration == configuration)
}

@Test func stopCommandRequiresExactConfigurationGeneration() throws {
  #expect(throws: ProtocolValidationError.invalidCommand) {
    try NativeCommand(kind: .stop)
  }
}

@Test func engineOwnerSchemaMatchesSharedContractAndRejectsV5() throws {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  let contract = try JSONDecoder().decode(
    EngineOwnerSchemaContract.self,
    from: Data(
      contentsOf:
        root
        .appendingPathComponent("contracts/engine-owner-v6", isDirectory: true)
        .appendingPathComponent("schema-policy.json")
    )
  )
  #expect(contract.configurationIdentitySchemaVersion == NativeProtocolConstants.schemaVersion)
  #expect(contract.engineOwnerSchemaVersion == NativeProtocolConstants.schemaVersion)

  for rejected: UInt16 in [5, 99] {
    let json = Data(
      """
      {"schemaVersion":\(rejected),"requestID":{"rawValue":"00000000-0000-0000-0000-000000000001"},"command":{"kind":"snapshot"}}
      """.utf8
    )
    #expect(throws: ProtocolValidationError.unsupportedSchemaVersion(rejected)) {
      try ProtocolCodec.decodeRequest(json)
    }
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

@Test func acceptanceJournalRejectsReplayAndAcceptsMonotonicGeneration() throws {
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-1111-1111-111111111111")
  )
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  defer { removeEngineProtocolTestDirectory(root) }

  let cursorStore = MemoryAcceptanceCursorStore()
  let journal = ConfigurationAcceptanceStore(
    testingRootURL: root,
    allowedSlot: .tunnel,
    cursorStore: cursorStore
  )
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  let first = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 3,
    generation: 7,
    byteCount: 128,
    sha256: digest
  )
  try journal.accept(first)

  #expect(throws: ConfigurationStoreError.self) {
    try journal.accept(first)
  }

  let next = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 3,
    generation: 8,
    byteCount: 128,
    sha256: digest
  )
  try journal.accept(next)

  let differentInstallation = try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: UUID(),
    epoch: 4,
    generation: 1,
    byteCount: 128,
    sha256: digest
  )
  #expect(throws: ConfigurationStoreError.self) {
    try journal.accept(differentInstallation)
  }

  let wrongSlot = try ConfigurationDescriptor(
    slot: .systemProxy,
    tunnelOptions: nil,
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 4,
    generation: 9,
    byteCount: 128,
    sha256: digest
  )
  #expect(
    throws: ConfigurationStoreError.unexpectedAcceptanceSlot(
      expected: .tunnel,
      actual: .systemProxy
    )
  ) {
    try journal.accept(wrongSlot)
  }

  cursorStore.replace(with: Data("{}".utf8))
  #expect(throws: ConfigurationStoreError.malformedAcceptanceJournal) {
    try journal.accept(next)
  }

  cursorStore.setFailure(.keychainReadFailed(errSecInteractionNotAllowed))
  #expect(
    throws: ConfigurationStoreError.acceptanceStateUnavailable(
      .keychainReadFailed(errSecInteractionNotAllowed)
    )
  ) {
    try journal.accept(next)
  }

  #expect(
    !FileManager.default.fileExists(
      atPath: root.appendingPathComponent("tunnel-accepted.json").path
    )
  )
}
