import Foundation
import Testing

@testable import CFWSharedProtocol

private func sandboxDescriptor(
  installationID: UUID,
  generation: UInt64
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: try testCredentialAudience(),
    installationID: installationID,
    epoch: 1,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

@Test func sandboxAcceptanceStoreRejectsReplayAndInstallationReplacement() throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "cfw-sandbox-acceptance-\(UUID().uuidString)",
    isDirectory: true
  )
  defer { try? FileManager.default.removeItem(at: root) }
  let store = SandboxConfigurationAcceptanceStore(testingRootURL: root)
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-4111-8111-111111111111")
  )
  let first = try sandboxDescriptor(installationID: installationID, generation: 1)
  try store.accept(first)
  #expect(
    throws: ConfigurationStoreError.staleConfiguration(
      acceptedEpoch: 1,
      acceptedGeneration: 1,
      requestedEpoch: 1,
      requestedGeneration: 1
    )
  ) {
    try store.accept(first)
  }
  try store.accept(try sandboxDescriptor(installationID: installationID, generation: 2))

  let otherInstallation = try #require(
    UUID(uuidString: "22222222-2222-4222-8222-222222222222")
  )
  #expect(
    throws: ConfigurationStoreError.installationIdentifierMismatch(
      expected: installationID,
      actual: otherInstallation
    )
  ) {
    try store.accept(
      try sandboxDescriptor(installationID: otherInstallation, generation: 3)
    )
  }
}

@Test func sandboxAcceptanceStoreFailsClosedOnCorruptCursor() throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "cfw-sandbox-acceptance-corrupt-\(UUID().uuidString)",
    isDirectory: true
  )
  defer { try? FileManager.default.removeItem(at: root) }
  let store = SandboxConfigurationAcceptanceStore(testingRootURL: root)
  let installationID = try #require(
    UUID(uuidString: "11111111-1111-4111-8111-111111111111")
  )
  try store.accept(try sandboxDescriptor(installationID: installationID, generation: 1))
  try Data("not-json".utf8).write(to: root.appendingPathComponent("accepted.json"))

  #expect(throws: ConfigurationStoreError.malformedAcceptanceJournal) {
    try store.accept(try sandboxDescriptor(installationID: installationID, generation: 2))
  }
}
