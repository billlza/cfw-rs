import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// MARK: - Fakes

private final class EventRecorder: @unchecked Sendable {
  enum Event: Equatable { case prepare, save, reload, start }
  private let lock = NSLock()
  private var events: [Event] = []
  func record(_ event: Event) { lock.withLock { events.append(event) } }
  var recorded: [Event] { lock.withLock { events } }
}

private final class RecordingPreparer: TunnelStartPreparing, @unchecked Sendable {
  private let recorder: EventRecorder
  private let ticketByte: UInt8
  private let descriptorOverride: ConfigurationDescriptor?

  init(
    recorder: EventRecorder,
    ticketByte: UInt8 = 0x5,
    descriptorOverride: ConfigurationDescriptor? = nil
  ) {
    self.recorder = recorder
    self.ticketByte = ticketByte
    self.descriptorOverride = descriptorOverride
  }

  func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart {
    recorder.record(.prepare)
    let ticket = try StartTicket(
      copying: Data(repeating: ticketByte, count: AuthorityV1Limits.ticketBytes))
    return HostPreparedTunnelStart(
      ticket: ticket,
      descriptor: descriptorOverride ?? preparation.descriptor,
      operationID: UUID())
  }
}

private final class FakeManagedTunnel: ManagedTunnelOperating, @unchecked Sendable {
  private let recorder: EventRecorder
  private let reloadOverride: ConfigurationDescriptor?
  private let lock = NSLock()
  private var savedDescriptor: ConfigurationDescriptor?
  private var saveCountValue = 0
  private var reloadCountValue = 0
  private var startCountValue = 0
  private var startedTicketValue: Data?

  init(recorder: EventRecorder, reloadOverride: ConfigurationDescriptor? = nil) {
    self.recorder = recorder
    self.reloadOverride = reloadOverride
  }

  var saveCount: Int { lock.withLock { saveCountValue } }
  var reloadCount: Int { lock.withLock { reloadCountValue } }
  var startCount: Int { lock.withLock { startCountValue } }
  var startedTicket: Data? { lock.withLock { startedTicketValue } }

  func saveDescriptorOnly(
    _ descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) async throws {
    lock.withLock {
      saveCountValue += 1
      savedDescriptor = descriptor
    }
    recorder.record(.save)
  }

  func reloadDescriptor() async throws -> ConfigurationDescriptor {
    recorder.record(.reload)
    return lock.withLock {
      reloadCountValue += 1
      return reloadOverride ?? savedDescriptor!
    }
  }

  func startWithTicket(_ ticketBytes: Data) async throws {
    lock.withLock {
      startCountValue += 1
      startedTicketValue = ticketBytes
    }
    recorder.record(.start)
  }
}

// MARK: - Builders

private func tunnelDescriptor(
  sha: String = String(repeating: "ab", count: 32),
  identity: String = String(repeating: "cd", count: 32)
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: sha),
    identitySHA256: SHA256Digest(hex: identity))
}

private func hostBridgeSource() throws -> String {
  let sourceURL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // CFWAppleNetworkTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // macos
    .appendingPathComponent("Sources/CFWAppleNetwork/HostBridge.swift")
  return try String(contentsOf: sourceURL, encoding: .utf8)
}

// MARK: - Tests

@Suite(.serialized)
struct TicketOnlyTunnelStartTests {
  @Test func authorityUnavailableFailsClosedBeforeAnyPreferenceMutation() async throws {
    let recorder = EventRecorder()
    let manager = FakeManagedTunnel(recorder: recorder)
    let descriptor = try tunnelDescriptor()

    await #expect(throws: AppleNetworkError.globalAuthorityUnavailable) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: descriptor,
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: FailClosedTunnelStartPreparer(),
        manager: manager)
    }
    // No preference or network mutation happened before the fail-closed preparation.
    #expect(manager.saveCount == 0)
    #expect(manager.reloadCount == 0)
    #expect(manager.startCount == 0)
    #expect(recorder.recorded.isEmpty)
  }

  @Test func preparesWithAuthorityBeforeSavingPreferences() async throws {
    let recorder = EventRecorder()
    let manager = FakeManagedTunnel(recorder: recorder)
    let descriptor = try tunnelDescriptor()

    try await TicketOnlyTunnelStartFlow.run(
      descriptor: descriptor,
      configuration: Data("{}".utf8),
      credentialPayload: nil,
      preparer: RecordingPreparer(recorder: recorder),
      manager: manager)

    // Prepare precedes save, then reload/verify, then start with the ticket.
    #expect(recorder.recorded == [.prepare, .save, .reload, .start])
    #expect(manager.saveCount == 1)
    #expect(manager.startCount == 1)
  }

  @Test func descriptorOnlyProviderConfigurationContainsNoSecretOrConfigBytes() throws {
    let descriptor = try tunnelDescriptor()
    let providerConfig = try descriptor.providerConfiguration()

    // Only bounded descriptor identity and network-option keys are persisted.
    let allowedKeys: Set<String> = [
      "schemaVersion", "slot", "installationID", "epoch", "generation",
      "byteCount", "sha256", "identitySha256", "credentialSlots",
      "credentialProfileID", "credentialProfileDigest",
      "ipv6Enabled", "bypassPrivateNetworks", "directIPv4Hosts", "mtu",
    ]
    #expect(Set(providerConfig.keys).isSubset(of: allowedKeys))

    // No value carries raw configuration JSON bytes or secret material.
    let stringValues = providerConfig.values.compactMap { $0 as? String }
    #expect(!stringValues.contains { $0.contains("{") || $0.contains("password") })
  }

  @Test func startOptionsCarryOnlyTheOpaqueTicket() throws {
    let bytes = Data(repeating: 0x7, count: AuthorityV1Limits.ticketBytes)
    let options = NetworkExtensionHostBridge.ticketStartOptions(bytes)

    #expect(options.count == 1)
    #expect(options[NativeProtocolConstants.tunnelStartTicketOptionKey] as? Data == bytes)
    #expect(options[NativeProtocolConstants.tunnelStartPayloadOptionKey] == nil)
  }

  @Test func startReceivesOnlyThePreparedTicketBytes() async throws {
    let recorder = EventRecorder()
    let manager = FakeManagedTunnel(recorder: recorder)
    let descriptor = try tunnelDescriptor()

    try await TicketOnlyTunnelStartFlow.run(
      descriptor: descriptor,
      configuration: Data("{}".utf8),
      credentialPayload: nil,
      preparer: RecordingPreparer(recorder: recorder, ticketByte: 0x9),
      manager: manager)

    #expect(
      manager.startedTicket == Data(repeating: 0x9, count: AuthorityV1Limits.ticketBytes))
  }

  @Test func reloadVerificationRejectsDescriptorMismatchAndDoesNotStart() async throws {
    let recorder = EventRecorder()
    let descriptor = try tunnelDescriptor()
    let mismatched = try tunnelDescriptor(
      sha: String(repeating: "11", count: 32),
      identity: String(repeating: "22", count: 32))
    let manager = FakeManagedTunnel(recorder: recorder, reloadOverride: mismatched)

    await #expect(throws: AppleNetworkError.self) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: descriptor,
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: RecordingPreparer(recorder: recorder),
        manager: manager)
    }
    // Verified mismatch stops the flow before starting the data plane.
    #expect(manager.startCount == 0)
    #expect(recorder.recorded == [.prepare, .save, .reload])
  }

  @Test func hostStartPathExcludesDirectPayloadTransport() throws {
    let source = try hostBridgeSource()
    // The production start path uses only the single-use ticket option key.
    #expect(source.contains("tunnelStartTicketOptionKey"))
    // The temporary direct configuration/credential payload transport is removed.
    #expect(!source.contains("TunnelStartPayloadCodec"))
    #expect(!source.contains("tunnelStartPayloadOptionKey"))
  }
}
