import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// Integration coverage for task 9.12 (Host): operation-scoped cancellation and
// stale/late isolation across the ordered ticket-only Tunnel start flow, plus the
// absence of any direct configuration/credential payload fallback. Every
// Authority/NetworkExtension side effect lives behind an injected in-memory seam,
// so no real Authority, XPC, or NetworkExtension is exercised.
//
// The ordered flow is: (1) prepare with the Authority, (2) save descriptor-only
// preferences, (3) reload and verify the exact descriptor, (4) start with only the
// single-use ticket. Cancellation at any checkpoint must abort BEFORE the next
// side effect and must never start the data plane after preferences were saved.

private enum HostFlowTestError: Error { case forcedStartFailure }

/// Throws `CancellationError` on exactly the Nth `checkCancellation()` invocation.
/// The flow checks cancellation at four ordered checkpoints:
///   1 = before prepare, 2 = after prepare/before save,
///   3 = after save/before reload, 4 = after reload/before start.
private final class CancelAtCheckpoint: @unchecked Sendable {
  private let lock = NSLock()
  private let target: Int
  private var count = 0

  init(target: Int) { self.target = target }

  var checkCancellation: @Sendable () throws -> Void {
    {
      let shouldThrow = self.lock.withLock { () -> Bool in
        self.count += 1
        return self.count == self.target
      }
      if shouldThrow { throw CancellationError() }
    }
  }
}

private final class RecordingPreparer: TunnelStartPreparing, @unchecked Sendable {
  private let lock = NSLock()
  private let ticketByte: UInt8
  private var preparationsValue: [HostTunnelStartPreparation] = []

  init(ticketByte: UInt8 = 0x5) { self.ticketByte = ticketByte }

  var preparations: [HostTunnelStartPreparation] { lock.withLock { preparationsValue } }

  func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart {
    lock.withLock { preparationsValue.append(preparation) }
    let ticket = try StartTicket(
      copying: Data(repeating: ticketByte, count: AuthorityV1Limits.ticketBytes))
    return HostPreparedTunnelStart(ticket: ticket, descriptor: preparation.descriptor)
  }
}

private final class RecordingManagedTunnel: ManagedTunnelOperating, @unchecked Sendable {
  enum Event: Equatable { case save, reload, start }

  private let lock = NSLock()
  private let startThrows: Bool
  private var savedDescriptor: ConfigurationDescriptor?
  private var log: [Event] = []
  private var startedTicketValue: Data?

  init(startThrows: Bool = false) { self.startThrows = startThrows }

  var events: [Event] { lock.withLock { log } }
  var startedTicket: Data? { lock.withLock { startedTicketValue } }

  func saveDescriptorOnly(_ descriptor: ConfigurationDescriptor) async throws {
    lock.withLock {
      log.append(.save)
      savedDescriptor = descriptor
    }
  }

  func reloadDescriptor() async throws -> ConfigurationDescriptor {
    lock.withLock {
      log.append(.reload)
      return savedDescriptor!
    }
  }

  func startWithTicket(_ ticketBytes: Data) async throws {
    let shouldThrow = lock.withLock { () -> Bool in
      log.append(.start)
      startedTicketValue = ticketBytes
      return startThrows
    }
    if shouldThrow { throw HostFlowTestError.forcedStartFailure }
  }
}

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "cd", count: 32)))
}

@Suite(.serialized)
struct HostTicketOnlyStartCancellationTests {
  @Test func cancellationBeforePrepareTouchesNothing() async throws {
    let preparer = RecordingPreparer()
    let manager = RecordingManagedTunnel()
    let cancel = CancelAtCheckpoint(target: 1)

    await #expect(throws: CancellationError.self) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: try tunnelDescriptor(),
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: preparer,
        manager: manager,
        checkCancellation: cancel.checkCancellation)
    }
    #expect(preparer.preparations.isEmpty)
    #expect(manager.events.isEmpty)
  }

  @Test func cancellationAfterPrepareDoesNotSavePreferences() async throws {
    let preparer = RecordingPreparer()
    let manager = RecordingManagedTunnel()
    let cancel = CancelAtCheckpoint(target: 2)

    await #expect(throws: CancellationError.self) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: try tunnelDescriptor(),
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: preparer,
        manager: manager,
        checkCancellation: cancel.checkCancellation)
    }
    // The Authority prepared, but no preference or network mutation happened.
    #expect(preparer.preparations.count == 1)
    #expect(manager.events.isEmpty)
  }

  @Test func cancellationAfterSaveNeverStartsTheDataPlane() async throws {
    let preparer = RecordingPreparer()
    let manager = RecordingManagedTunnel()
    let cancel = CancelAtCheckpoint(target: 3)

    await #expect(throws: CancellationError.self) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: try tunnelDescriptor(),
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: preparer,
        manager: manager,
        checkCancellation: cancel.checkCancellation)
    }
    // Preferences were saved (a committed external mutation), but the reload and
    // the data-plane start are skipped: cancellation after save never starts.
    #expect(manager.events == [.save])
    #expect(manager.startedTicket == nil)
  }

  @Test func cancellationAfterReloadNeverStartsTheDataPlane() async throws {
    let preparer = RecordingPreparer()
    let manager = RecordingManagedTunnel()
    let cancel = CancelAtCheckpoint(target: 4)

    await #expect(throws: CancellationError.self) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: try tunnelDescriptor(),
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: preparer,
        manager: manager,
        checkCancellation: cancel.checkCancellation)
    }
    #expect(manager.events == [.save, .reload])
    #expect(manager.startedTicket == nil)
  }

  @Test func startFailureSurfacesWithoutFallback() async throws {
    let preparer = RecordingPreparer()
    let manager = RecordingManagedTunnel(startThrows: true)

    await #expect(throws: HostFlowTestError.forcedStartFailure) {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: try tunnelDescriptor(),
        configuration: Data("{}".utf8),
        credentialPayload: nil,
        preparer: preparer,
        manager: manager,
        checkCancellation: {})
    }
    // The ordered flow ran fully to the ticket-only start and surfaced the failure
    // with no direct-payload or alternate-mode fallback.
    #expect(manager.events == [.save, .reload, .start])
  }

  @Test func credentialPayloadGoesOnlyToAuthorityAndNeverToStart() async throws {
    let preparer = RecordingPreparer(ticketByte: 0x9)
    let manager = RecordingManagedTunnel()
    let credentialPayload = Data("s3cr3t-credentials".utf8)

    try await TicketOnlyTunnelStartFlow.run(
      descriptor: try tunnelDescriptor(),
      configuration: Data("{\"outbounds\":[]}".utf8),
      credentialPayload: credentialPayload,
      preparer: preparer,
      manager: manager,
      checkCancellation: {})

    // The credential payload is handed to the Authority preparation only.
    #expect(preparer.preparations.first?.credentialPayload == credentialPayload)
    // The data-plane start receives ONLY the opaque single-use ticket: no
    // configuration or credential bytes are forwarded through the start path.
    let ticketBytes = try #require(manager.startedTicket)
    #expect(ticketBytes == Data(repeating: 0x9, count: AuthorityV1Limits.ticketBytes))
    #expect(ticketBytes != credentialPayload)
    #expect(!ticketBytes.elementsEqual(credentialPayload))
  }
}
