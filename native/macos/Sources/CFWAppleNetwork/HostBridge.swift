import CFWSharedProtocol
import Foundation

/// Bounded, non-secret inputs the Host hands to the Global Authority when it
/// prepares a Tunnel start. The configuration and credential bytes travel to the
/// Authority over its typed XPC prepare call and are never written to preferences
/// or `NETunnelProviderSession.startTunnel(options:)`.
public struct HostTunnelStartPreparation: Sendable {
  public let descriptor: ConfigurationDescriptor
  public let configuration: Data
  public let credentialPayload: Data?

  public init(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?
  ) {
    self.descriptor = descriptor
    self.configuration = configuration
    self.credentialPayload = credentialPayload
  }
}

/// The single-use opaque Start Ticket, bounded non-secret descriptor, and exact
/// Authority operation identity. No configuration or credential bytes are
/// returned to the Host.
public struct HostPreparedTunnelStart: Sendable {
  public let ticket: StartTicket
  public let descriptor: ConfigurationDescriptor
  public let operationID: UUID

  public init(
    ticket: StartTicket,
    descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) {
    self.ticket = ticket
    self.descriptor = descriptor
    self.operationID = operationID
  }
}

/// Injectable seam over the Global Authority prepare step. Implementations must
/// prepare with the Authority BEFORE any preference or network mutation and fail
/// closed with a typed Authority error when the Authority is unavailable or
/// unproven. There is no direct configuration/credential payload fallback.
public protocol TunnelStartPreparing: Sendable {
  func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart
}

/// Default production preparer used until the authenticated Host→Authority XPC
/// client is wired end to end. It fails closed so no Tunnel start can proceed
/// without a real Authority preparation and single-use ticket.
public struct FailClosedTunnelStartPreparer: TunnelStartPreparing {
  public init() {}

  public func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart {
    throw AppleNetworkError.globalAuthorityUnavailable
  }
}

/// Injectable seam over the exact `NETunnelProviderManager` operations the
/// ticket-only start flow needs. Extracted so the flow is exercised with an
/// in-memory fake and requires no real NetworkExtension in tests.
protocol ManagedTunnelOperating: Sendable {
  /// Persists ONLY the descriptor-only preference contract to the managed
  /// manager, creating it when absent and explicitly disabling/clearing VPN On
  /// Demand. No configuration, credential, or on-demand rule bytes are written.
  func saveDescriptorOnly(
    _ descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) async throws
  /// Reloads the managed manager from preferences, verifies every bounded value
  /// against the durable receipt, and returns its descriptor.
  func reloadDescriptor() async throws -> ConfigurationDescriptor
  /// Starts the managed tunnel connection with ONLY the one-use start ticket.
  func startWithTicket(_ ticketBytes: Data) async throws
}

/// Ordered ticket-only Tunnel start: prepare with the Authority before any
/// preference mutation, save the descriptor-only manager, reload and verify the
/// exact bounded preference values, then start with only the single-use ticket.
/// Every Authority, XPC, and NetworkExtension side effect lives behind an
/// injected seam.
enum TicketOnlyTunnelStartFlow {
  static func run(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?,
    preparer: any TunnelStartPreparing,
    manager: any ManagedTunnelOperating,
    checkCancellation: @Sendable () throws -> Void = { try Task.checkCancellation() }
  ) async throws {
    try checkCancellation()
    guard descriptor.slot == .tunnel else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    // (1) Prepare with the Global Authority BEFORE any preference mutation. This
    // yields the single-use opaque ticket and the bounded non-secret descriptor.
    let prepared = try await preparer.prepareTunnelStart(
      HostTunnelStartPreparation(
        descriptor: descriptor,
        configuration: configuration,
        credentialPayload: credentialPayload
      )
    )
    let ticket = prepared.ticket
    defer { ticket.erase() }
    let preparedDescriptor = prepared.descriptor
    guard preparedDescriptor.slot == .tunnel else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    try checkCancellation()

    // (2) Save only the descriptor-only provider configuration.
    try await manager.saveDescriptorOnly(
      preparedDescriptor,
      operationID: prepared.operationID)
    // Saving preferences is a committed external mutation and cannot be canceled
    // through NetworkExtension. Honor cancellation before reloading and, critically,
    // before starting the data plane.
    try checkCancellation()

    // (3) Reload and verify the exact bounded managed-manager round trip.
    let reloaded = try await manager.reloadDescriptor()
    guard reloaded == preparedDescriptor else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "Reloaded managed tunnel descriptor does not match the prepared descriptor."
      )
    }
    try checkCancellation()

    // (4) Start with ONLY the one-use ticket. No configuration or credential bytes.
    var ticketBytes = try ticket.withUnsafeBytes { Data($0) }
    defer { ticketBytes.resetBytes(in: ticketBytes.startIndex..<ticketBytes.endIndex) }
    try await manager.startWithTicket(ticketBytes)
  }
}

public protocol TunnelHostBridging: Sendable {
  func installTunnel() async throws -> SystemExtensionInstallResult
  /// Waits for the answer to the approval that `installTunnel()` reported as
  /// awaited; see `SystemExtensionInstalling.awaitApprovalResolution()`.
  func awaitTunnelInstallationApproval() async throws -> SystemExtensionApprovalWait
  func cancelTunnelInstallationWait() async
  /// Obtains the first VPN-configuration consent using a disabled, descriptor-only
  /// manager. No Authority lease, start ticket or credential material is involved.
  func authorizeTunnelConfiguration(_ descriptor: ConfigurationDescriptor) async throws
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) async throws
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  /// Public NetworkExtension state used only by the Global Authority restart
  /// reconciliation barrier. Unknown or transitional values must not prove Off.
  func recoveryManagedTunnelStatus() async throws -> RecoveryManagedTunnelStatus
  func hasManagedTunnelConfiguration() async throws -> Bool
  func managedTunnelConfiguration() async throws -> ConfigurationDescriptor?
  /// Returns the exact durable write-ahead descriptor recovered at Host startup.
  /// A non-nil value blocks every new native mutation until compensation succeeds.
  func pendingPreferenceMutationConfiguration() async throws -> ConfigurationDescriptor?
  /// Revokes or stop-orders the exact Authority generation and compare-and-
  /// restores/removes its durable manager. This step deliberately retains the
  /// write-ahead receipt.
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool
  /// Clears an idempotently compensated receipt only after a final fresh reload
  /// proves the exact prior/nil state and OS Off.
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws
  /// Commits a successful start only after the durable manager and connected
  /// runtime still match the exact write-ahead receipt.
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws
}

extension TunnelHostBridging {
  public func recoveryManagedTunnelStatus() async throws -> RecoveryManagedTunnelStatus {
    .unknown
  }
}
