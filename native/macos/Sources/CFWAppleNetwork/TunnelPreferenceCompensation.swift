import CFWSharedProtocol
import Foundation

/// The exact `NEVPNStatus`-equivalent connection states the compensation flow
/// reasons about, mirrored behind a seam so the ordered compensation is exercised
/// with an in-memory fake and no real NetworkExtension.
public enum ManagedTunnelConnectionStatus: Equatable, Sendable {
  case invalid
  case disconnected
  case connecting
  case connected
  case reasserting
  case disconnecting

  /// The connection may still be routing packets and must be stopped before the
  /// managed manager is restored or removed.
  public var mayBeActive: Bool {
    switch self {
    case .connecting, .connected, .reasserting, .disconnecting:
      return true
    case .invalid, .disconnected:
      return false
    }
  }

  /// The OS has proven the connection is not routing: `disconnected` or `invalid`.
  public var isStopped: Bool {
    switch self {
    case .disconnected, .invalid:
      return true
    case .connecting, .connected, .reasserting, .disconnecting:
      return false
    }
  }
}

/// Bounded, non-secret snapshot of the exact `NETunnelProviderManager` preference
/// values one operation may write or restore. Only the descriptor-only provider
/// configuration identity, the enabled flag, and the localized description are
/// captured; configuration and credential bytes are never present. `Equatable` so
/// compensation can prove current values still equal this operation's written
/// values before restoring, and never overwrite an external/administrator change.
public struct ManagedTunnelPreferenceValues: Equatable, Sendable {
  public let descriptor: ConfigurationDescriptor
  public let isEnabled: Bool
  public let localizedDescription: String?

  public init(
    descriptor: ConfigurationDescriptor,
    isEnabled: Bool,
    localizedDescription: String?
  ) {
    self.descriptor = descriptor
    self.isEnabled = isEnabled
    self.localizedDescription = localizedDescription
  }
}

/// The in-memory record the Host stages BEFORE mutating `NETunnelProviderManager`.
///
/// It records whether this operation created the manager, the prior bounded values
/// (absent when the operation created the manager), and the exact values written.
/// It holds no secret or configuration bytes and is never serialized. Compensation
/// uses it to compare-and-restore: only when the current values still equal
/// `writtenValues` does it restore `priorValues` or remove a created manager.
public struct PreferenceMutationReceipt: Equatable, Sendable {
  public let operationID: UUID
  public let createdManager: Bool
  public let priorValues: ManagedTunnelPreferenceValues?
  public let writtenValues: ManagedTunnelPreferenceValues

  public init(
    operationID: UUID,
    createdManager: Bool,
    priorValues: ManagedTunnelPreferenceValues?,
    writtenValues: ManagedTunnelPreferenceValues
  ) {
    self.operationID = operationID
    self.createdManager = createdManager
    self.priorValues = priorValues
    self.writtenValues = writtenValues
  }

  /// The identity digest of the exact descriptor this operation wrote, per the
  /// design's `PreferenceMutationReceipt { ... writtenDescriptorSHA256 }` model.
  public var writtenDescriptorSHA256: SHA256Digest { writtenValues.descriptor.identitySHA256 }

  /// The bounded values compensation expects to observe after a successful
  /// restore: `nil` (no manager) when this operation created the manager,
  /// otherwise the prior values.
  public var expectedRestoredValues: ManagedTunnelPreferenceValues? {
    createdManager ? nil : priorValues
  }
}

/// Injectable seam over the exact managed-manager preference operations the
/// ownership-sensitive compensation needs. Extracted so the ordered compensation
/// is exercised with an in-memory fake requiring no real NetworkExtension. Reads
/// reflect the durable preference store so compare-and-restore observes external
/// or administrator changes.
public protocol ManagedTunnelPreferences: Sendable {
  /// Reloads from preferences and returns the current bounded values, or `nil`
  /// when no product-owned managed manager currently exists.
  func loadCurrentValues() async throws -> ManagedTunnelPreferenceValues?
  /// The current managed connection status, used for the bounded stop decision
  /// and the final OS Off proof.
  func connectionStatus() async throws -> ManagedTunnelConnectionStatus
  /// Requests the OS to stop the managed tunnel connection.
  func stop() async throws
  /// Restores the prior bounded values to the managed manager and saves them.
  func apply(_ values: ManagedTunnelPreferenceValues) async throws
  /// Removes the product-owned managed manager entirely.
  func removeManager() async throws
}

/// Injectable seam over the Authority revocation step of compensation. The
/// implementation atomically revokes this operation's ticket/lease and zeroizes
/// the Authority-retained secret buffers. Kept behind a seam so compensation runs
/// deterministically without a real Authority XPC channel.
public protocol AuthorityPreparationRevoking: Sendable {
  func revokePreparation() async throws
}

/// Ordered, ownership-sensitive Tunnel preference compensation.
///
/// After a successful `NETunnelProviderManager` save, any of {cancellation before
/// start submission, reload mismatch, ticket expiry, synchronous start failure,
/// Provider rejection, readiness timeout, Authority revocation} runs the design's
/// ordered compensation:
///
///  1. Authority atomically revokes the ticket/lease and zeroizes retained secret
///     buffers.
///  2. Stop the connection if it may be connecting/connected and wait boundedly
///     for `disconnected`/`invalid`.
///  3. Reload preferences and compare-and-restore: only when the current values
///     still equal this operation's written values does it restore the prior
///     manager, or remove a manager this operation created. An external or
///     administrator change (mismatch) is never overwritten.
///  4. Save, reload, and verify the compensation result.
///  5. Require OS Off proof before the result is treated as Off.
///
/// A comparison conflict returns `compensationConflict`; a cleanup timeout or an
/// unverifiable result returns `cleanupUnproven`; either leaves the machine
/// Quarantined. The secret eraser runs on every path (success, conflict, timeout,
/// thrown error). The previous mode is never restarted.
public enum TunnelPreferenceCompensation {
  /// Bounded-wait policy for the stop step. Defaults to five seconds of 100 ms
  /// polls, matching the Host's other bounded NE waits; tests inject a no-op sleep
  /// and a small budget for determinism.
  public struct StopWaitPolicy: Sendable {
    public let maximumPolls: Int
    public let sleep: @Sendable () async throws -> Void

    public init(
      maximumPolls: Int = 50,
      sleep: @escaping @Sendable () async throws -> Void = {
        try await Task.sleep(for: .milliseconds(100))
      }
    ) {
      self.maximumPolls = max(1, maximumPolls)
      self.sleep = sleep
    }
  }

  public static func run(
    receipt: PreferenceMutationReceipt,
    authority: any AuthorityPreparationRevoking,
    preferences: any ManagedTunnelPreferences,
    secretEraser: @escaping @Sendable () -> Void = {},
    stopWait: StopWaitPolicy = StopWaitPolicy()
  ) async throws {
    let eraser = OneShotEraser(secretEraser)
    // Terminal secret erasure on EVERY path: success, conflict, timeout, or a
    // thrown error all run the eraser exactly once.
    defer { eraser.erase() }

    // (1) Authority atomically revokes the ticket/lease and zeroizes retained
    // secret buffers. Host-owned buffers are erased immediately afterward.
    try await authority.revokePreparation()
    eraser.erase()

    // (2) Stop a possibly connecting/connected Tunnel and wait boundedly for the
    // OS to prove disconnected/invalid. A cleanup timeout leaves Quarantined.
    let status = try await preferences.connectionStatus()
    if status.mayBeActive {
      try await preferences.stop()
      var polls = 0
      while true {
        if try await preferences.connectionStatus().isStopped { break }
        polls += 1
        guard polls < stopWait.maximumPolls else {
          throw AppleNetworkError.cleanupUnproven(
            "Managed tunnel did not reach a disconnected state within the bounded stop wait."
          )
        }
        try await stopWait.sleep()
      }
    }

    // (3) Reload and compare-and-restore ONLY when the current values still equal
    // this operation's written values. Any external/administrator change is a
    // conflict and is never overwritten.
    let current = try await preferences.loadCurrentValues()
    guard current == receipt.writtenValues else {
      throw AppleNetworkError.compensationConflict(
        "Managed tunnel preferences changed externally; compensation refuses to overwrite them."
      )
    }
    if receipt.createdManager {
      try await preferences.removeManager()
    } else {
      guard let prior = receipt.priorValues else {
        throw AppleNetworkError.compensationConflict(
          "Compensation receipt is missing the prior values required to restore the manager."
        )
      }
      try await preferences.apply(prior)
    }

    // (4) Save, reload, and verify the compensation result matches the expected
    // restored state exactly. An unverifiable result leaves Quarantined.
    let restored = try await preferences.loadCurrentValues()
    guard restored == receipt.expectedRestoredValues else {
      throw AppleNetworkError.cleanupUnproven(
        "Compensation result did not match the expected restored preferences."
      )
    }

    // (5) Require OS Off proof before the compensated result is treated as Off.
    guard try await preferences.connectionStatus().isStopped else {
      throw AppleNetworkError.cleanupUnproven(
        "Managed tunnel connection is not proven Off after compensation."
      )
    }
  }
}

/// Runs a secret-erasure closure at most once regardless of how many terminal
/// paths reach it, so compensation can invoke it eagerly after revocation and
/// again from the outer `defer` without double-wiping already-cleared buffers.
private final class OneShotEraser: @unchecked Sendable {
  private let lock = NSLock()
  private var erased = false
  private let body: @Sendable () -> Void

  init(_ body: @escaping @Sendable () -> Void) { self.body = body }

  func erase() {
    let shouldRun = lock.withLock {
      guard !erased else { return false }
      erased = true
      return true
    }
    if shouldRun { body() }
  }
}
