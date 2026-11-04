import CFWSharedProtocol
import Foundation

/// Monotonic time source for provider attestations. Injected so tests can
/// assert exact readiness/stopped timestamps without a real clock.
protocol ProviderMonotonicClock: Sendable {
  func nowMilliseconds() -> UInt64
}

struct SystemProviderMonotonicClock: ProviderMonotonicClock {
  func nowMilliseconds() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds / 1_000_000
  }
}

/// Local engine lease that grants no machine-wide authority. The Global Authority
/// owns the single machine lease under the ticket-only model, so the Provider must
/// never construct `CrossProcessEngineLeaseStore` in its Release start path.
final class UnleasedEngineOwnership: EngineLeaseHolding, @unchecked Sendable {
  func release() throws {}
}

final class TunnelRevocationChannel: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?

  func onRevoke(_ handler: @escaping @Sendable () -> Void) {
    lock.withLock { self.handler = handler }
  }

  func revoke() {
    let handler = lock.withLock { self.handler }
    handler?()
  }
}

/// Bounds reported in the ready attestation. They mirror the production packet pump
/// so the Authority's readiness proof matches the transport that is actually running.
enum ProviderPacketPumpLimits {
  static let maximumQueuedPackets: UInt16 = 1_024
  static let maximumQueuedBytes: UInt32 = 4 * 1_048_576
  static let maximumReadBatch: UInt8 = 64

  static func attestation(mtu: UInt16) throws -> PacketPumpLimits {
    try PacketPumpLimits(
      maximumQueuedPackets: maximumQueuedPackets,
      maximumQueuedBytes: maximumQueuedBytes,
      maximumPacketBytes: mtu,
      maximumReadBatch: maximumReadBatch
    )
  }
}
