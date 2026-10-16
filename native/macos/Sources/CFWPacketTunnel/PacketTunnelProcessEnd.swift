import CFWLibboxRuntime
import Darwin
import Dispatch
import OSLog
import Synchronization

/// Ends the extension's process after libbox could not close a runtime: only the
/// process ending releases what that close left open. Network Extension removes
/// the tunnel's routes, DNS and proxy settings with the session and launches the
/// extension again for the next start.
///
/// Network Extension offers no barrier for the provider's completions, so the
/// end waits for its acknowledgement instead: Network Extension asks the
/// provider to stop only after it received the failure the provider reported,
/// or the cancel that followed it, so the extension ends once it answered the
/// first stop after the failure. A failure inside a stop Network Extension
/// already asked for is reported with that stop's answer, which is the last
/// thing the extension sends; Network Extension takes the ended process for a
/// stopped one. When no stop comes, as may happen after a failed start, the
/// extension ends `stopWait` after the failure. That wait runs from the
/// failure whether or not a stop is on its way, so a report Network Extension
/// has not received by then ends with the process. From the failure on, no
/// start in this process runs libbox again.
final class PacketTunnelProcessEnd: Sendable {
  typealias Schedule = @Sendable (DispatchTime, @escaping @Sendable () -> Void) -> Void

  /// How long a spent extension waits for Network Extension to stop it.
  static let stopWait: DispatchTimeInterval = .seconds(2)

  /// The extension's own; `_exit` skips atexit handlers while libbox's threads
  /// still run.
  static let shared = PacketTunnelProcessEnd(
    now: { .now() },
    schedule: { deadline, work in
      DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: deadline, execute: work)
    },
    exit: { _exit($0) })

  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "packet-tunnel"
  )

  private enum Phase {
    case running
    case spent(LibboxInstanceUnclosable)
    case ending(LibboxInstanceUnclosable)
  }

  private let phase = Mutex(Phase.running)
  private let now: @Sendable () -> DispatchTime
  private let schedule: Schedule
  private let exit: @Sendable (Int32) -> Void

  init(
    now: @escaping @Sendable () -> DispatchTime,
    schedule: @escaping Schedule,
    exit: @escaping @Sendable (Int32) -> Void
  ) {
    self.now = now
    self.schedule = schedule
    self.exit = exit
  }

  /// The failure that keeps this process from running libbox again, if any.
  var spentFailure: LibboxInstanceUnclosable? {
    phase.withLock { phase in
      switch phase {
      case .running: nil
      case .spent(let failure), .ending(let failure): failure
      }
    }
  }

  /// libbox could not close a runtime. The provider calls this before it
  /// completes anything with the failure; only the first failure counts. Its
  /// text is never logged.
  func spent(_ failure: LibboxInstanceUnclosable) {
    let first = phase.withLock { phase -> Bool in
      guard case .running = phase else { return false }
      phase = .spent(failure)
      return true
    }
    guard first else { return }
    Self.logger.fault(
      "libbox could not close the tunnel runtime; ending the extension once it is stopped")
    schedule(now() + Self.stopWait) { [self] in
      if end() {
        Self.logger.fault("Network Extension did not stop the spent tunnel; ending the extension")
      }
    }
  }

  /// The provider answered a stop Network Extension asked for. After a failure,
  /// Network Extension has received everything the provider reported, so the
  /// extension ends once this answer's callback has returned.
  func networkExtensionStopAnswered() {
    let ends = phase.withLock { phase -> Bool in
      guard case .spent = phase else { return false }
      return true
    }
    guard ends else { return }
    schedule(now()) { [self] in
      end()
    }
  }

  /// Ends the process unless it is already ending; returns whether this call
  /// ended it.
  @discardableResult
  private func end() -> Bool {
    let ends = phase.withLock { phase -> Bool in
      guard case .spent(let failure) = phase else { return false }
      phase = .ending(failure)
      return true
    }
    if ends {
      exit(EX_SOFTWARE)
    }
    return ends
  }
}
