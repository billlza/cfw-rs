import Foundation
import Observation

enum IntegrationStatus: String, Decodable, Sendable {
  case active, inactive, pending, unknown
}

enum OverviewPhase: String, Decodable, Sendable {
  case off, active, changing, approval, failed
}

/// Versioned, bounded presentation supplied by the existing Rust coordinator.
/// No native service, persistent setting or network command is owned by Swift.
struct OverviewFrame: Decodable, Sendable, Equatable {
  let version: UInt32
  let session: UInt64
  let sequence: UInt64
  let locale: String
  let phase: OverviewPhase
  let core: IntegrationStatus
  let systemProxy: IntegrationStatus
  let tunnel: IntegrationStatus
  let failure: String?

  static let maximumBytes = 32_768

  static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= maximumBytes else { throw FrameError.invalidSize }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    guard frame.version == 1 else { throw FrameError.unsupportedVersion }
    guard ["en", "zh-Hans", "zh-Hant", "ja"].contains(frame.locale) else {
      throw FrameError.unsupportedLocale
    }
    guard (frame.phase == .failed) == (frame.failure != nil),
      frame.failure.map({ !$0.isEmpty }) ?? true
    else { throw FrameError.invalidFailure }
    let statuses = [frame.core, frame.systemProxy, frame.tunnel]
    let valid: Bool
    switch frame.phase {
    case .off: valid = statuses.allSatisfy { $0 == .inactive }
    case .active:
      valid = frame.core == .active && statuses.allSatisfy { $0 == .active || $0 == .inactive }
    case .changing, .approval: valid = statuses.allSatisfy { $0 == .pending }
    case .failed: valid = statuses.allSatisfy { $0 == .unknown }
    }
    guard valid else { throw FrameError.inconsistentState }
    return frame
  }
}

enum FrameError: Error {
  case invalidSize, unsupportedVersion, unsupportedLocale, invalidFailure, staleFrame, staleSession,
    inconsistentState
}

@MainActor @Observable
final class OverviewModel {
  private(set) var frame: OverviewFrame?
  private(set) var deliveryFailure = false

  func accept(_ frame: OverviewFrame) throws {
    if let current = self.frame {
      guard frame.session == current.session else { throw FrameError.staleSession }
      guard frame.sequence > current.sequence else { throw FrameError.staleFrame }
    }
    self.frame = frame
    deliveryFailure = false
  }

  func beginSession(_ frame: OverviewFrame) throws {
    // A prior observer may have published a later sequence while this open
    // waited for the main thread. Sequence order applies within a session;
    // only the session identifier orders complete observer replacements.
    if let current = self.frame, frame.session <= current.session { throw FrameError.staleSession }
    self.frame = frame
    deliveryFailure = false
  }

  func rejectDelivery() { deliveryFailure = true }
}
