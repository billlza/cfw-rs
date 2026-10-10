import Foundation
import Observation

enum IntegrationStatus: String, Decodable, Sendable {
  case active, inactive, pending, unknown
}

enum OverviewPhase: String, Decodable, Sendable {
  case off, active, changing, approval, failed
}

enum NativeControl: UInt32, CaseIterable, Sendable {
  case core = 1
  case systemProxy = 2
  case tunnel = 3
}

struct ControlSwitch: Decodable, Sendable, Equatable {
  let enabled: Bool
  let available: Bool
  let retry: Bool
  let reason: String?
}

struct OverviewControls: Decodable, Sendable, Equatable {
  let core: ControlSwitch
  let systemProxy: ControlSwitch
  let tunnel: ControlSwitch

  func value(for control: NativeControl) -> ControlSwitch {
    switch control {
    case .core: core
    case .systemProxy: systemProxy
    case .tunnel: tunnel
    }
  }
}

struct ControlCompletion: Decodable, Sendable, Equatable {
  let requestId: UInt64
  let pending: Bool
  let error: String?
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
  let controls: OverviewControls
  let command: ControlCompletion?

  static let maximumBytes = 32_768

  static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= maximumBytes else { throw FrameError.invalidSize }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    guard frame.version == 2 else { throw FrameError.unsupportedVersion }
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
    for control in NativeControl.allCases {
      let value = frame.controls.value(for: control)
      guard value.available == (value.reason == nil), value.reason.map({ !$0.isEmpty }) ?? true,
        !value.retry || (value.enabled && value.available)
      else { throw FrameError.inconsistentControl }
    }
    if let command = frame.command {
      guard command.requestId > 0, !command.pending || command.error == nil,
        command.error.map({ !$0.isEmpty }) ?? true
      else { throw FrameError.inconsistentControl }
    }
    return frame
  }
}

enum FrameError: Error {
  case invalidSize, unsupportedVersion, unsupportedLocale, invalidFailure, staleFrame, staleSession,
    inconsistentState, inconsistentControl
}

@MainActor @Observable
final class OverviewModel {
  private(set) var frame: OverviewFrame?
  private(set) var deliveryFailure = false
  private(set) var pendingRequest: UInt64?
  private(set) var actionError: String?
  @ObservationIgnored private var nextRequest: UInt64 = 1
  @ObservationIgnored private var submit: ((UInt64, UInt64, UInt64, NativeControl, Bool) -> Int32)?

  func accept(_ frame: OverviewFrame) throws {
    if let current = self.frame {
      guard frame.session == current.session else { throw FrameError.staleSession }
      guard frame.sequence > current.sequence else { throw FrameError.staleFrame }
    }
    self.frame = frame
    deliveryFailure = false
    if let command = frame.command, command.requestId == pendingRequest, !command.pending {
      pendingRequest = nil
      actionError = command.error
    }
  }

  func beginSession(_ frame: OverviewFrame) throws {
    // A prior observer may have published a later sequence while this open
    // waited for the main thread. Sequence order applies within a session;
    // only the session identifier orders complete observer replacements.
    if let current = self.frame, frame.session <= current.session { throw FrameError.staleSession }
    self.frame = frame
    deliveryFailure = false
    pendingRequest = nil
    actionError = nil
    nextRequest = 1
    submit = nil
  }

  func rejectDelivery() { deliveryFailure = true }

  func bindControl(_ submit: @escaping (UInt64, UInt64, UInt64, NativeControl, Bool) -> Int32) {
    self.submit = submit
  }

  func disconnect() {
    submit = nil
    pendingRequest = nil
  }

  func canSubmit(_ control: NativeControl) -> Bool {
    submit != nil && !deliveryFailure && pendingRequest == nil
      && frame?.controls.value(for: control).available == true
      && frame?.command?.pending != true
  }

  @discardableResult
  func request(_ control: NativeControl, enabled: Bool) -> Int32 {
    if pendingRequest != nil || frame?.command?.pending == true { return 4 }
    guard canSubmit(control), let frame, let submit,
      frame.controls.value(for: control).enabled != enabled
        || (enabled && frame.controls.value(for: control).retry)
    else { return 0 }
    let id = nextRequest
    let increment = id.addingReportingOverflow(1)
    guard !increment.overflow else {
      actionError = DashboardStrings.text("requestRejected", locale: frame.locale)
      return 0
    }
    nextRequest = increment.partialValue
    pendingRequest = id
    actionError = nil
    let status = submit(frame.session, frame.sequence, id, control, enabled)
    if status != 1 {
      pendingRequest = nil
      actionError = DashboardStrings.text(
        status == 4 ? "anotherChangePending" : "requestRejected", locale: frame.locale)
    }
    return status
  }
}
