import AppKit
import Observation
import SwiftUI

public typealias PromptDialogEventCallback =
  @convention(c) (UInt, UInt64, UnsafePointer<UInt8>?, Int) -> Int32
public typealias PromptDialogClosedCallback = @convention(c) (UInt, UInt64) -> Void

struct PromptDialogFrame: Decodable {
  struct Button: Decodable, Identifiable {
    enum Role: String, Decodable { case cancel, `default`, destructive }
    let id: String
    let title: String
    let role: Role
  }

  static let maximumBytes = 16 * 1024
  static let maximumCounter: UInt64 = 9_007_199_254_740_991
  private static let requiredKeys: Set<String> = [
    "version", "session", "sequence", "acknowledgedSubmission", "windowNumber", "locale",
    "appearance", "title", "message", "buttons", "transportFailure",
  ]
  let version: UInt32
  let session: UInt64
  let sequence: UInt64
  let acknowledgedSubmission: UInt64
  let windowNumber: Int
  let locale: String
  let appearance: RuntimeSettingsFrame.Appearance
  let title: String
  let message: String
  let buttons: [Button]
  let transportFailure: String

  static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= maximumBytes,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys) == requiredKeys,
      let buttons = object["buttons"] as? [[String: Any]],
      buttons.allSatisfy({ Set($0.keys) == ["id", "title", "role"] })
    else { throw InvalidFrame.invalid }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    guard frame.version == 1, frame.session > 0,
      frame.sequence > 0, frame.sequence <= maximumCounter,
      frame.acknowledgedSubmission <= maximumCounter, frame.windowNumber > 0,
      ["en", "zh-Hans", "zh-Hant", "ja"].contains(frame.locale),
      isBounded(frame.title, 160), frame.message.unicodeScalars.count <= 4096,
      isBounded(frame.transportFailure, 1024),
      (1...3).contains(frame.buttons.count), frame.buttons[0].role == .cancel,
      frame.buttons.dropFirst().allSatisfy({ $0.role != .cancel }),
      Set(frame.buttons.map(\.id)).count == frame.buttons.count,
      frame.buttons.allSatisfy({ isFrameIdentifier($0.id) && isBounded($0.title, 160) })
    else { throw InvalidFrame.invalid }
    return frame
  }
  enum InvalidFrame: Error { case invalid }

  private static func isBounded(_ text: String, _ maximum: Int) -> Bool {
    !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      && text.unicodeScalars.count <= maximum
  }

}

/// The prompt owns no decision. It reports which button was chosen and keeps
/// its actions unavailable until the host acknowledges that activation.
/// Cancelling stays available throughout, as in the page's dialogs.
@MainActor @Observable
final class PromptDialogModel {
  private(set) var frame: PromptDialogFrame
  private(set) var pendingSubmissionId: UInt64?
  private(set) var submissionCount: UInt64 = 0
  /// The frame's transport-failure line, after an activation the host did not take.
  private(set) var failure: String?
  private(set) var closed = false
  @ObservationIgnored private var event: PromptDialogEventCallback?
  @ObservationIgnored private var onClosed: PromptDialogClosedCallback?
  @ObservationIgnored private let context: UInt

  init(
    _ frame: PromptDialogFrame, event: @escaping PromptDialogEventCallback,
    closed: @escaping PromptDialogClosedCallback, context: UInt
  ) {
    self.frame = frame
    self.event = event
    onClosed = closed
    self.context = context
  }

  /// An activation the host has not acknowledged yet.
  var pending: Bool { pendingSubmissionId != nil }

  /// The cancel button stays available while an action runs; the actions do not.
  func available(_ button: PromptDialogFrame.Button) -> Bool {
    !closed && (button.role == .cancel || !pending)
  }

  func update(_ next: PromptDialogFrame) -> Int32 {
    guard !closed, next.session == frame.session else { return 2 }
    guard next.sequence > frame.sequence, next.windowNumber == frame.windowNumber,
      next.acknowledgedSubmission >= frame.acknowledgedSubmission,
      next.acknowledgedSubmission <= submissionCount
    else { return 0 }
    frame = next
    if next.acknowledgedSubmission == pendingSubmissionId { pendingSubmissionId = nil }
    return 1
  }

  static func nextSubmission(after value: UInt64) -> UInt64? {
    value < PromptDialogFrame.maximumCounter ? value + 1 : nil
  }

  /// Cancel is not an activation: it only closes the panel.
  @discardableResult func activate(_ buttonId: String) -> Int32 {
    guard !closed else { return 2 }
    guard !pending, let event,
      frame.buttons.contains(where: { $0.id == buttonId && $0.role != .cancel })
    else { return 0 }
    guard let submissionId = Self.nextSubmission(after: submissionCount) else {
      failure = frame.transportFailure
      return 0
    }
    struct Activation: Encodable {
      let action = "activate"
      let submissionId: UInt64
      let buttonId: String
    }
    let data: Data
    do {
      data = try JSONEncoder().encode(Activation(submissionId: submissionId, buttonId: buttonId))
    } catch {
      failure = frame.transportFailure
      return 0
    }
    failure = nil
    submissionCount = submissionId
    pendingSubmissionId = submissionId
    let accepted = data.withUnsafeBytes {
      event(context, frame.session, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
    }
    if accepted != 1, !closed {
      pendingSubmissionId = nil
      failure = frame.transportFailure
    }
    return accepted == 1 ? 1 : 0
  }

  /// The user or the host may close the prompt while an activation is
  /// pending. Closing releases only the prompt; it never cancels an operation
  /// the host has admitted.
  func finish() {
    guard !closed else { return }
    closed = true
    event = nil
    let callback = onClosed
    onClosed = nil
    callback?(context, frame.session)
  }
}

extension PromptDialogFrame.Button.Role {
  fileprivate var kind: DialogButton.Kind {
    switch self {
    case .cancel: .cancel
    case .default: .action
    case .destructive: .destructive
    }
  }
}

struct PromptDialogContent: View {
  /// `.glass-dialog-copy` sets `line-height: 1.45`; a 13 pt system line is 16 pt.
  private static let copyLeading: CGFloat = 13 * 1.45 - 16
  let model: PromptDialogModel
  let cancel: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(model.frame.title).font(.system(size: 15, weight: .semibold)).tracking(-0.3)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityAddTraits(.isHeader)
      if !model.frame.message.isEmpty {
        // `.glass-dialog-copy`: #3a3a3c on the sheet, 13px/500. The page puts
        // half of a line's extra leading above the first line and below the last.
        Text(model.frame.message).font(.system(size: 13, weight: .medium))
          .lineSpacing(Self.copyLeading).padding(.vertical, Self.copyLeading / 2)
          .foregroundStyle(.primary.opacity(0.9)).fixedSize(horizontal: false, vertical: true)
      }
      if let failure = model.failure {
        Text(failure).font(.system(size: 13, weight: .medium)).foregroundStyle(.orange)
          .fixedSize(horizontal: false, vertical: true)
          .accessibilityLabel(failure).accessibilityAddTraits(.updatesFrequently)
      }
      DialogActions {
        ForEach(model.frame.buttons) { button in
          DialogButton(title: button.title, kind: button.role.kind, action: { choose(button) })
            .disabled(!model.available(button))
            .accessibilityIdentifier("prompt-dialog.\(button.id)")
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.horizontal, 18.5).padding(.top, 18.5).padding(.bottom, 14.5)
    .environment(\.locale, Locale(identifier: model.frame.locale))
  }

  private func choose(_ button: PromptDialogFrame.Button) {
    if button.role == .cancel {
      cancel()
    } else {
      model.activate(button.id)
    }
  }
}

private struct PromptDialogSurface: View {
  let model: PromptDialogModel
  let cancel: () -> Void
  let relayout: () -> Void

  var body: some View {
    // A message longer than the parent's content area scrolls inside the panel.
    ScrollView { PromptDialogContent(model: model, cancel: cancel) }
      .modifier(DialogSheet())
      .onExitCommand(perform: cancel)
      .onChange(of: model.failure) { _, _ in relayout() }
  }
}

@MainActor
final class PromptDialogWindow: CenteredDialogWindow {
  let model: PromptDialogModel

  init(
    frame: PromptDialogFrame, parent: NSWindow, event: @escaping PromptDialogEventCallback,
    closed: @escaping PromptDialogClosedCallback, context: UInt
  ) {
    let model = PromptDialogModel(frame, event: event, closed: closed, context: context)
    self.model = model
    super.init(
      parent: parent, appearance: frame.appearance.name,
      metrics: Metrics(maximumWidth: 360, horizontalMargin: 32, verticalMargin: 32),
      content: Content(
        surface: { cancel, relayout in
          NSHostingView(
            rootView: PromptDialogSurface(model: model, cancel: cancel, relayout: relayout))
        },
        measured: { width in
          NSHostingView(
            rootView: PromptDialogContent(model: model, cancel: {}).frame(width: width))
        },
        finished: {
          if promptDialogWindow?.model === model { promptDialogWindow = nil }
          model.finish()
        }))
    panel.setAccessibilitySubrole(.dialog)
    panel.title = frame.title
  }

  func update(_ next: PromptDialogFrame) -> Int32 {
    let status = model.update(next)
    if status == 1 {
      panel.title = next.title
      refresh(appearance: next.appearance.name)
    }
    return status
  }
}

@MainActor private var promptDialogWindow: PromptDialogWindow?
@MainActor private var newestPromptDialogSession: UInt64 = 0

@_cdecl("cfm_prompt_dialog_present_v1")
public func promptDialogPresent(
  _ bytes: UnsafePointer<UInt8>?, _ count: Int,
  _ event: PromptDialogEventCallback?, _ closed: PromptDialogClosedCallback?,
  _ context: UInt
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= PromptDialogFrame.maximumBytes, let event, let closed
  else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? PromptDialogFrame.decode(data) else { return 0 }
    guard frame.session > newestPromptDialogSession else { return 2 }
    guard frame.acknowledgedSubmission == 0 else { return 0 }
    guard let parent = NSApp?.windows.first(where: { $0.windowNumber == frame.windowNumber }),
      parent.isVisible
    else { return 0 }
    let next = PromptDialogWindow(
      frame: frame, parent: parent, event: event, closed: closed, context: context)
    guard next.layout() else { return 0 }
    let prior = promptDialogWindow
    promptDialogWindow = next
    newestPromptDialogSession = frame.session
    prior?.finish()
    // A replacement callback may synchronously replace this window in turn.
    if !next.model.closed, !next.show() { next.finish() }
    return 1
  }
}

@_cdecl("cfm_prompt_dialog_update_v1")
public func promptDialogUpdate(_ bytes: UnsafePointer<UInt8>?, _ count: Int) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= PromptDialogFrame.maximumBytes else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? PromptDialogFrame.decode(data) else { return 0 }
    guard let promptDialogWindow else { return 2 }
    return promptDialogWindow.update(frame)
  }
}

@_cdecl("cfm_prompt_dialog_dismiss_v1")
public func promptDialogDismiss(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let promptDialogWindow, promptDialogWindow.model.frame.session == session else {
      return 2
    }
    promptDialogWindow.finish()
    return 1
  }
}
