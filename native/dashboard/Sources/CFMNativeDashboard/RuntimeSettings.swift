import AppKit
import Observation
import SwiftUI

typealias RuntimeSettingsEventCallback =
  @convention(c) (UInt, UInt64, UnsafePointer<UInt8>?, Int) -> Int32
typealias RuntimeSettingsClosedCallback = @convention(c) (UInt, UInt64) -> Void

struct RuntimeSettingsDraft: Codable, Equatable {
  enum Level: String, Codable, CaseIterable { case trace, debug, info, warn, error, fatal, silent }
  enum Field: String, CaseIterable {
    case port, level, mtu, ipv6DNS, allow, lanAddress, lanPort, lanSources

    var maximumLength: Int? {
      switch self {
      case .port, .mtu, .lanPort: 32
      case .lanAddress: 255
      case .lanSources: 8192
      case .level, .ipv6DNS, .allow: nil
      }
    }
  }
  var port: String
  var level: Level
  var mtu: String
  var ipv6DNS: Bool
  var allow: Bool
  var lanAddress: String
  var lanPort: String
  var lanSources: String
  var ipv6DNSEdited: Bool

  func text(_ field: Field) -> String {
    switch field {
    case .port: port
    case .level: level.rawValue
    case .mtu: mtu
    case .lanAddress: lanAddress
    case .lanPort: lanPort
    case .lanSources: lanSources
    case .ipv6DNS, .allow: ""
    }
  }

  var isBounded: Bool {
    Field.allCases.allSatisfy { field in
      field.maximumLength.map { text(field).unicodeScalars.count <= $0 } ?? true
    }
  }
}

struct RuntimeSettingsFrame: Codable {
  enum Appearance: String, Codable {
    case light, dark
    var name: NSAppearance.Name { self == .light ? .aqua : .darkAqua }
  }

  struct Labels: Codable {
    let title: String
    let description: String
    let port: String
    let automatic: String
    let level: String
    let mtu: String
    let ipv6DNS: String
    let ipv6Note: String
    let allow: String
    let lanNote: String
    let lanAddress: String
    let lanPort: String
    let lanSources: String
    let cancel: String
    let apply: String
    let applying: String
    let transportFailure: String
    let inputTooLong: String

    func field(_ field: RuntimeSettingsDraft.Field) -> String {
      switch field {
      case .port: port
      case .level: level
      case .mtu: mtu
      case .ipv6DNS: ipv6DNS
      case .allow: allow
      case .lanAddress: lanAddress
      case .lanPort: lanPort
      case .lanSources: lanSources
      }
    }

    var isValid: Bool {
      let short = [
        title, port, automatic, level, mtu, ipv6DNS, allow, lanAddress, lanPort, lanSources,
        cancel, apply, applying,
      ]
      let long = [description, ipv6Note, lanNote, transportFailure, inputTooLong]
      return short.allSatisfy {
        !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
          && $0.unicodeScalars.count <= 160
      }
        && long.allSatisfy {
          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && $0.unicodeScalars.count <= 1024
        }
        && inputTooLong.contains("{label}") && inputTooLong.contains("{maximum}")
    }
  }

  static let maximumBytes = 16 * 1024
  static let maximumSubmission: UInt64 = 9_007_199_254_740_991
  let version: UInt32
  let session: UInt64
  let sequence: UInt64
  let acknowledgedSubmission: UInt64
  let windowNumber: Int
  let locale: String
  let appearance: Appearance
  let labels: Labels
  let draft: RuntimeSettingsDraft
  let saving: Bool
  let error: String?

  static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= maximumBytes else { throw InvalidFrame.invalid }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    guard frame.version == 1, frame.session > 0, frame.sequence > 0, frame.windowNumber > 0,
      frame.acknowledgedSubmission <= maximumSubmission,
      ["en", "zh-Hans", "zh-Hant", "ja"].contains(frame.locale), frame.labels.isValid,
      frame.draft.isBounded,
      frame.error.map({
        !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
          && $0.unicodeScalars.count <= 4096
      }) ?? true
    else { throw InvalidFrame.invalid }
    return frame
  }
  enum InvalidFrame: Error { case invalid }
}

/// The native form owns only the unsaved draft. The host retains existing
/// preferencesFromRuntimeDraft validation and the Rust settings transaction.
@MainActor @Observable
final class RuntimeSettingsModel {
  private(set) var frame: RuntimeSettingsFrame
  private(set) var draft: RuntimeSettingsDraft
  private(set) var pendingSubmissionId: UInt64?
  private(set) var submissionCount: UInt64 = 0
  private(set) var localError: String?
  private(set) var closed = false
  private(set) var textAreaHeight: CGFloat = 64
  private(set) var maximumTextAreaHeight: CGFloat = 64
  @ObservationIgnored private var event: RuntimeSettingsEventCallback?
  @ObservationIgnored private var onClosed: RuntimeSettingsClosedCallback?
  @ObservationIgnored private let context: UInt

  init(
    _ frame: RuntimeSettingsFrame, event: @escaping RuntimeSettingsEventCallback,
    closed: @escaping RuntimeSettingsClosedCallback, context: UInt
  ) {
    self.frame = frame
    draft = frame.draft
    self.event = event
    onClosed = closed
    self.context = context
  }

  func setViewportHeight(_ height: CGFloat) {
    guard height.isFinite, height > 0 else { return }
    let limit = max(64, height * 0.48)
    if maximumTextAreaHeight != limit { maximumTextAreaHeight = limit }
    if textAreaHeight > limit { textAreaHeight = limit }
  }

  func resizeTextArea(_ height: CGFloat) {
    guard !closed, !busy, height.isFinite else { return }
    let bounded = min(maximumTextAreaHeight, max(64, height))
    if textAreaHeight != bounded { textAreaHeight = bounded }
  }

  var busy: Bool { frame.saving || pendingSubmissionId != nil }
  var error: String? { localError ?? frame.error }

  @discardableResult func edit(_ field: RuntimeSettingsDraft.Field, text: String) -> Bool {
    guard !closed, !busy else { return false }
    if let maximum = field.maximumLength, text.unicodeScalars.count > maximum {
      localError = frame.labels.inputTooLong
        .replacingOccurrences(of: "{label}", with: frame.labels.field(field))
        .replacingOccurrences(of: "{maximum}", with: String(maximum))
      return false
    }
    switch field {
    case .port: draft.port = text
    case .level:
      guard let level = RuntimeSettingsDraft.Level(rawValue: text) else { return false }
      draft.level = level
    case .mtu: draft.mtu = text
    case .lanAddress: draft.lanAddress = text
    case .lanPort: draft.lanPort = text
    case .lanSources: draft.lanSources = text
    case .ipv6DNS, .allow: return false
    }
    localError = nil
    return true
  }

  @discardableResult func edit(_ field: RuntimeSettingsDraft.Field, enabled: Bool) -> Bool {
    guard !closed, !busy else { return false }
    switch field {
    case .ipv6DNS:
      draft.ipv6DNS = enabled
      draft.ipv6DNSEdited = true
    case .allow: draft.allow = enabled
    default: return false
    }
    return true
  }

  func update(_ next: RuntimeSettingsFrame) -> Int32 {
    guard !closed, next.session == frame.session else { return 2 }
    guard next.sequence > frame.sequence, next.windowNumber == frame.windowNumber,
      next.acknowledgedSubmission >= frame.acknowledgedSubmission,
      next.acknowledgedSubmission <= submissionCount
    else { return 0 }
    frame = next
    if next.acknowledgedSubmission == pendingSubmissionId, next.saving || next.error != nil {
      pendingSubmissionId = nil
      localError = nil
    }
    return 1
  }

  static func nextSubmission(after value: UInt64) -> UInt64? {
    value < RuntimeSettingsFrame.maximumSubmission ? value + 1 : nil
  }

  @discardableResult func submit() -> Int32 {
    guard !closed else { return 2 }
    guard !busy, let event else { return 0 }
    guard let submissionId = Self.nextSubmission(after: submissionCount) else {
      localError = frame.labels.transportFailure
      return 0
    }
    struct Submission: Encodable {
      let action = "submit"
      let submissionId: UInt64
      let draft: RuntimeSettingsDraft
    }
    let data: Data
    do {
      data = try JSONEncoder().encode(Submission(submissionId: submissionId, draft: draft))
    } catch {
      localError = frame.labels.transportFailure
      return 0
    }
    guard data.count <= RuntimeSettingsFrame.maximumBytes else {
      localError = frame.labels.transportFailure
      return 0
    }
    localError = nil
    submissionCount = submissionId
    pendingSubmissionId = submissionId
    let accepted = data.withUnsafeBytes {
      event(context, frame.session, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
    }
    if accepted != 1, !closed {
      pendingSubmissionId = nil
      localError = frame.labels.transportFailure
    }
    return accepted == 1 ? 1 : 0
  }

  /// Host dismissal may follow success or a page reload even while busy. It
  /// releases only the form; it cannot cancel the host's admitted operation.
  func finish() {
    guard !closed else { return }
    closed = true
    event = nil
    let callback = onClosed
    onClosed = nil
    callback?(context, frame.session)
  }
}

struct RuntimeSettingsForm: View {
  let model: RuntimeSettingsModel
  let cancel: () -> Void
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var contrast
  @State private var textAreaDragStart: CGFloat?

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(model.frame.labels.title).font(.system(size: 18, weight: .bold))
        .accessibilityAddTraits(.isHeader)
      note(model.frame.labels.description)
      ForEach(RuntimeSettingsDraft.Field.allCases, id: \.self) { field in
        fieldView(field)
        if field == .ipv6DNS { note(model.frame.labels.ipv6Note) }
        if field == .allow { note(model.frame.labels.lanNote) }
      }
      if let error = model.error {
        Text(error).font(.system(size: 13, weight: .medium)).foregroundStyle(.orange)
          .fixedSize(horizontal: false, vertical: true)
          .accessibilityLabel(error).accessibilityAddTraits(.updatesFrequently)
      }
      HStack(spacing: 8) {
        Spacer(minLength: 0)
        if #available(macOS 26, *), !reduceTransparency, contrast != .increased {
          GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
              Button(model.frame.labels.cancel, action: cancel).buttonStyle(.glass)
              Button(model.busy ? model.frame.labels.applying : model.frame.labels.apply) {
                model.submit()
              }.buttonStyle(.glassProminent)
            }
          }
        } else {
          Button(model.frame.labels.cancel, action: cancel).buttonStyle(.bordered)
          Button(model.busy ? model.frame.labels.applying : model.frame.labels.apply) {
            model.submit()
          }.buttonStyle(.borderedProminent)
        }
      }
      .controlSize(.regular).disabled(model.busy || model.closed).padding(.top, 4)
    }
    .padding(.horizontal, 18.5).padding(.top, 18.5).padding(.bottom, 14.5)
    .environment(\.locale, Locale(identifier: model.frame.locale))
  }

  private func note(_ text: String) -> some View {
    Text(text).font(.system(size: 13, weight: .medium)).foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
  }

  @ViewBuilder private func fieldView(_ field: RuntimeSettingsDraft.Field) -> some View {
    let label = model.frame.labels.field(field)
    Group {
      if field == .ipv6DNS || field == .allow {
        Toggle(
          label,
          isOn: Binding(
            get: { field == .ipv6DNS ? model.draft.ipv6DNS : model.draft.allow },
            set: { model.edit(field, enabled: $0) })
        )
        .toggleStyle(.checkbox).font(.system(size: 12, weight: .semibold))
      } else {
        VStack(alignment: .leading, spacing: 6) {
          Text(label).font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
          if field == .level {
            Picker(
              label,
              selection: Binding(
                get: { model.draft.level.rawValue },
                set: { model.edit(field, text: $0) })
            ) {
              ForEach(RuntimeSettingsDraft.Level.allCases, id: \.self) { level in
                Text(level.rawValue).tag(level.rawValue)
              }
            }.labelsHidden().pickerStyle(.menu).frame(maxWidth: .infinity, alignment: .leading)
              .frame(minHeight: 34)
          } else if field == .lanSources {
            TextEditor(text: text(field)).font(.system(size: 12))
              .frame(height: model.textAreaHeight - 16).scrollContentBackground(.hidden)
              .padding(8).background(.background, in: RoundedRectangle(cornerRadius: 8))
              .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator, lineWidth: 0.5))
              .accessibilityLabel(label)
              .overlay(alignment: .bottomTrailing) {
                RuntimeSettingsResizeGrip().stroke(.secondary, lineWidth: 1)
                  .frame(width: 10, height: 10).padding(3).contentShape(Rectangle())
                  .gesture(
                    DragGesture(minimumDistance: 0)
                      .onChanged { value in
                        if textAreaDragStart == nil { textAreaDragStart = model.textAreaHeight }
                        model.resizeTextArea(
                          (textAreaDragStart ?? model.textAreaHeight) + value.translation.height)
                      }
                      .onEnded { _ in textAreaDragStart = nil }
                  )
                  .accessibilityHidden(true)
              }
          } else {
            TextField(field == .port ? model.frame.labels.automatic : "", text: text(field))
              .textFieldStyle(.plain).font(.system(size: 13))
              .padding(.horizontal, 11).padding(.vertical, 9)
              .background(.background, in: RoundedRectangle(cornerRadius: 10))
              .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator, lineWidth: 0.5))
              .accessibilityLabel(label)
          }
        }
      }
    }
    .disabled(model.busy || model.closed)
    .accessibilityIdentifier("runtime-settings.\(field.rawValue)")
  }

  private func text(_ field: RuntimeSettingsDraft.Field) -> Binding<String> {
    Binding(get: { model.draft.text(field) }, set: { model.edit(field, text: $0) })
  }
}

private struct RuntimeSettingsResizeGrip: Shape {
  func path(in rectangle: CGRect) -> Path {
    var path = Path()
    for inset in [CGFloat(1), 4, 7] {
      path.move(to: CGPoint(x: rectangle.maxX - inset, y: rectangle.maxY))
      path.addLine(to: CGPoint(x: rectangle.maxX, y: rectangle.maxY - inset))
    }
    return path
  }
}

private struct RuntimeSettingsSurface: View {
  let model: RuntimeSettingsModel
  let cancel: () -> Void
  let relayout: () -> Void
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var contrast

  var body: some View {
    ScrollView {
      RuntimeSettingsForm(model: model, cancel: cancel)
    }
    .background {
      if reduceTransparency || contrast == .increased {
        RoundedRectangle(cornerRadius: 16).fill(Color(nsColor: .windowBackgroundColor))
      } else {
        RoundedRectangle(cornerRadius: 16).fill(.regularMaterial)
      }
    }
    .overlay(
      RoundedRectangle(cornerRadius: 16).stroke(
        .separator, lineWidth: contrast == .increased ? 1 : 0.5)
    )
    .clipShape(RoundedRectangle(cornerRadius: 16))
    .onExitCommand(perform: cancel)
    .onChange(of: model.error) { _, _ in relayout() }
    .onChange(of: model.textAreaHeight) { _, _ in relayout() }
  }
}

private final class RuntimeSettingsPanel: NSPanel {
  override var canBecomeKey: Bool { true }
  override var canBecomeMain: Bool { false }
}

@MainActor
final class RuntimeSettingsWindow: NSObject, NSWindowDelegate {
  let model: RuntimeSettingsModel
  let panel: NSPanel
  private weak var parent: NSWindow?
  private weak var priorResponder: NSResponder?
  private var observers: [NSObjectProtocol] = []
  private var closing = false

  init(
    frame: RuntimeSettingsFrame, parent: NSWindow, event: @escaping RuntimeSettingsEventCallback,
    closed: @escaping RuntimeSettingsClosedCallback, context: UInt
  ) {
    self.parent = parent
    priorResponder = parent.firstResponder
    model = RuntimeSettingsModel(frame, event: event, closed: closed, context: context)
    panel = RuntimeSettingsPanel(
      contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel],
      backing: .buffered, defer: false)
    super.init()
    panel.isReleasedWhenClosed = false
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.hidesOnDeactivate = false
    panel.level = .normal
    panel.collectionBehavior = [.fullScreenAuxiliary]
    panel.delegate = self
    panel.appearance = NSAppearance(named: frame.appearance.name)
  }

  func show() -> Bool {
    guard !closing, let parent, parent.isVisible, layout() else { return false }
    panel.contentView = NSHostingView(
      rootView: RuntimeSettingsSurface(
        model: model, cancel: { [weak self] in self?.cancel() },
        relayout: { [weak self] in _ = self?.layout() }))
    parent.addChildWindow(panel, ordered: .above)
    panel.makeKeyAndOrderFront(nil)
    observe(NSWindow.willCloseNotification, object: parent) { $0.finish() }
    observe(NSWindow.didResizeNotification, object: parent) { _ = $0.layout() }
    observe(NSWindow.didMoveNotification, object: parent) { _ = $0.layout() }
    observe(NSWindow.didMiniaturizeNotification, object: parent) { $0.panel.orderOut(nil) }
    observe(NSWindow.didDeminiaturizeNotification, object: parent) { $0.restoreIfVisible() }
    observe(NSWindow.didChangeOcclusionStateNotification, object: parent) { controller in
      if controller.parent?.isVisible == true {
        controller.restoreIfVisible()
      } else {
        controller.panel.orderOut(nil)
      }
    }
    return true
  }

  @discardableResult func layout() -> Bool {
    guard let parent else { return false }
    let viewport = parent.convertToScreen(parent.contentLayoutRect)
    let width = min(480, viewport.width - 40)
    let maximumHeight = viewport.height - 48
    model.setViewportHeight(viewport.height)
    guard width >= 1, maximumHeight >= 1 else { return false }
    let measure = NSHostingView(
      rootView: RuntimeSettingsForm(model: model, cancel: {}).frame(width: width))
    measure.appearance = panel.appearance
    let height = min(maximumHeight, measure.fittingSize.height)
    guard height.isFinite, height >= 1 else { return false }
    panel.setFrame(
      NSRect(
        x: viewport.midX - width / 2, y: viewport.midY - height / 2,
        width: width, height: height), display: false)
    return true
  }

  private func restoreIfVisible() {
    guard !closing, let parent, parent.isVisible, !parent.isMiniaturized else { return }
    _ = layout()
    if !panel.isVisible { panel.orderFront(nil) }
  }

  func update(_ next: RuntimeSettingsFrame) -> Int32 {
    let status = model.update(next)
    if status == 1 {
      panel.appearance = NSAppearance(named: next.appearance.name)
      _ = layout()
    }
    return status
  }

  func cancel() { if !model.busy { finish() } }
  func windowShouldClose(_ sender: NSWindow) -> Bool { !model.busy }
  func windowWillClose(_ notification: Notification) { finish() }

  private func observe(
    _ name: Notification.Name, object: AnyObject,
    action: @escaping @MainActor (RuntimeSettingsWindow) -> Void
  ) {
    observers.append(
      NotificationCenter.default.addObserver(forName: name, object: object, queue: .main) {
        [weak self] _ in MainActor.assumeIsolated { if let self { action(self) } }
      })
  }

  func finish() {
    guard !closing else { return }
    closing = true
    let ownedFocus = panel.isKeyWindow
    for observer in observers { NotificationCenter.default.removeObserver(observer) }
    observers.removeAll()
    parent?.removeChildWindow(panel)
    panel.orderOut(nil)
    panel.close()
    if ownedFocus, NSApp.isActive, let parent, parent.isVisible {
      parent.makeKey()
      if let priorResponder { parent.makeFirstResponder(priorResponder) }
    }
    if runtimeSettingsWindow === self { runtimeSettingsWindow = nil }
    model.finish()
  }
}

@MainActor private var runtimeSettingsWindow: RuntimeSettingsWindow?
@MainActor private var newestRuntimeSettingsSession: UInt64 = 0

@_cdecl("cfm_runtime_settings_present_v1")
func runtimeSettingsPresent(
  _ bytes: UnsafePointer<UInt8>?, _ count: Int,
  _ event: RuntimeSettingsEventCallback?, _ closed: RuntimeSettingsClosedCallback?,
  _ context: UInt
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= RuntimeSettingsFrame.maximumBytes, let event, let closed
  else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? RuntimeSettingsFrame.decode(data) else { return 0 }
    guard frame.session > newestRuntimeSettingsSession else { return 2 }
    guard frame.acknowledgedSubmission == 0 else { return 0 }
    guard let parent = NSApp?.windows.first(where: { $0.windowNumber == frame.windowNumber }),
      parent.isVisible
    else { return 0 }
    let next = RuntimeSettingsWindow(
      frame: frame, parent: parent, event: event, closed: closed, context: context)
    guard next.layout() else { return 0 }
    let prior = runtimeSettingsWindow
    runtimeSettingsWindow = next
    newestRuntimeSettingsSession = frame.session
    prior?.finish()
    // A replacement callback may synchronously replace this window in turn.
    if !next.model.closed, !next.show() { next.finish() }
    return 1
  }
}

@_cdecl("cfm_runtime_settings_update_v1")
func runtimeSettingsUpdate(_ bytes: UnsafePointer<UInt8>?, _ count: Int) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= RuntimeSettingsFrame.maximumBytes else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? RuntimeSettingsFrame.decode(data) else { return 0 }
    guard let runtimeSettingsWindow else { return 2 }
    return runtimeSettingsWindow.update(frame)
  }
}

@_cdecl("cfm_runtime_settings_dismiss_v1")
func runtimeSettingsDismiss(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let runtimeSettingsWindow, runtimeSettingsWindow.model.frame.session == session else {
      return 2
    }
    runtimeSettingsWindow.finish()
    return 1
  }
}
