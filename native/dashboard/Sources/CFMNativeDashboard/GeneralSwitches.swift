import AppKit
import OSLog
import Observation
import SwiftUI
import WebKit

private let generalSwitchesLog = Logger(
  subsystem: "com.bill.clashformac", category: "general-switches")

public typealias GeneralSwitchesCallback =
  @convention(c) (UInt, UInt64, UInt64, UInt64, UInt32, UInt32, UInt8) -> Int32
public typealias GeneralSwitchesClosed = @convention(c) (UInt) -> Void

struct GeneralSwitchesFrame: Decodable {
  struct Viewport: Decodable {
    let width: Double
    let height: Double
  }
  struct Rectangle: Decodable {
    let x: Double
    let y: Double
    let width: Double
    let height: Double
    var valid: Bool {
      [x, y, width, height, x + width, y + height].allSatisfy(\.isFinite)
        && width >= 0 && height >= 0
    }
  }
  struct Item: Decodable {
    let key: UInt32
    let label: String
    let help: String
    let enabled: Bool
    let checked: Bool
    let rect: Rectangle
  }
  static let maximumBytes = 16_384
  static let maximumCounter: UInt64 = 9_007_199_254_740_991
  let version: UInt32
  let session: UInt64
  let sequence: UInt64
  let acknowledgedSubmission: UInt64
  let locale: String
  let appearance: RuntimeSettingsFrame.Appearance
  let viewport: Viewport
  let clip: Rectangle
  let items: [Item]

  enum Invalid: Error { case frame }
  static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= maximumBytes,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys)
        == Set([
          "version", "session", "sequence", "acknowledgedSubmission",
          "locale", "appearance", "viewport", "clip", "items",
        ]),
      let viewport = object["viewport"] as? [String: Any],
      Set(viewport.keys) == Set(["width", "height"]),
      let clip = object["clip"] as? [String: Any], validRectangleKeys(clip),
      let items = object["items"] as? [[String: Any]], items.count <= 6,
      items.allSatisfy({ item in
        guard Set(item.keys) == Set(["key", "label", "help", "enabled", "checked", "rect"]),
          let rect = item["rect"] as? [String: Any]
        else { return false }
        return validRectangleKeys(rect)
      })
    else { throw Invalid.frame }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    guard frame.version == 1, frame.session > 0,
      frame.sequence > 0, frame.sequence <= maximumCounter,
      frame.acknowledgedSubmission <= maximumCounter,
      ["en", "zh-Hans", "zh-Hant", "ja"].contains(frame.locale),
      frame.viewport.width.isFinite, frame.viewport.height.isFinite,
      frame.viewport.width > 0, frame.viewport.height > 0, frame.clip.valid,
      Set(frame.items.map(\.key)).count == frame.items.count,
      frame.items.allSatisfy({
        (1...6).contains($0.key)
          && !$0.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
          && $0.label.unicodeScalars.count <= 160 && $0.help.unicodeScalars.count <= 1024
          && $0.rect.valid && $0.rect.width > 0 && $0.rect.height > 0
      })
    else { throw Invalid.frame }
    return frame
  }
  private static func validRectangleKeys(_ value: [String: Any]) -> Bool {
    Set(value.keys) == Set(["x", "y", "width", "height"])
  }
}

@MainActor @Observable
final class GeneralSwitchModel {
  var item: GeneralSwitchesFrame.Item
  var available = false
  var pending = false
  var locale: String
  var focusRequest: UInt64 = 0
  @ObservationIgnored let toggle: (UInt32, Bool) -> Void
  @ObservationIgnored let focused: (UInt32) -> Void
  init(
    _ item: GeneralSwitchesFrame.Item, locale: String,
    toggle: @escaping (UInt32, Bool) -> Void, focused: @escaping (UInt32) -> Void
  ) {
    self.item = item
    self.locale = locale
    self.toggle = toggle
    self.focused = focused
  }
  var enabled: Bool { available && item.enabled && !pending }
}

struct GeneralSwitchView: View {
  let model: GeneralSwitchModel
  @FocusState private var focused: Bool
  @Environment(\.accessibilityReduceMotion) private var reduceMotion
  var body: some View {
    Toggle(
      model.item.label,
      isOn: Binding(
        get: { model.item.checked }, set: { model.toggle(model.item.key, $0) })
    )
    .toggleStyle(.switch).controlSize(.mini).labelsHidden().fixedSize()
    .disabled(!model.enabled)
    .focusable()
    .focused($focused)
    .onKeyPress(.space, phases: .down) { press in
      guard press.modifiers.intersection([.command, .control, .option]).isEmpty,
        model.enabled
      else { return .ignored }
      model.toggle(model.item.key, !model.item.checked)
      return .handled
    }
    .accessibilityLabel(model.item.label)
    .accessibilityHint(model.item.help)
    .accessibilityIdentifier("general-switch.\(model.item.key)")
    .help(model.item.help)
    .environment(\.locale, Locale(identifier: model.locale))
    // Standard switches supply contrast/transparency behavior. Do not add a
    // custom glass layer or animate authoritative state when motion is reduced.
    .transaction {
      if reduceMotion {
        $0.animation = nil
        $0.disablesAnimations = true
      }
    }
    .onChange(of: model.focusRequest, initial: true) { _, value in
      if value > 0 && model.enabled { focused = true }
    }
    .onChange(of: focused) { _, value in if value { model.focused(model.item.key) } }
  }
}

@MainActor
final class GeneralSwitchOverlay: NSView {
  override var isFlipped: Bool { true }
  override func hitTest(_ point: NSPoint) -> NSView? {
    let local = convert(point, from: superview)
    guard !isHidden, bounds.contains(local) else { return nil }
    for child in subviews.reversed() where !child.isHidden {
      if let hit = child.hitTest(local) { return hit }
    }
    return nil
  }
}

@MainActor
final class GeneralSwitchesController {
  private(set) var frame: GeneralSwitchesFrame
  let overlay = GeneralSwitchOverlay()
  private(set) var models: [UInt32: GeneralSwitchModel] = [:]
  private(set) var hosts: [UInt32: NSHostingView<GeneralSwitchView>] = [:]
  private(set) var submission: UInt64 = 0
  private(set) var pendingSubmission: UInt64?
  private(set) var closed = false
  private(set) var geometryValid = false
  private weak var webview: WKWebView?
  private weak var parent: NSWindow?
  private var callback: GeneralSwitchesCallback?
  private var onClosed: GeneralSwitchesClosed?
  private let context: UInt
  private var observers: [NSObjectProtocol] = []
  private var eventMonitor: Any?
  private var ownsContext = false
  private struct MeasurementKey: Equatable {
    let locale: String
    let appearance: RuntimeSettingsFrame.Appearance
    let label: String
    let help: String
    let checked: Bool
    let enabled: Bool
    let pending: Bool
  }
  private var measurements: [UInt32: (MeasurementKey, NSSize)] = [:]
  private(set) var measurementCount = 0

  init(
    frame: GeneralSwitchesFrame, webview: WKWebView,
    callback: @escaping GeneralSwitchesCallback, closed: @escaping GeneralSwitchesClosed,
    context: UInt
  ) {
    self.frame = frame
    self.webview = webview
    parent = webview.window
    self.callback = callback
    onClosed = closed
    self.context = context
    overlay.wantsLayer = true
    overlay.layer?.masksToBounds = true
  }

  /// DOM innerWidth/innerHeight are integer CSS-pixel viewport measurements.
  /// A resize can reach AppKit before the renderer publishes its new layout.
  /// Admit only the public pageZoom conversion, allowing less than one CSS
  /// pixel for viewport quantization, never arbitrary proportional stretching.
  static func viewportIsCurrent(_ frame: GeneralSwitchesFrame, in webview: WKWebView) -> Bool {
    WebContentGeometry(
      webview: webview, width: frame.viewport.width, height: frame.viewport.height) != nil
  }

  /// Validate all geometry and system-control sizes before taking ownership of
  /// the caller's context. No callback is retained after a rejected first sync.
  func attach() -> Bool {
    guard let webview, let parent, NSApp?.windows.contains(where: { $0 === parent }) == true,
      let container = webview.superview
    else {
      return false
    }
    guard Self.viewportIsCurrent(frame, in: webview) else { return false }
    container.addSubview(overlay, positioned: .above, relativeTo: webview)
    guard apply(frame) else {
      overlay.removeFromSuperview()
      return false
    }
    observe(NSWindow.willCloseNotification, parent) { $0.finish() }
    for name in [
      NSWindow.didResizeNotification, NSWindow.didMoveNotification,
      NSWindow.didMiniaturizeNotification, NSWindow.didChangeOcclusionStateNotification,
      NSWindow.didChangeBackingPropertiesNotification, NSWindow.didBecomeKeyNotification,
    ] { observe(name, parent) { $0.invalidateGeometry() } }
    observe(NSView.frameDidChangeNotification, webview) { $0.invalidateGeometry() }
    observe(NSView.boundsDidChangeNotification, webview) { $0.invalidateGeometry() }
    eventMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .scrollWheel]) {
      [weak self] event in
      let consumed = MainActor.assumeIsolated { self?.handle(event) ?? false }
      return consumed ? nil : event
    }
    ownsContext = true
    return true
  }

  func update(_ next: GeneralSwitchesFrame, webview: WKWebView) -> Int32 {
    guard !closed, next.session == frame.session else { return 2 }
    guard self.webview === webview, webview.window === parent else { return 0 }
    guard Self.viewportIsCurrent(next, in: webview) else {
      invalidateGeometry(notify: false)
      return 2
    }
    guard next.sequence > frame.sequence else { return 2 }
    guard next.acknowledgedSubmission >= frame.acknowledgedSubmission,
      next.acknowledgedSubmission <= submission
    else { return 0 }
    guard apply(next) else {
      invalidateGeometry(notify: false)
      return 0
    }
    frame = next
    if let pendingSubmission, next.acknowledgedSubmission >= pendingSubmission {
      self.pendingSubmission = nil
    }
    updateAvailability()
    return 1
  }

  private func apply(_ next: GeneralSwitchesFrame) -> Bool {
    guard let webview, let container = webview.superview, overlay.superview === container,
      webview.window === parent, let parent,
      NSApp?.windows.contains(where: { $0 === parent }) == true
    else { return false }
    guard
      let geometry = WebContentGeometry(
        webview: webview, width: next.viewport.width, height: next.viewport.height)
    else { return false }
    func rectangle(_ input: GeneralSwitchesFrame.Rectangle) -> NSRect {
      geometry.rectangle(x: input.x, y: input.y, width: input.width, height: input.height)
    }
    let clipRectangle = rectangle(next.clip)
    guard
      [clipRectangle.minX, clipRectangle.minY, clipRectangle.width, clipRectangle.height]
        .allSatisfy(\.isFinite)
    else { return false }
    let intersection = clipRectangle.intersection(geometry.viewport)
    let clip = intersection.isNull || intersection.isEmpty ? NSRect.zero : intersection
    guard [clip.origin.x, clip.origin.y, clip.width, clip.height].allSatisfy(\.isFinite) else {
      return false
    }
    overlay.appearance = NSAppearance(named: next.appearance.name)
    overlay.frame = webview.convert(clip, to: container)
    var placements: [UInt32: NSRect] = [:]
    for item in next.items {
      let model: GeneralSwitchModel
      let host: NSHostingView<GeneralSwitchView>
      if let existing = models[item.key], let existingHost = hosts[item.key] {
        model = existing
        host = existingHost
      } else {
        model = GeneralSwitchModel(
          item, locale: next.locale,
          toggle: { [weak self] in self?.toggle($0, value: $1) },
          focused: { [weak self] in self?.sendFocus($0) })
        host = NSHostingView(rootView: GeneralSwitchView(model: model))
        models[item.key] = model
        hosts[item.key] = host
        overlay.addSubview(host)
      }
      let willBePending = pendingSubmission.map { next.acknowledgedSubmission < $0 } ?? false
      let measureKey = MeasurementKey(
        locale: next.locale, appearance: next.appearance,
        label: item.label, help: item.help, checked: item.checked, enabled: item.enabled,
        pending: willBePending)
      let measured: NSSize
      if let prior = measurements[item.key], prior.0 == measureKey {
        measured = prior.1
      } else {
        let measuringModel = GeneralSwitchModel(
          item, locale: next.locale, toggle: { _, _ in }, focused: { _ in })
        measuringModel.available = true
        measuringModel.pending = willBePending
        let measuringHost = NSHostingView(rootView: GeneralSwitchView(model: measuringModel))
        measuringHost.appearance = NSAppearance(named: next.appearance.name)
        measured = measuringHost.fittingSize
        measurements[item.key] = (measureKey, measured)
        measurementCount += 1
      }
      let target = rectangle(item.rect)
      guard
        [
          measured.width, measured.height, target.origin.x, target.origin.y, target.width,
          target.height,
        ].allSatisfy(\.isFinite),
        measured.width > 0, measured.height > 0,
        measured.width <= target.width + 0.01, measured.height <= target.height + 0.01
      else {
        generalSwitchesLog.error(
          "Control footprint rejected key=\(item.key) actual=\(measured.width)x\(measured.height) available=\(target.width)x\(target.height)"
        )
        return false
      }
      // Scroll clipping must not leave a partly visible, still clickable switch.
      if clip.contains(target) {
        let local = overlay.convert(target, from: webview)
        placements[item.key] = NSRect(
          x: local.midX - measured.width / 2,
          y: local.midY - measured.height / 2, width: measured.width, height: measured.height)
      }
    }
    // Publish the accepted sequence before enabling views that may synchronously
    // report focus; rejected geometry never produces events for a new frame.
    frame = next
    if let focused = focusedKey(), placements[focused] == nil { returnFocusToWebviewIfOwned() }
    for (key, host) in hosts {
      host.appearance = overlay.appearance
      host.isHidden = placements[key] == nil
      if let placement = placements[key] { host.frame = placement }
    }
    for item in next.items {
      models[item.key]?.item = item
      models[item.key]?.locale = next.locale
    }
    geometryValid = true
    overlay.isHidden = !parent.isVisible || next.items.isEmpty || placements.isEmpty
    updateAvailability()
    return true
  }

  private func updateAvailability() {
    for (key, model) in models {
      model.available = geometryValid && !overlay.isHidden && hosts[key]?.isHidden == false
      model.pending = pendingSubmission != nil
    }
  }

  func invalidateGeometry(notify: Bool = true) {
    let wasValid = geometryValid
    geometryValid = false
    overlay.isHidden = true
    updateAvailability()
    returnFocusToWebviewIfOwned()
    if notify, wasValid, ownsContext, !closed,
      callback?(context, frame.session, frame.sequence, 0, 0, 5, 0) != 1
    {
      finish()
    }
  }

  func toggle(_ key: UInt32, value: Bool) {
    guard !closed, ownsContext, let model = models[key], model.enabled, value != model.item.checked,
      submission < GeneralSwitchesFrame.maximumCounter
    else { return }
    submission += 1
    pendingSubmission = submission
    updateAvailability()
    if callback?(context, frame.session, frame.sequence, submission, key, 1, value ? 1 : 0) != 1 {
      finish()
    }
  }

  private func sendFocus(_ key: UInt32) {
    guard !closed, ownsContext, geometryValid, models[key]?.enabled == true else { return }
    if callback?(context, frame.session, frame.sequence, 0, key, 4, 0) != 1 { finish() }
  }

  func focus(sequence: UInt64, key: UInt32) -> Int32 {
    guard !closed, sequence == frame.sequence else { return 2 }
    guard let model = models[key], model.enabled, model.focusRequest < UInt64.max else { return 0 }
    model.focusRequest += 1
    return 1
  }

  private func focusedKey() -> UInt32? {
    guard let responder = parent?.firstResponder as? NSView else { return nil }
    return hosts.first(where: { responder === $0.value || responder.isDescendant(of: $0.value) })?
      .key
  }

  func handle(_ event: NSEvent) -> Bool {
    guard !closed, let parent, event.window === parent else { return false }
    if event.type == .scrollWheel {
      if let webview, webview.convert(webview.bounds, to: nil).contains(event.locationInWindow) {
        invalidateGeometry()
      }
      return false
    }
    guard geometryValid, !overlay.isHidden, event.type == .keyDown, event.keyCode == 48,
      event.modifierFlags.intersection([.command, .control, .option]).isEmpty,
      let key = focusedKey()
    else { return false }
    let kind: UInt32 = event.modifierFlags.contains(.shift) ? 3 : 2
    guard callback?(context, frame.session, frame.sequence, 0, key, kind, 0) == 1 else {
      finish()
      return true
    }
    returnFocusToWebviewIfOwned()
    return true
  }

  private func returnFocusToWebviewIfOwned() {
    if focusedKey() != nil, let webview { parent?.makeFirstResponder(webview) }
  }

  private func observe(
    _ name: Notification.Name, _ object: AnyObject,
    action: @escaping @MainActor (GeneralSwitchesController) -> Void
  ) {
    observers.append(
      NotificationCenter.default.addObserver(forName: name, object: object, queue: .main) {
        [weak self] _ in MainActor.assumeIsolated { if let self { action(self) } }
      })
  }

  func finish() {
    guard !closed else { return }
    closed = true
    returnFocusToWebviewIfOwned()
    if let eventMonitor { NSEvent.removeMonitor(eventMonitor) }
    eventMonitor = nil
    for observer in observers { NotificationCenter.default.removeObserver(observer) }
    observers.removeAll()
    overlay.removeFromSuperview()
    let release = onClosed
    onClosed = nil
    callback = nil
    if generalSwitches === self { generalSwitches = nil }
    if ownsContext { release?(context) }
    ownsContext = false
  }
}

@MainActor private var generalSwitches: GeneralSwitchesController?
@MainActor private var newestGeneralSwitchesSession: UInt64 = 0

@_cdecl("cfm_general_switches_sync_v1")
public func generalSwitchesSync(
  _ view: UnsafeMutableRawPointer?, _ bytes: UnsafePointer<UInt8>?, _ count: Int,
  _ callback: GeneralSwitchesCallback?, _ closed: GeneralSwitchesClosed?, _ context: UInt
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let view, let bytes, count > 0, count <= GeneralSwitchesFrame.maximumBytes else { return 0 }
  let data = Data(bytes: bytes, count: count)
  let borrowed = Unmanaged<NSView>.fromOpaque(view).takeUnretainedValue()
  return MainActor.assumeIsolated {
    guard let frame = try? GeneralSwitchesFrame.decode(data),
      let webview = borrowed as? WKWebView
    else {
      generalSwitchesLog.error(
        "Native General switches rejected frame schema or WKWebView identity")
      return 0
    }
    if let existing = generalSwitches, existing.frame.session == frame.session {
      guard callback == nil, closed == nil, context == 0 else { return 0 }
      return existing.update(frame, webview: webview)
    }
    guard frame.session > newestGeneralSwitchesSession else { return 2 }
    guard let callback, let closed, frame.acknowledgedSubmission == 0 else { return 0 }
    guard webview.window != nil, webview.superview != nil,
      GeneralSwitchesController.viewportIsCurrent(frame, in: webview)
    else {
      generalSwitches?.invalidateGeometry(notify: false)
      return 2
    }
    let next = GeneralSwitchesController(
      frame: frame, webview: webview, callback: callback, closed: closed, context: context)
    guard next.attach() else { return 0 }
    let previous = generalSwitches
    generalSwitches = next
    newestGeneralSwitchesSession = frame.session
    previous?.finish()
    return 1
  }
}

@_cdecl("cfm_general_switches_focus_v1")
public func generalSwitchesFocus(_ session: UInt64, _ sequence: UInt64, _ key: UInt32) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let current = generalSwitches, current.frame.session == session else { return 2 }
    return current.focus(sequence: sequence, key: key)
  }
}

@_cdecl("cfm_general_switches_dismiss_v1")
public func generalSwitchesDismiss(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let current = generalSwitches, current.frame.session == session else { return 2 }
    current.finish()
    return 1
  }
}
