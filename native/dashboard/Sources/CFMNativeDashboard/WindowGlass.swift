import AppKit
import SwiftUI
import WebKit

public typealias WindowGlassEventCallback =
  @convention(c) (UInt, UInt64, UnsafePointer<UInt8>?, Int) -> Int32
public typealias WindowGlassClosedCallback = @convention(c) (UInt, UInt64) -> Void

/// The glass behind the page: the window's own slab and the panels, cards and
/// the navigation pill the page lays out. The renderer measures them in DOM
/// coordinates and the backdrop follows; it never draws text or controls.
struct WindowGlassFrame: Decodable, Equatable {
  static let maximumBytes = 16384
  static let maximumCounter: UInt64 = 9_007_199_254_740_991
  static let maximumPanels = 32
  static let requiredKeys: Set<String> = [
    "version", "session", "sequence", "acknowledgedSubmission", "windowNumber", "appearance",
    "viewport", "panels",
  ]

  enum Kind: String, Decodable { case panel, card, pill, strip }
  struct Viewport: Decodable, Equatable {
    let width: Double
    let height: Double
  }
  struct Panel: Decodable, Equatable {
    let id: String
    let kind: Kind
    let x: Double
    let y: Double
    let width: Double
    let height: Double
    let radius: Double
  }

  let version: Int
  let session: UInt64
  let sequence: UInt64
  let acknowledgedSubmission: UInt64
  let windowNumber: Int
  let appearance: RuntimeSettingsFrame.Appearance
  let viewport: Viewport
  let panels: [Panel]

  static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= maximumBytes,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(object.keys) == requiredKeys,
      let viewport = object["viewport"] as? [String: Any],
      Set(viewport.keys) == ["width", "height"],
      let panels = object["panels"] as? [[String: Any]],
      panels.allSatisfy({
        Set($0.keys) == ["id", "kind", "x", "y", "width", "height", "radius"]
      })
    else { throw InvalidFrame.invalid }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    let finite =
      frame.panels.flatMap { [$0.x, $0.y, $0.width, $0.height, $0.radius] }
      + [frame.viewport.width, frame.viewport.height]
    guard frame.version == 1, frame.session > 0,
      frame.sequence > 0, frame.sequence <= maximumCounter,
      frame.acknowledgedSubmission == 0, frame.windowNumber > 0,
      finite.allSatisfy(\.isFinite), frame.viewport.width > 0, frame.viewport.height > 0,
      frame.panels.count <= maximumPanels,
      Set(frame.panels.map(\.id)).count == frame.panels.count,
      frame.panels.allSatisfy({
        isFrameIdentifier($0.id) && $0.width >= 0 && $0.height >= 0 && (0...64).contains($0.radius)
      })
    else { throw InvalidFrame.invalid }
    return frame
  }
  enum InvalidFrame: Error { case invalid }
}

/// One placed panel in the backdrop's flipped coordinates.
struct WindowGlassPlacement: Equatable {
  let id: String
  let kind: WindowGlassFrame.Kind
  let rect: CGRect
  let radius: CGFloat
}

@MainActor
final class WindowGlassModel: ObservableObject {
  @Published private(set) var placements: [WindowGlassPlacement] = []
  @Published private(set) var dark = false

  func apply(placements: [WindowGlassPlacement], dark: Bool) {
    self.placements = placements
    self.dark = dark
  }
}

/// The slab is real glass over whatever is behind the window; the page's
/// panels and cards are frosted fills on it and only the navigation pill is
/// glass again, so no two glass materials stack over a large area. Before
/// macOS 26 the slab is the system's behind-window material.
struct WindowGlassView: View {
  @ObservedObject var model: WindowGlassModel

  var body: some View {
    ZStack(alignment: .topLeading) {
      slab
      ForEach(model.placements, id: \.id) { placement in
        panel(placement)
          .frame(width: placement.rect.width, height: placement.rect.height)
          .offset(x: placement.rect.minX, y: placement.rect.minY)
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    // The host window extends its content under the titlebar, and so does the
    // page; the glass must not stop at the safe area the page ignores.
    .ignoresSafeArea()
    .environment(\.colorScheme, model.dark ? .dark : .light)
  }

  /// Fills the backdrop, so a resized window keeps its glass before the page
  /// has measured its new layout. The window's own shape rounds the corners:
  /// a smaller glass shape would leave the window's material showing in the
  /// corners around it.
  @ViewBuilder private var slab: some View {
    if #available(macOS 26, *) {
      Color.clear.glassEffect(.regular, in: Rectangle())
    } else {
      BehindWindowMaterial(dark: model.dark)
    }
  }

  @ViewBuilder private func panel(_ placement: WindowGlassPlacement) -> some View {
    let shape = RoundedRectangle(cornerRadius: placement.radius, style: .continuous)
    switch placement.kind {
    case .pill:
      if #available(macOS 26, *) {
        Color.clear
          .glassEffect(.regular.tint(Self.accent.opacity(model.dark ? 0.45 : 0.3)), in: Capsule())
      } else {
        Capsule().fill(Self.accent.opacity(model.dark ? 0.4 : 0.24))
      }
    case .panel:
      shape.fill(fill(0.34, dark: 0.18))
        .overlay(shape.strokeBorder(stroke, lineWidth: 1))
    case .card:
      shape.fill(fill(0.5, dark: 0.26))
        .overlay(shape.strokeBorder(stroke, lineWidth: 1))
    case .strip:
      shape.fill(fill(0.16, dark: 0.1))
    }
  }

  static let accent = Color(red: 0x3b / 255, green: 0x82 / 255, blue: 0xf6 / 255)
  private var stroke: Color { Color.white.opacity(model.dark ? 0.1 : 0.55) }
  private func fill(_ light: Double, dark: Double) -> Color {
    model.dark ? Color.black.opacity(dark) : Color.white.opacity(light)
  }
}

/// The pre-26 slab: the system's behind-window blur.
struct BehindWindowMaterial: NSViewRepresentable {
  let dark: Bool
  func makeNSView(context: Context) -> NSVisualEffectView {
    let view = NSVisualEffectView()
    view.blendingMode = .behindWindow
    view.material = .hudWindow
    view.state = .active
    return view
  }
  func updateNSView(_ view: NSVisualEffectView, context: Context) {
    view.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
  }
}

/// A flipped container, so placements keep the page's top-left origin.
final class WindowGlassBackdrop: NSView {
  override var isFlipped: Bool { true }
  override func hitTest(_ point: NSPoint) -> NSView? { nil }
}

@MainActor
final class WindowGlassController {
  private(set) var frame: WindowGlassFrame
  let model = WindowGlassModel()
  let backdrop = WindowGlassBackdrop()
  private(set) var closed = false
  private weak var webview: WKWebView?
  private weak var parent: NSWindow?
  private var hosting: NSHostingView<WindowGlassView>?
  private var closedCallback: WindowGlassClosedCallback?
  private let context: UInt
  private var observers: [NSObjectProtocol] = []

  init(
    frame: WindowGlassFrame, parent: NSWindow, webview: WKWebView,
    closed: @escaping WindowGlassClosedCallback, context: UInt
  ) {
    self.frame = frame
    self.parent = parent
    self.webview = webview
    closedCallback = closed
    self.context = context
  }

  /// The WKWebView of a decorated host window: the view the page lives in.
  static func webview(of window: NSWindow) -> WKWebView? {
    func search(_ view: NSView) -> WKWebView? {
      if let webview = view as? WKWebView { return webview }
      for child in view.subviews {
        if let found = search(child) { return found }
      }
      return nil
    }
    return window.contentView.flatMap(search)
  }

  /// Inserts the backdrop under the page. Nothing is retained after a refusal.
  func attach() -> Bool {
    guard let webview, let parent, parent.isVisible, let container = webview.superview,
      webview.window === parent
    else { return false }
    backdrop.frame = container.bounds
    backdrop.autoresizingMask = [.width, .height]
    backdrop.wantsLayer = true
    let hosting = NSHostingView(rootView: WindowGlassView(model: model))
    hosting.frame = backdrop.bounds
    hosting.autoresizingMask = [.width, .height]
    backdrop.addSubview(hosting)
    self.hosting = hosting
    container.addSubview(backdrop, positioned: .below, relativeTo: webview)
    guard apply(frame) else {
      backdrop.removeFromSuperview()
      self.hosting = nil
      return false
    }
    observers.append(
      NotificationCenter.default.addObserver(
        forName: NSWindow.willCloseNotification, object: parent, queue: .main
      ) { [weak self] _ in MainActor.assumeIsolated { self?.finish() } })
    return true
  }

  func update(_ next: WindowGlassFrame) -> Int32 {
    guard !closed else { return 2 }
    guard next.session == frame.session else { return 2 }
    guard next.sequence > frame.sequence, next.windowNumber == frame.windowNumber else { return 0 }
    guard apply(next) else { return 2 }
    frame = next
    return 1
  }

  /// Places the panels for a frame whose viewport still matches the page.
  private func apply(_ next: WindowGlassFrame) -> Bool {
    guard let webview, let container = webview.superview, backdrop.superview === container,
      let geometry = WebContentGeometry(
        webview: webview, width: next.viewport.width, height: next.viewport.height)
    else { return false }
    let placements = next.panels.map { panel in
      let native = geometry.rectangle(
        x: panel.x, y: panel.y, width: panel.width, height: panel.height)
      let rect = backdrop.convert(webview.convert(native, to: container), from: container)
      return WindowGlassPlacement(
        id: panel.id, kind: panel.kind, rect: rect.standardized,
        radius: panel.kind == .pill ? panel.height / 2 : panel.radius)
    }
    guard
      placements.allSatisfy({
        [$0.rect.minX, $0.rect.minY, $0.rect.width, $0.rect.height]
          .allSatisfy(\.isFinite)
      })
    else { return false }
    model.apply(placements: placements, dark: next.appearance == .dark)
    backdrop.appearance = NSAppearance(named: next.appearance.name)
    return true
  }

  func finish() {
    guard !closed else { return }
    closed = true
    for observer in observers { NotificationCenter.default.removeObserver(observer) }
    observers.removeAll()
    backdrop.removeFromSuperview()
    hosting = nil
    if windowGlass === self { windowGlass = nil }
    let callback = closedCallback
    closedCallback = nil
    callback?(context, frame.session)
  }
}

@MainActor private var windowGlass: WindowGlassController?
@MainActor private var newestWindowGlassSession: UInt64 = 0

/// The backdrop that is showing, for the package's own tests.
@MainActor func currentWindowGlass() -> WindowGlassController? { windowGlass }

@_cdecl("cfm_window_glass_present_v1")
public func windowGlassPresent(
  _ bytes: UnsafePointer<UInt8>?, _ count: Int,
  _ event: WindowGlassEventCallback?, _ closed: WindowGlassClosedCallback?,
  _ context: UInt
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= WindowGlassFrame.maximumBytes, event != nil, let closed
  else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? WindowGlassFrame.decode(data) else { return 0 }
    guard frame.session > newestWindowGlassSession else { return 2 }
    guard let parent = NSApp?.windows.first(where: { $0.windowNumber == frame.windowNumber }),
      parent.isVisible, let webview = WindowGlassController.webview(of: parent)
    else { return 0 }
    let next = WindowGlassController(
      frame: frame, parent: parent, webview: webview, closed: closed, context: context)
    let prior = windowGlass
    prior?.finish()
    guard next.attach() else { return 0 }
    windowGlass = next
    newestWindowGlassSession = frame.session
    return 1
  }
}

@_cdecl("cfm_window_glass_update_v1")
public func windowGlassUpdate(_ bytes: UnsafePointer<UInt8>?, _ count: Int) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= WindowGlassFrame.maximumBytes else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? WindowGlassFrame.decode(data) else { return 0 }
    guard let windowGlass else { return 2 }
    return windowGlass.update(frame)
  }
}

@_cdecl("cfm_window_glass_dismiss_v1")
public func windowGlassDismiss(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let windowGlass, windowGlass.frame.session == session else { return 2 }
    windowGlass.finish()
    return 1
  }
}
