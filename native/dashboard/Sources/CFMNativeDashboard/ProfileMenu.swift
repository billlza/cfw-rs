import AppKit
import Observation
import SwiftUI

typealias ProfileMenuCallback = @convention(c) (UInt, UInt64, UInt32) -> Void

enum ProfileMenuAction: String, Codable, CaseIterable {
  case select, edit
  case editExternal = "edit-external"
  case update, reveal, outbounds, route, copy, qrcode, credentials, settings, delete

  var wireValue: UInt32 {
    switch self {
    case .select: 1
    case .edit: 2
    case .editExternal: 3
    case .update: 4
    case .reveal: 5
    case .outbounds: 6
    case .route: 7
    case .copy: 8
    case .qrcode: 9
    case .credentials: 10
    case .settings: 11
    case .delete: 12
    }
  }
}

enum ProfileMenuIcon: String, Codable {
  case check, edit, refresh, folder, send, rules, copy, qr, gear, trash

  var symbol: String {
    switch self {
    case .check: "checkmark"
    case .edit: "pencil"
    case .refresh: "arrow.clockwise"
    case .folder: "folder"
    case .send: "paperplane"
    case .rules: "list.bullet"
    case .copy: "doc.on.doc"
    case .qr: "qrcode"
    case .gear: "gearshape"
    case .trash: "trash"
    }
  }
}

struct ProfileMenuItem: Codable, Identifiable {
  let id: ProfileMenuAction
  let title: String
  let icon: ProfileMenuIcon
  let enabled: Bool
  let reason: String?
  let danger: Bool
}

struct ProfileMenuFrame: Codable {
  enum Appearance: String, Codable {
    case light, dark

    var name: NSAppearance.Name { self == .light ? .aqua : .darkAqua }
  }

  struct Anchor: Codable {
    let x: Double
    let y: Double
    var point: NSPoint { NSPoint(x: x, y: y) }
  }
  static let maximumBytes = 16 * 1024
  let version: UInt32
  let session: UInt64
  let revision: UInt64
  let windowNumber: Int
  let anchor: Anchor
  let locale: String
  let appearance: Appearance
  let moreLabel: String
  let items: [ProfileMenuItem]

  static func decode(_ data: Data) throws -> ProfileMenuFrame {
    guard !data.isEmpty, data.count <= maximumBytes else { throw InvalidFrame.invalid }
    let frame = try JSONDecoder().decode(Self.self, from: data)
    guard frame.version == 1, frame.session > 0, frame.revision > 0,
      frame.windowNumber > 0, frame.anchor.x.isFinite, frame.anchor.y.isFinite,
      ["en", "zh-Hans", "zh-Hant", "ja"].contains(frame.locale),
      !frame.moreLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      frame.moreLabel.count <= 160, !frame.items.isEmpty, frame.items.count <= 12
    else { throw InvalidFrame.invalid }
    var prior: UInt32 = 0
    for item in frame.items {
      guard item.id.wireValue > prior,
        !item.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
        item.title.count <= 160,
        item.enabled ? item.reason == nil : item.reason != nil,
        item.reason.map({
          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && $0.count <= 1024
        }) ?? true,
        item.danger == (item.id == .delete)
      else { throw InvalidFrame.invalid }
      prior = item.id.wireValue
    }
    return frame
  }

  enum InvalidFrame: Error { case invalid }
}

/// The displayed frame controls presentation only. The receiving Rust use case
/// rechecks all profile, engine, and permission preconditions before mutation.
@MainActor @Observable
final class ProfileMenuModel {
  private(set) var frame: ProfileMenuFrame
  var focused: ProfileMenuAction?
  private(set) var finished = false
  @ObservationIgnored private var callback: ProfileMenuCallback?
  @ObservationIgnored private let context: UInt

  init(_ frame: ProfileMenuFrame, callback: @escaping ProfileMenuCallback, context: UInt) {
    self.frame = frame
    self.callback = callback
    self.context = context
    focused = frame.items.first(where: \.enabled)?.id
  }

  func update(_ next: ProfileMenuFrame) -> Int32 {
    guard !finished, next.session == frame.session else { return 2 }
    guard next.revision > frame.revision, next.windowNumber == frame.windowNumber else { return 0 }
    frame = next
    if !next.items.contains(where: { $0.id == focused && $0.enabled }) {
      focused = next.items.first(where: \.enabled)?.id
    }
    return 1
  }

  func allowed(_ action: ProfileMenuAction) -> Bool {
    !finished && frame.items.contains { $0.id == action && $0.enabled }
  }

  func move(_ offset: Int) {
    let enabled = frame.items.filter(\.enabled).map(\.id)
    guard !enabled.isEmpty else {
      focused = nil
      return
    }
    let current = focused.flatMap { enabled.firstIndex(of: $0) }
    if let current {
      focused = enabled[(current + offset % enabled.count + enabled.count) % enabled.count]
    } else {
      focused = offset < 0 ? enabled.last : enabled.first
    }
  }

  /// Clear the callback before invoking it, including synchronous reentry.
  func complete(_ action: ProfileMenuAction?) {
    guard !finished, action.map(allowed) ?? true else { return }
    finished = true
    let released = callback
    callback = nil
    released?(context, frame.session, action?.wireValue ?? 0)
  }
}

enum ProfileMenuLayout {
  static let rowHeight: CGFloat = 32
  static let scrollPadding: CGFloat = 6
  static let border: CGFloat = 0.5
  static let viewportPadding: CGFloat = 10

  static func contentHeight(itemCount: Int) -> CGFloat {
    CGFloat(itemCount) * rowHeight + 2 * scrollPadding + 2 * border
  }

  static func showsScrollHint(contentHeight: CGFloat, viewportHeight: CGFloat, offset: CGFloat)
    -> Bool
  {
    contentHeight > viewportHeight + 2 && offset + viewportHeight < contentHeight - 2
  }
}

private struct ProfileMenuView: View {
  let model: ProfileMenuModel
  let height: CGFloat
  let choose: (ProfileMenuAction) -> Void
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var contrast
  @State private var showsMore = false

  var body: some View {
    Group {
      if #available(macOS 26, *), !reduceTransparency, contrast != .increased {
        GlassEffectContainer(spacing: 0) {
          content.glassEffect(.regular, in: RoundedRectangle(cornerRadius: 14))
        }
      } else {
        content
          .background(
            Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 14)
          )
          .overlay {
            RoundedRectangle(cornerRadius: 14)
              .stroke(Color(nsColor: .separatorColor), lineWidth: contrast == .increased ? 1 : 0.5)
          }
      }
    }
    .environment(\.locale, Locale(identifier: model.frame.locale))
    .frame(height: height)
    .accessibilityElement(children: .contain)
  }

  private var content: some View {
    VStack(spacing: 0) {
      ScrollViewReader { reader in
        ScrollView {
          VStack(spacing: 0) {
            ForEach(model.frame.items) { item in
              Button {
                choose(item.id)
              } label: {
                HStack(spacing: 10) {
                  Image(systemName: item.icon.symbol).font(.system(size: 14))
                    .frame(width: 22).accessibilityHidden(true)
                  Text(item.title).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.system(size: 13, weight: .medium))
                .padding(.horizontal, 10).frame(height: ProfileMenuLayout.rowHeight)
                .contentShape(Rectangle())
              }
              .buttonStyle(.plain)
              .foregroundStyle(foreground(item))
              .background {
                RoundedRectangle(cornerRadius: 8).fill(highlight(item))
              }
              .disabled(!item.enabled)
              .focusable(false)
              .help(item.reason ?? item.title)
              .accessibilityHint(item.reason ?? "")
              .onHover { hovering in
                if hovering && item.enabled { model.focused = item.id }
              }
              .id(item.id)
            }
          }.padding(ProfileMenuLayout.scrollPadding)
        }
        .scrollIndicators(.automatic)
        .onScrollGeometryChange(for: Bool.self) { geometry in
          ProfileMenuLayout.showsScrollHint(
            contentHeight: geometry.contentSize.height,
            viewportHeight: geometry.containerSize.height,
            offset: geometry.contentOffset.y)
        } action: { _, visible in
          showsMore = visible
        }
        .onChange(of: model.focused) { _, action in
          if let action { reader.scrollTo(action) }
        }
      }
      if showsMore {
        VStack(spacing: 0) {
          Rectangle().fill(.separator).frame(height: ProfileMenuLayout.border)
          HStack(spacing: 6) {
            Text(model.frame.moreLabel)
            Image(systemName: "chevron.down").accessibilityHidden(true)
          }
          .font(.system(size: 11, weight: .semibold))
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity)
          .padding(.top, 6).padding(.bottom, 8).padding(.horizontal, 10)
        }
        .fixedSize(horizontal: false, vertical: true)
        .background(.quaternary)
        .accessibilityHidden(true)
      }
    }
    .padding(ProfileMenuLayout.border)
    .clipShape(RoundedRectangle(cornerRadius: 14))
  }

  private func foreground(_ item: ProfileMenuItem) -> Color {
    if !item.enabled { return Color(nsColor: .disabledControlTextColor) }
    if model.focused == item.id { return .white }
    return item.danger ? .red : .primary
  }

  private func highlight(_ item: ProfileMenuItem) -> Color {
    guard item.enabled, model.focused == item.id else { return .clear }
    return item.danger ? .red : .accentColor
  }
}

private final class ProfileMenuPanel: NSPanel {
  override var canBecomeKey: Bool { true }
  override var canBecomeMain: Bool { false }
}

@MainActor
final class ProfileMenuWindow: NSObject, NSWindowDelegate {
  let model: ProfileMenuModel
  let panel: NSPanel
  private weak var parent: NSWindow?
  private weak var priorResponder: NSResponder?
  private var observers: [NSObjectProtocol] = []
  private var mouseMonitor: Any?
  private var keyMonitor: Any?
  private var closing = false

  init(
    frame: ProfileMenuFrame, parent: NSWindow, callback: @escaping ProfileMenuCallback,
    context: UInt
  ) {
    self.parent = parent
    priorResponder = parent.firstResponder
    model = ProfileMenuModel(frame, callback: callback, context: context)
    panel = ProfileMenuPanel(
      contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered,
      defer: false)
    super.init()
    panel.isReleasedWhenClosed = false
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.hidesOnDeactivate = true
    panel.level = .popUpMenu
    panel.collectionBehavior = [.transient, .fullScreenAuxiliary]
    panel.delegate = self
  }

  static func geometry(_ frame: ProfileMenuFrame, parent: NSWindow) -> NSRect? {
    // The decorated Tauri host fills contentLayoutRect with its WebView. Match
    // positionGlassMenu's viewport coordinates before applying display bounds.
    let viewport = parent.convertToScreen(parent.contentLayoutRect)
    guard parent.isVisible, containsInclusive(viewport, frame.anchor.point),
      let screen = NSScreen.screens.first(where: { $0.frame.contains(frame.anchor.point) })
        ?? parent.screen
    else { return nil }
    let visible = viewport.intersection(screen.visibleFrame)
    guard !visible.isNull, visible.width > 0, visible.height > 0 else { return nil }
    let pad = ProfileMenuLayout.viewportPadding
    let width = min(248, viewport.width - 2 * pad, visible.width)
    let height = min(
      440, viewport.height * 0.7, visible.height,
      ProfileMenuLayout.contentHeight(itemCount: frame.items.count))
    guard width >= 1, height >= 1 else { return nil }
    var left = frame.anchor.x - viewport.minX
    var top = viewport.maxY - frame.anchor.y
    // The original menu only applies the 10px padding when right/bottom would
    // overflow. Near top/left, its original click position is retained.
    if left + width > viewport.width - pad {
      left = max(pad, viewport.width - width - pad)
    }
    if top + height > viewport.height - pad {
      top = max(pad, viewport.height - height - pad)
    }
    // JS Math.round runs on nonnegative CSS coordinates, before screen origin.
    let x = viewport.minX + floor(left + 0.5)
    let y = viewport.maxY - floor(top + 0.5) - height
    return NSRect(
      x: min(max(x, visible.minX), visible.maxX - width),
      y: min(max(y, visible.minY), visible.maxY - height),
      width: width, height: height)
  }

  func show(_ rectangle: NSRect) {
    guard !closing, let parent else { return }
    installView(rectangle)
    parent.addChildWindow(panel, ordered: .above)
    panel.makeKeyAndOrderFront(nil)
    panel.makeFirstResponder(panel.contentView)
    observe(NSApplication.didResignActiveNotification, object: NSApp)
    observe(NSWindow.willCloseNotification, object: parent)
    observe(NSWindow.didResizeNotification, object: parent)
    observe(NSWindow.didMoveNotification, object: parent)
    observe(NSWindow.didMiniaturizeNotification, object: parent)
    mouseMonitor = NSEvent.addLocalMonitorForEvents(matching: [
      .leftMouseDown, .rightMouseDown, .otherMouseDown,
    ]) {
      [weak self] event in
      let consumed = MainActor.assumeIsolated {
        guard let self, event.window !== self.panel else { return false }
        // Match the former page backdrop: a click in the parent content only
        // dismisses the menu. Titlebar controls and other windows still work.
        let contentClick =
          event.window === self.parent
          && self.parent?.contentLayoutRect.contains(event.locationInWindow) == true
        self.finish(nil)
        return contentClick
      }
      return consumed ? nil : event
    }
    keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      let consumed = MainActor.assumeIsolated { self?.consumeKey(event) ?? false }
      return consumed ? nil : event
    }
  }

  func update(_ frame: ProfileMenuFrame) -> Int32 {
    guard !closing, let parent, let rectangle = Self.geometry(frame, parent: parent) else {
      return 2
    }
    let status = model.update(frame)
    if status == 1 { installView(rectangle) }
    return status
  }

  private func installView(_ rectangle: NSRect) {
    // Page appearance can differ from the host window or system appearance.
    // Apply only an accepted frame, so stale updates cannot recolor the menu.
    panel.appearance = NSAppearance(named: model.frame.appearance.name)
    panel.setFrame(rectangle, display: false)
    panel.contentView = NSHostingView(
      rootView: ProfileMenuView(model: model, height: rectangle.height) {
        [weak self] action in self?.choose(action)
      })
  }

  private func observe(_ name: Notification.Name, object: AnyObject) {
    observers.append(
      NotificationCenter.default.addObserver(forName: name, object: object, queue: .main) {
        [weak self] _ in MainActor.assumeIsolated { self?.finish(nil) }
      })
  }

  func choose(_ action: ProfileMenuAction) {
    guard model.allowed(action) else { return }
    finish(action)
  }

  func consumeKey(_ event: NSEvent) -> Bool {
    guard !closing, event.window === panel,
      event.modifierFlags.intersection([.command, .control, .option]).isEmpty
    else { return false }
    switch event.keyCode {
    case 53: finish(nil)
    case 125: model.move(1)
    case 126: model.move(-1)
    case 48: model.move(event.modifierFlags.contains(.shift) ? -1 : 1)
    case 115: model.focused = model.frame.items.first(where: \.enabled)?.id
    case 119: model.focused = model.frame.items.last(where: \.enabled)?.id
    case 36, 76, 49:
      if let focused = model.focused { choose(focused) }
    default: return false
    }
    return true
  }

  func windowWillClose(_ notification: Notification) { finish(nil) }
  func windowDidResignKey(_ notification: Notification) { finish(nil) }

  func finish(_ action: ProfileMenuAction?) {
    guard !closing, action.map(model.allowed) ?? true else { return }
    closing = true
    let ownedFocus = panel.isKeyWindow
    if let mouseMonitor { NSEvent.removeMonitor(mouseMonitor) }
    if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
    mouseMonitor = nil
    keyMonitor = nil
    for observer in observers { NotificationCenter.default.removeObserver(observer) }
    observers.removeAll()
    parent?.removeChildWindow(panel)
    panel.orderOut(nil)
    panel.close()
    if ownedFocus, NSApp.isActive, let parent, parent.isVisible {
      parent.makeKey()
      if let priorResponder { parent.makeFirstResponder(priorResponder) }
    }
    if profileMenu === self { profileMenu = nil }
    model.complete(action)
  }
}

@MainActor private var profileMenu: ProfileMenuWindow?
@MainActor private var newestProfileMenuSession: UInt64 = 0

@_cdecl("cfm_profile_menu_present_v1")
func profileMenuPresent(
  _ bytes: UnsafePointer<UInt8>?, _ count: Int, _ callback: ProfileMenuCallback?, _ context: UInt
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= ProfileMenuFrame.maximumBytes, let callback else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? ProfileMenuFrame.decode(data) else { return 0 }
    guard frame.session > newestProfileMenuSession else { return 2 }
    guard let parent = NSApp?.windows.first(where: { $0.windowNumber == frame.windowNumber }),
      let rectangle = ProfileMenuWindow.geometry(frame, parent: parent)
    else { return 0 }
    let next = ProfileMenuWindow(frame: frame, parent: parent, callback: callback, context: context)
    let previous = profileMenu
    profileMenu = next
    newestProfileMenuSession = frame.session
    previous?.finish(nil)
    next.show(rectangle)
    return 1
  }
}

@_cdecl("cfm_profile_menu_update_v1")
func profileMenuUpdate(_ bytes: UnsafePointer<UInt8>?, _ count: Int) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= ProfileMenuFrame.maximumBytes else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let frame = try? ProfileMenuFrame.decode(data) else { return 0 }
    guard let profileMenu, profileMenu.model.frame.session == frame.session else { return 2 }
    return profileMenu.update(frame)
  }
}

@_cdecl("cfm_profile_menu_dismiss_v1")
func profileMenuDismiss(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let profileMenu, profileMenu.model.frame.session == session else { return 2 }
    profileMenu.finish(nil)
    return 1
  }
}

/// The host supplies the actual WKWebView obtained from Tauri's with_webview
/// callback. The pointer is borrowed for this call; it is never retained.
@_cdecl("cfm_profile_menu_anchor_v1")
func profileMenuAnchor(
  _ borrowedView: UnsafeMutableRawPointer?, _ clientX: Double, _ clientY: Double,
  _ viewportWidth: Double, _ viewportHeight: Double,
  _ windowNumber: UnsafeMutablePointer<Int64>?, _ screenX: UnsafeMutablePointer<Double>?,
  _ screenY: UnsafeMutablePointer<Double>?
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let borrowedView, let windowNumber, let screenX, let screenY,
    clientX.isFinite, clientY.isFinite, viewportWidth.isFinite, viewportHeight.isFinite,
    viewportWidth > 0, viewportHeight > 0, clientX >= 0, clientY >= 0,
    clientX <= viewportWidth, clientY <= viewportHeight
  else { return 0 }
  let view = Unmanaged<NSView>.fromOpaque(borrowedView).takeUnretainedValue()
  let result: (Int32, Int64, Double, Double) = MainActor.assumeIsolated {
    guard let window = view.window, window.isVisible,
      NSApp?.windows.contains(where: { $0 === window }) == true
    else { return (2, 0, 0, 0) }
    let bounds = view.bounds
    guard bounds.width.isFinite, bounds.height.isFinite, bounds.minX.isFinite, bounds.minY.isFinite,
      bounds.width > 0, bounds.height > 0
    else { return (0, 0, 0, 0) }
    let point = NSPoint(
      x: bounds.minX + clientX / viewportWidth * bounds.width,
      y: view.isFlipped
        ? bounds.minY + clientY / viewportHeight * bounds.height
        : bounds.maxY - clientY / viewportHeight * bounds.height)
    let screenPoint = window.convertPoint(toScreen: view.convert(point, to: nil))
    guard screenPoint.x.isFinite, screenPoint.y.isFinite,
      containsInclusive(window.frame, screenPoint)
    else { return (0, 0, 0, 0) }
    return (1, Int64(window.windowNumber), screenPoint.x, screenPoint.y)
  }
  guard result.0 == 1 else { return result.0 }
  windowNumber.pointee = result.1
  screenX.pointee = result.2
  screenY.pointee = result.3
  return 1
}

private func containsInclusive(_ rectangle: NSRect, _ point: NSPoint) -> Bool {
  point.x >= rectangle.minX && point.x <= rectangle.maxX
    && point.y >= rectangle.minY && point.y <= rectangle.maxY
}
