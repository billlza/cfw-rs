import AppKit
import SwiftUI

/// The page's dialog sheet (`.glass-dialog`: one translucent sheet, radius 16)
/// in the system's material: a single Liquid Glass shape where the system has
/// one, a material sheet before that, and an opaque sheet when the user asked
/// for less transparency or more contrast.
struct DialogSheet: ViewModifier {
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var contrast

  func body(content: Content) -> some View {
    Group {
      if #available(macOS 26, *), !opaque {
        content.glassEffect(.regular, in: shape)
      } else {
        content
          .background {
            if opaque {
              shape.fill(Color(nsColor: .windowBackgroundColor))
            } else {
              shape.fill(.regularMaterial)
            }
          }
          .overlay { shape.stroke(.separator, lineWidth: contrast == .increased ? 1 : 0.5) }
      }
    }
    .clipShape(shape)
  }

  private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: 16) }
  private var opaque: Bool { reduceTransparency || contrast == .increased }
}

/// The page's pill button (`.glass-btn`: a solid fill, 13px/600, radius 999)
/// as a solid system capsule, so no control stacks glass on the glass sheet.
/// No kind answers Return, as on the page: a destructive action is never the
/// keyboard default. Only the cancel kind answers Escape.
struct DialogButton: View {
  enum Kind { case cancel, action, destructive }

  /// The system control size nearest the page pill, which is `padding: 7px
  /// 14px` around one line of 13px text, about 30px high: this size is 28
  /// high with 14 beside the label.
  static let controlSize: ControlSize = .large
  /// The `.glass-btn` and `.glass-btn.danger` fills.
  private static let blue = Color(.sRGB, red: 0, green: 122 / 255, blue: 1, opacity: 0.95)
  private static let red = Color(.sRGB, red: 1, green: 69 / 255, blue: 58 / 255, opacity: 0.95)

  let title: String
  let kind: Kind
  let action: () -> Void

  var body: some View {
    Group {
      switch kind {
      case .cancel:
        Button(action: action) { label }.buttonStyle(.bordered).keyboardShortcut(.cancelAction)
      case .action:
        Button(action: action) { label }.buttonStyle(.borderedProminent).tint(Self.blue)
      case .destructive:
        Button(role: .destructive, action: action) { label }
          .buttonStyle(.borderedProminent).tint(Self.red)
      }
    }
    .buttonBorderShape(.capsule)
  }

  private var label: some View { Text(title).font(.system(size: 13, weight: .semibold)) }
}

/// The page's `.glass-dialog-actions` row: trailing buttons 8 apart, 4 below
/// the content gap, at the shared button size.
struct DialogActions<Buttons: View>: View {
  private let buttons: Buttons

  init(@ViewBuilder buttons: () -> Buttons) { self.buttons = buttons() }

  var body: some View {
    HStack(spacing: 8) {
      Spacer(minLength: 0)
      buttons
    }
    .controlSize(DialogButton.controlSize).padding(.top, 4)
  }
}

/// Key-capable borderless panel of a centered dialog. The window that hosts it
/// decides every attribute; a subclass adds only its own event handling.
class CenteredDialogPanel: NSPanel {
  override var canBecomeKey: Bool { true }
  override var canBecomeMain: Bool { false }

  required override init(
    contentRect: NSRect, styleMask style: NSWindow.StyleMask,
    backing backingStoreType: NSWindow.BackingStoreType, defer flag: Bool
  ) {
    super.init(contentRect: contentRect, styleMask: style, backing: backingStoreType, defer: flag)
  }
}

/// Hosts one dialog as a child panel centered in its parent's content area.
/// The panel follows the parent, hides with it and ends exactly once. What the
/// dialog shows, and when the user may cancel it, belong to its family.
@MainActor
class CenteredDialogWindow: NSObject, NSWindowDelegate {
  /// The page's `width: min(maximumWidth, calc(100vw - horizontalMargin))`.
  /// Height follows the measured content, up to the viewport less its margin.
  struct Metrics {
    let maximumWidth: CGFloat
    let horizontalMargin: CGFloat
    let verticalMargin: CGFloat
  }

  struct Content {
    /// User cancellation is refused while this is true. A dialog the user may
    /// always cancel keeps the default.
    var busy: () -> Bool = { false }
    /// The installed root view. Its cancel and relayout actions return here.
    let surface: (_ cancel: @escaping () -> Void, _ relayout: @escaping () -> Void) -> NSView
    /// The unclipped content at a width; its fitting height sizes the panel.
    let measured: (_ width: CGFloat) -> NSView
    /// The parent's content height, published before each measurement.
    var viewportHeightChanged: (CGFloat) -> Void = { _ in }
    /// Runs once, after the panel has left the screen.
    let finished: () -> Void
  }

  let panel: NSPanel
  private let metrics: Metrics
  private let content: Content
  private weak var parent: NSWindow?
  private weak var priorResponder: NSResponder?
  private var observers: [NSObjectProtocol] = []
  private var closing = false

  init(
    parent: NSWindow, appearance: NSAppearance.Name, metrics: Metrics, content: Content,
    panelClass: CenteredDialogPanel.Type = CenteredDialogPanel.self
  ) {
    self.parent = parent
    priorResponder = parent.firstResponder
    self.metrics = metrics
    self.content = content
    // An ordinary activating panel: the nonactivating policy can leave the
    // parent inactive after dismissal, so its next click is lost.
    panel = panelClass.init(
      contentRect: .zero, styleMask: [.borderless],
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
    panel.appearance = NSAppearance(named: appearance)
  }

  func show() -> Bool {
    guard !closing, let parent, parent.isVisible, layout() else { return false }
    panel.contentView = content.surface(
      { [weak self] in self?.cancel() }, { [weak self] in _ = self?.layout() })
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
    let width = min(metrics.maximumWidth, viewport.width - metrics.horizontalMargin)
    let maximumHeight = viewport.height - metrics.verticalMargin
    content.viewportHeightChanged(viewport.height)
    guard width >= 1, maximumHeight >= 1 else { return false }
    let measure = content.measured(width)
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
    // Ordering a child window out detaches it. Attached again, it keeps its
    // place above the parent when the parent is clicked.
    if panel.parent !== parent { parent.addChildWindow(panel, ordered: .above) }
    if !panel.isVisible { panel.orderFront(nil) }
  }

  /// Applies the page theme of an accepted frame, then fits its content.
  func refresh(appearance: NSAppearance.Name) {
    panel.appearance = NSAppearance(named: appearance)
    _ = layout()
  }

  func cancel() { if !content.busy() { finish() } }
  func windowShouldClose(_ sender: NSWindow) -> Bool { !content.busy() }
  func windowWillClose(_ notification: Notification) { finish() }

  private func observe(
    _ name: Notification.Name, object: AnyObject,
    action: @escaping @MainActor (CenteredDialogWindow) -> Void
  ) {
    observers.append(
      NotificationCenter.default.addObserver(forName: name, object: object, queue: .main) {
        [weak self] _ in MainActor.assumeIsolated { if let self { action(self) } }
      })
  }

  /// Unconditional and idempotent: closing the parent, a host dismissal and
  /// the panel's own close all arrive here, and the family is told once.
  func finish() {
    guard !closing else { return }
    closing = true
    let ownedFocus = panel.isKeyWindow
    for observer in observers { NotificationCenter.default.removeObserver(observer) }
    observers.removeAll()
    parent?.removeChildWindow(panel)
    panel.orderOut(nil)
    panel.close()
    if ownedFocus, NSApp.isActive { returnFocusToParent() }
    content.finished()
  }

  /// Key status and the responder the parent had before the dialog go back to
  /// a parent that is still on screen.
  func returnFocusToParent() {
    guard let parent, parent.isVisible else { return }
    parent.makeKey()
    if let priorResponder { parent.makeFirstResponder(priorResponder) }
  }
}
