import AppKit
import SwiftUI

typealias DashboardClosed = @convention(c) (UInt) -> Void

/// AppKit owns exactly one observation window. It never owns the VPN session.
@MainActor
private final class DashboardWindow: NSObject, NSWindowDelegate {
  let model = OverviewModel()
  let window: NSWindow
  private var closed: DashboardClosed?
  private var context: UInt = 0

  override init() {
    window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 980, height: 680),
      styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
      backing: .buffered, defer: false)
    super.init()
    window.title = "Clash for Mac · 0.5"
    window.isReleasedWhenClosed = false
    window.contentMinSize = NSSize(width: 850, height: 603)
    window.contentView = NSHostingView(
      rootView: OverviewView(
        model: model,
        onClose: { [weak self] in
          self?.window.close()
        }))
    window.delegate = self
    window.center()
  }

  func present(_ frame: OverviewFrame, closed: @escaping DashboardClosed, context: UInt) throws {
    try model.beginSession(frame)
    endSubscription()
    self.closed = closed
    self.context = context
    window.makeKeyAndOrderFront(nil)
  }

  func windowWillClose(_ notification: Notification) { endSubscription() }

  private func endSubscription() {
    let callback = closed
    let pointer = context
    closed = nil
    context = 0
    callback?(pointer)
  }
}

@MainActor private var dashboard: DashboardWindow?

// ABI status: 0 rejected, 1 accepted, 2 window hidden, 3 wrong thread.
// All pointers are borrowed only for this synchronous call. A successful
// present transfers exactly one callback/context pair until close/replacement.
@_cdecl("cfm_dashboard_present_v1")
func dashboardPresent(
  _ bytes: UnsafePointer<UInt8>?, _ count: Int,
  _ closed: DashboardClosed?, _ context: UInt
) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= OverviewFrame.maximumBytes, let closed, context != 0 else {
    return 0
  }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    do {
      let frame = try OverviewFrame.decode(data)
      _ = NSApplication.shared
      let controller = dashboard ?? DashboardWindow()
      try controller.present(frame, closed: closed, context: context)
      dashboard = controller
      return 1
    } catch { return 0 }
  }
}

@_cdecl("cfm_dashboard_publish_v1")
func dashboardPublish(_ bytes: UnsafePointer<UInt8>?, _ count: Int) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  guard let bytes, count > 0, count <= OverviewFrame.maximumBytes else { return 0 }
  let data = Data(bytes: bytes, count: count)
  return MainActor.assumeIsolated {
    guard let dashboard, dashboard.window.isVisible else { return 2 }
    do {
      let frame = try OverviewFrame.decode(data)
      guard frame.session == dashboard.model.frame?.session else { return 2 }
      try dashboard.model.accept(frame)
      return 1
    } catch {
      dashboard.model.rejectDelivery()
      return 0
    }
  }
}

@_cdecl("cfm_dashboard_invalidate_v1")
func dashboardInvalidate(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let dashboard, dashboard.model.frame?.session == session else { return 2 }
    dashboard.model.rejectDelivery()
    return 1
  }
}

@_cdecl("cfm_dashboard_close_v1")
func dashboardClose(_ session: UInt64) -> Int32 {
  guard Thread.isMainThread else { return 3 }
  return MainActor.assumeIsolated {
    guard let dashboard, dashboard.window.isVisible, dashboard.model.frame?.session == session
    else { return 2 }
    dashboard.window.close()
    return 1
  }
}
