import AppKit
import Foundation
import Testing
import WebKit

@testable import CFMNativeDashboard

private func glassPayload(
  _ fields: [String: Any] = [:], panels: [[String: Any]]? = nil
) throws -> Data {
  var value: [String: Any] = [
    "version": 1, "session": 1, "sequence": 1, "acknowledgedSubmission": 0, "windowNumber": 1,
    "appearance": "light", "viewport": ["width": 800, "height": 500],
    "panels": panels ?? [
      [
        "id": "sidebar", "kind": "panel", "x": 0, "y": 0, "width": 200, "height": 500, "radius": 24,
      ],
      [
        "id": "traffic", "kind": "card", "x": 12, "y": 12, "width": 176, "height": 80, "radius": 16,
      ],
      [
        "id": "nav-active", "kind": "pill", "x": 12, "y": 120, "width": 176, "height": 44,
        "radius": 0,
      ],
      ["id": "status", "kind": "strip", "x": 0, "y": 0, "width": 800, "height": 28, "radius": 0],
    ],
  ]
  for (key, field) in fields { value[key] = field }
  return try JSONSerialization.data(withJSONObject: value)
}

@MainActor private final class GlassProbe {
  var closedSessions: [UInt64] = []
  var context: UInt { UInt(bitPattern: Unmanaged.passUnretained(self).toOpaque()) }
}
private let glassEvent: WindowGlassEventCallback = { _, _, _, _ in
  Issue.record("the backdrop reports no events")
  return 0
}
private let glassClosed: WindowGlassClosedCallback = { context, session in
  guard let pointer = UnsafeRawPointer(bitPattern: context) else { return }
  let probe = Unmanaged<GlassProbe>.fromOpaque(pointer).takeUnretainedValue()
  MainActor.assumeIsolated { probe.closedSessions.append(session) }
}

@MainActor private func glassHost() -> (NSWindow, WKWebView) {
  NSApplication.shared.setActivationPolicy(.prohibited)
  let parent = NSPanel(
    contentRect: NSRect(x: 70, y: 100, width: 840, height: 560),
    styleMask: [.titled, .closable, .nonactivatingPanel], backing: .buffered, defer: false)
  parent.isReleasedWhenClosed = false
  let webview = WKWebView(frame: NSRect(x: 20, y: 30, width: 800, height: 500))
  parent.contentView?.addSubview(webview)
  parent.orderFront(nil)
  RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))
  return (parent, webview)
}

@MainActor private var glassTestSession: UInt64 = 90_000
@MainActor private func nextGlassSession() -> UInt64 {
  glassTestSession += 1
  return glassTestSession
}

@MainActor private func present(
  _ data: Data, probe: GlassProbe
) -> Int32 {
  data.withUnsafeBytes { buffer in
    windowGlassPresent(
      buffer.bindMemory(to: UInt8.self).baseAddress, data.count, glassEvent, glassClosed,
      probe.context)
  }
}

@MainActor private func update(_ data: Data) -> Int32 {
  data.withUnsafeBytes { buffer in
    windowGlassUpdate(buffer.bindMemory(to: UInt8.self).baseAddress, data.count)
  }
}

@Suite(.serialized) struct WindowGlassTests {
  @Test func frameIsStrictAboutKeysKindsBoundsAndIdentifiers() throws {
    let frame = try WindowGlassFrame.decode(glassPayload())
    #expect(frame.panels.count == 4)
    #expect(frame.panels[2].kind == .pill)
    for fields: [String: Any] in [
      ["version": 2], ["session": 0], ["sequence": 0], ["acknowledgedSubmission": 1],
      ["windowNumber": 0], ["appearance": "system"], ["viewport": ["width": 0, "height": 500]],
      ["viewport": ["width": 800, "height": 500, "scale": 2]], ["extra": true],
    ] {
      #expect(throws: (any Error).self) { try WindowGlassFrame.decode(glassPayload(fields)) }
    }
    for panels: [[String: Any]] in [
      [["id": "Sidebar", "kind": "panel", "x": 0, "y": 0, "width": 1, "height": 1, "radius": 0]],
      [["id": "a", "kind": "window", "x": 0, "y": 0, "width": 1, "height": 1, "radius": 0]],
      [["id": "a", "kind": "panel", "x": 0, "y": 0, "width": -1, "height": 1, "radius": 0]],
      [["id": "a", "kind": "panel", "x": 0, "y": 0, "width": 1, "height": 1, "radius": 65]],
      [["id": "a", "kind": "panel", "x": 0, "y": 0, "width": 1, "height": 1]],
      [
        ["id": "a", "kind": "panel", "x": 0, "y": 0, "width": 1, "height": 1, "radius": 0],
        ["id": "a", "kind": "card", "x": 0, "y": 0, "width": 1, "height": 1, "radius": 0],
      ],
      Array(
        repeating: [
          "id": "a", "kind": "panel", "x": 0, "y": 0, "width": 1, "height": 1, "radius": 0,
        ],
        count: 33),
    ] {
      #expect(throws: (any Error).self) {
        try WindowGlassFrame.decode(glassPayload(panels: panels))
      }
    }
    #expect(throws: (any Error).self) {
      try WindowGlassFrame.decode(Data(repeating: 0x20, count: WindowGlassFrame.maximumBytes + 1))
    }
  }

  @Test @MainActor func backdropSitsBelowThePageAndFollowsItsGeometry() throws {
    let (parent, webview) = glassHost()
    defer { parent.close() }
    let probe = GlassProbe()
    let session = nextGlassSession()
    #expect(
      present(
        try glassPayload(["session": session, "windowNumber": parent.windowNumber]),
        probe: probe) == 1)
    let container = try #require(webview.superview)
    let backdrop = try #require(
      container.subviews.first(where: { $0 is WindowGlassBackdrop }) as? WindowGlassBackdrop)
    let order = container.subviews.map { ObjectIdentifier($0) }
    let backdropIndex = try #require(order.firstIndex(of: ObjectIdentifier(backdrop)))
    let webviewIndex = try #require(order.firstIndex(of: ObjectIdentifier(webview)))
    #expect(backdropIndex < webviewIndex, "the glass is under the page")
    #expect(backdrop.frame == container.bounds)
    #expect(backdrop.hitTest(NSPoint(x: 10, y: 10)) == nil, "the page keeps every click")
    let controller = try #require(currentWindowGlass())
    let placed = Dictionary(uniqueKeysWithValues: controller.model.placements.map { ($0.id, $0) })
    // The webview starts 20 pt from the container's left edge and the DOM's
    // top-left is the webview's top-left in the flipped backdrop.
    let sidebar = try #require(placed["sidebar"])
    #expect(sidebar.rect.minX == 20)
    #expect(sidebar.rect.minY == container.bounds.height - 30 - 500)
    #expect(sidebar.rect.size == CGSize(width: 200, height: 500))
    #expect(sidebar.radius == 24)
    let pill = try #require(placed["nav-active"])
    #expect(pill.radius == 22, "a pill is a capsule whatever radius the page sent")
    #expect(controller.model.dark == false)

    let darker = try glassPayload([
      "session": session, "sequence": 2, "windowNumber": parent.windowNumber,
      "appearance": "dark",
    ])
    #expect(update(darker) == 1)
    #expect(controller.model.dark)
    #expect(
      update(
        try glassPayload(["session": session, "sequence": 2, "windowNumber": parent.windowNumber]))
        == 0, "a sequence that does not advance is refused")
    #expect(
      update(try glassPayload(["session": session, "sequence": 3, "windowNumber": 9999])) == 0,
      "the window cannot change")
    #expect(
      update(
        try glassPayload([
          "session": session, "sequence": 3, "windowNumber": parent.windowNumber,
          "viewport": ["width": 790, "height": 500],
        ])) == 2, "a viewport the view no longer has is stale")
    #expect(update(try glassPayload(["session": session + 500, "sequence": 9])) == 2)
    #expect(probe.closedSessions.isEmpty)
    #expect(windowGlassDismiss(session) == 1)
    #expect(probe.closedSessions == [session])
    #expect(backdrop.superview == nil)
    #expect(windowGlassDismiss(session) == 2)
  }

  @Test @MainActor func presentIsRefusedWithoutAVisibleWebviewWindowAndStaleSessionsLose() throws {
    let probe = GlassProbe()
    let session = nextGlassSession()
    #expect(
      present(try glassPayload(["session": session, "windowNumber": 123_456]), probe: probe) == 0)
    let empty = NSPanel(
      contentRect: NSRect(x: 0, y: 0, width: 300, height: 200), styleMask: [.titled],
      backing: .buffered, defer: false)
    empty.isReleasedWhenClosed = false
    empty.orderFront(nil)
    defer { empty.close() }
    #expect(
      present(
        try glassPayload(["session": session, "windowNumber": empty.windowNumber]), probe: probe)
        == 0, "a window without a page has nothing to stand behind")
    let (parent, _) = glassHost()
    defer { parent.close() }
    #expect(
      present(
        try glassPayload([
          "session": session, "windowNumber": parent.windowNumber,
          "viewport": ["width": 600, "height": 500],
        ]), probe: probe) == 0, "a viewport that does not match the page is refused")
    let same = try glassPayload(["session": session, "windowNumber": parent.windowNumber])
    #expect(present(same, probe: probe) == 1)
    #expect(present(same, probe: probe) == 2, "the same session again is stale")
    #expect(probe.closedSessions.isEmpty)
    let later = nextGlassSession()
    let replacement = try glassPayload(["session": later, "windowNumber": parent.windowNumber])
    #expect(present(replacement, probe: probe) == 1)
    #expect(probe.closedSessions == [session], "a replacement closes the earlier backdrop first")
    #expect(windowGlassDismiss(later) == 1)
    #expect(probe.closedSessions == [session, later])
    #expect(windowGlassPresent(nil, 0, glassEvent, glassClosed, probe.context) == 0)
  }

  @Test @MainActor func closingTheWindowReturnsTheContextOnce() throws {
    let (parent, webview) = glassHost()
    let probe = GlassProbe()
    let session = nextGlassSession()
    let frame = try glassPayload(["session": session, "windowNumber": parent.windowNumber])
    #expect(present(frame, probe: probe) == 1)
    parent.close()
    #expect(probe.closedSessions == [session])
    #expect(webview.superview?.subviews.contains(where: { $0 is WindowGlassBackdrop }) == false)
    #expect(windowGlassDismiss(session) == 2)
    #expect(probe.closedSessions == [session])
  }

  @Test func wrongThreadIsRefusedWithoutTouchingAnything() async throws {
    // The frame is well formed, so status 3 can only come from the thread check.
    let data = try glassPayload()
    let presented = await Task.detached {
      data.withUnsafeBytes {
        windowGlassPresent(
          $0.bindMemory(to: UInt8.self).baseAddress, $0.count, glassEvent, glassClosed, 0)
      }
    }.value
    #expect(presented == 3)
    let updated = await Task.detached {
      data.withUnsafeBytes {
        windowGlassUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
      }
    }.value
    #expect(updated == 3)
    #expect(await Task.detached { windowGlassDismiss(1) }.value == 3)
  }
}
