import AppKit
import Foundation
import Testing

@testable import CFMNativeDashboard

private func menuPayload(_ fields: [String: Any] = [:]) throws -> Data {
  var value: [String: Any] = [
    "version": 1, "session": 1, "revision": 1, "windowNumber": 1,
    "anchor": ["x": 100.0, "y": 100.0], "locale": "en", "appearance": "light",
    "moreLabel": "scroll to view more",
    "items": ProfileMenuAction.allCases.map { action -> [String: Any] in
      [
        "id": action.rawValue, "title": action.rawValue, "icon": "edit", "enabled": true,
        "reason": NSNull(), "danger": action == .delete,
      ]
    },
  ]
  for (key, field) in fields { value[key] = field }
  return try JSONSerialization.data(withJSONObject: value)
}

private func menuItems(_ change: (inout [[String: Any]]) -> Void) throws -> Data {
  var value = try #require(JSONSerialization.jsonObject(with: menuPayload()) as? [String: Any])
  var items = try #require(value["items"] as? [[String: Any]])
  change(&items)
  value["items"] = items
  return try JSONSerialization.data(withJSONObject: value)
}

private let menuCallback: ProfileMenuCallback = { context, session, action in
  guard let values = UnsafeMutablePointer<UInt64>(bitPattern: context) else { return }
  values[0] += 1
  values[1] = session
  values[2] = UInt64(action)
}

@MainActor private func withMenuLog(
  _ operation: @MainActor (UnsafeMutablePointer<UInt64>) throws -> Void
) rethrows {
  let values = UnsafeMutablePointer<UInt64>.allocate(capacity: 3)
  values.initialize(repeating: 0, count: 3)
  defer {
    values.deinitialize(count: 3)
    values.deallocate()
  }
  try operation(values)
}

@Suite(.serialized)
struct ProfileMenuTests {
  @Test func orderedClosedWireContractAndBoundaries() throws {
    let frame = try ProfileMenuFrame.decode(menuPayload())
    #expect(frame.items.map(\.id.wireValue) == Array(1...12))
    let subset = try menuItems { $0 = [$0[0], $0[3], $0[11]] }
    #expect(try ProfileMenuFrame.decode(subset).items.count == 3)
    for fields: [String: Any] in [
      ["version": 2], ["session": 0], ["session": -1], ["revision": 0],
      ["windowNumber": 0], ["locale": "future"], ["moreLabel": ""],
      ["moreLabel": String(repeating: "a", count: 161)], ["items": []],
    ] {
      #expect(throws: (any Error).self) { try ProfileMenuFrame.decode(menuPayload(fields)) }
    }
    let validBoundary = try menuItems {
      $0[0]["title"] = String(repeating: "字", count: 160)
      $0[0]["enabled"] = false
      $0[0]["reason"] = String(repeating: "字", count: 1024)
    }
    #expect(try ProfileMenuFrame.decode(validBoundary).items.count == 12)
    #expect(throws: (any Error).self) { try ProfileMenuFrame.decode(Data()) }
    #expect(throws: (any Error).self) {
      try ProfileMenuFrame.decode(Data(repeating: 32, count: 16_385))
    }
    let notFinite = String(decoding: try menuPayload(), as: UTF8.self)
      .replacingOccurrences(of: "100", with: "1e999")
    #expect(throws: (any Error).self) { try ProfileMenuFrame.decode(Data(notFinite.utf8)) }
  }

  @Test func invalidItemsCannotCreateAnAction() throws {
    let mutations: [(inout [[String: Any]]) -> Void] = [
      { $0.swapAt(0, 1) }, { $0[1] = $0[0] }, { $0.append($0[0]) },
      { $0[0]["id"] = "run-command" }, { $0[0]["icon"] = "network" },
      { $0[0]["title"] = " " }, { $0[0]["title"] = String(repeating: "a", count: 161) },
      { $0[0]["enabled"] = false }, { $0[0]["reason"] = "must be disabled" },
      {
        $0[0]["enabled"] = false
        $0[0]["reason"] = ""
      },
      {
        $0[0]["enabled"] = false
        $0[0]["reason"] = String(repeating: "a", count: 1025)
      },
      { $0[0]["danger"] = true }, { $0[11]["danger"] = false },
    ]
    for mutation in mutations {
      #expect(throws: (any Error).self) { try ProfileMenuFrame.decode(menuItems(mutation)) }
    }
  }

  @Test @MainActor func updateAndDisabledSelectionPreserveCallbackOwnership() throws {
    try withMenuLog { log throws in
      let frame = try ProfileMenuFrame.decode(
        menuItems {
          $0[0]["enabled"] = false
          $0[0]["reason"] = "Already selected"
        })
      let model = ProfileMenuModel(frame, callback: menuCallback, context: UInt(bitPattern: log))
      #expect(model.focused == .edit)
      model.complete(.select)
      #expect(log[0] == 0)
      #expect(model.update(try ProfileMenuFrame.decode(menuPayload())) == 0)
      #expect(model.update(try ProfileMenuFrame.decode(menuPayload(["session": 2]))) == 2)
      #expect(
        model.update(try ProfileMenuFrame.decode(menuPayload(["windowNumber": 2, "revision": 2])))
          == 0)
      model.move(-1)
      #expect(model.focused == .delete)
      model.move(1)
      #expect(model.focused == .edit)
      #expect(model.update(try ProfileMenuFrame.decode(menuPayload(["revision": 2]))) == 1)
      model.complete(.select)
      model.complete(nil)
      #expect(log[0] == 1)
      #expect(log[1] == 1)
      #expect(log[2] == 1)
      #expect(model.update(try ProfileMenuFrame.decode(menuPayload(["revision": 3]))) == 2)
    }
  }

  @Test @MainActor func actualPanelSelectionClosureAndKeyboard() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 120, y: 120, width: 850, height: 603),
      styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let point = parent.convertPoint(toScreen: NSPoint(x: 300, y: 400))
    let data = try menuPayload([
      "windowNumber": parent.windowNumber,
      "anchor": ["x": point.x, "y": point.y],
    ])
    let frame = try ProfileMenuFrame.decode(data)
    let rectangle = try #require(ProfileMenuWindow.geometry(frame, parent: parent))
    #expect(rectangle.width == 248)
    #expect(rectangle.height <= 440)
    #expect(rectangle.height <= parent.contentLayoutRect.height * 0.7)
    try withMenuLog { log throws in
      let controller = ProfileMenuWindow(
        frame: frame, parent: parent, callback: menuCallback,
        context: UInt(bitPattern: log))
      controller.show(rectangle)
      #expect(controller.panel.isVisible)
      #expect(controller.panel.parent === parent)
      #expect(controller.panel.contentView != nil)
      let quit = try #require(
        NSEvent.keyEvent(
          with: .keyDown, location: .zero,
          modifierFlags: .command, timestamp: 0, windowNumber: controller.panel.windowNumber,
          context: nil, characters: "q", charactersIgnoringModifiers: "q", isARepeat: false,
          keyCode: 12))
      #expect(!controller.consumeKey(quit))
      #expect(log[0] == 0)
      let down = try #require(
        NSEvent.keyEvent(
          with: .keyDown, location: .zero,
          modifierFlags: [], timestamp: 0, windowNumber: controller.panel.windowNumber,
          context: nil, characters: "", charactersIgnoringModifiers: "", isARepeat: false,
          keyCode: 125))
      #expect(controller.consumeKey(down))
      #expect(controller.model.focused == .edit)
      controller.choose(.edit)
      #expect(!controller.panel.isVisible)
      controller.finish(nil)
      #expect(log[0] == 1)
      #expect(log[2] == 2)
    }
    withMenuLog { log in
      let controller = ProfileMenuWindow(
        frame: frame, parent: parent, callback: menuCallback,
        context: UInt(bitPattern: log))
      controller.show(rectangle)
      NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: parent)
      #expect(log[0] == 1)
      #expect(log[2] == 0)
      controller.finish(nil)
      #expect(log[0] == 1)
    }
  }

  @Test @MainActor func viewportEdgesMatchOriginalOverflowPaddingOnAvailableDisplays() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    #expect(!NSScreen.screens.isEmpty)
    for screen in NSScreen.screens {
      let safe = screen.visibleFrame
      let parent = NSWindow(
        contentRect: NSRect(
          x: safe.minX + 40, y: safe.minY + 40,
          width: min(850, safe.width - 80), height: min(603, safe.height - 100)),
        styleMask: [.titled, .closable], backing: .buffered, defer: false)
      parent.isReleasedWhenClosed = false
      parent.orderFront(nil)
      defer { parent.close() }
      let viewport = parent.convertToScreen(parent.contentLayoutRect)
      for right in [false, true] {
        for bottom in [false, true] {
          let point = NSPoint(
            x: right ? viewport.maxX - 1 : viewport.minX + 1,
            y: bottom ? viewport.minY + 1 : viewport.maxY - 1)
          let frame = try ProfileMenuFrame.decode(
            menuPayload([
              "windowNumber": parent.windowNumber, "anchor": ["x": point.x, "y": point.y],
            ]))
          let rectangle = try #require(ProfileMenuWindow.geometry(frame, parent: parent))
          #expect(viewport.contains(rectangle))
          #expect(safe.contains(rectangle))
          #expect(rectangle.width == 248)
          #expect(rectangle.height == min(397, viewport.height * 0.7))
          if right {
            #expect(abs(viewport.maxX - rectangle.maxX - 10) < 0.01)
          } else {
            #expect(abs(rectangle.minX - point.x) < 0.01)
          }
          if bottom {
            #expect(abs(rectangle.minY - viewport.minY - 10) <= 0.5)
          } else {
            #expect(abs(rectangle.maxY - point.y) < 0.01)
          }
        }
      }
      let titlebar = try ProfileMenuFrame.decode(
        menuPayload([
          "windowNumber": parent.windowNumber,
          "anchor": ["x": viewport.midX, "y": viewport.maxY + 1],
        ]))
      #expect(ProfileMenuWindow.geometry(titlebar, parent: parent) == nil)
    }
  }

  @Test func scrollHintRetainsOriginalTwoPixelThreshold() {
    #expect(ProfileMenuLayout.contentHeight(itemCount: 12) == 397)
    #expect(!ProfileMenuLayout.showsScrollHint(contentHeight: 100, viewportHeight: 100, offset: 0))
    #expect(!ProfileMenuLayout.showsScrollHint(contentHeight: 102, viewportHeight: 100, offset: 0))
    #expect(ProfileMenuLayout.showsScrollHint(contentHeight: 103, viewportHeight: 100, offset: 0))
    #expect(ProfileMenuLayout.showsScrollHint(contentHeight: 397, viewportHeight: 209, offset: 185))
    #expect(
      !ProfileMenuLayout.showsScrollHint(contentHeight: 397, viewportHeight: 209, offset: 186))
  }

  @Test @MainActor func shortViewportIncludesScrollHintInsideMenuHeight() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 220, height: 300),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let viewport = parent.convertToScreen(parent.contentLayoutRect)
    let frame = try ProfileMenuFrame.decode(
      menuPayload([
        "windowNumber": parent.windowNumber,
        "anchor": ["x": viewport.maxX - 1, "y": viewport.minY + 1],
      ]))
    let rectangle = try #require(ProfileMenuWindow.geometry(frame, parent: parent))
    #expect(rectangle.width == 200)
    #expect(rectangle.height == 210)
    #expect(abs(rectangle.minX - viewport.minX - 10) < 0.01)
    #expect(abs(rectangle.minY - viewport.minY - 10) < 0.01)
    try withMenuLog { log throws in
      let controller = ProfileMenuWindow(
        frame: frame, parent: parent, callback: menuCallback, context: UInt(bitPattern: log))
      controller.show(rectangle)
      defer { controller.finish(nil) }
      RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
      let content = try #require(controller.panel.contentView)
      content.layoutSubtreeIfNeeded()
      @MainActor func findScroll(_ view: NSView) -> NSScrollView? {
        if let scroll = view as? NSScrollView { return scroll }
        for child in view.subviews {
          if let scroll = findScroll(child) { return scroll }
        }
        return nil
      }
      let scroll = try #require(findScroll(content))
      let document = try #require(scroll.documentView)
      #expect(controller.panel.frame.height == 210)
      #expect(document.bounds.height > scroll.contentView.bounds.height + 2)
      // 0.5px border on each side plus the actual hint consumes space inside
      // the fixed height. It must not expand beyond 70% of the viewport.
      #expect(scroll.frame.height < controller.panel.frame.height - 15.5)
      #expect(scroll.frame.height > 140)
      #expect(log[0] == 0)
    }
  }

  @Test func appearanceIsRequiredAndClosed() throws {
    #expect(try ProfileMenuFrame.decode(menuPayload()).appearance == .light)
    #expect(try ProfileMenuFrame.decode(menuPayload(["appearance": "dark"])).appearance == .dark)
    for invalid: Any in ["system", "future", "", NSNull(), true] {
      #expect(throws: (any Error).self) {
        try ProfileMenuFrame.decode(menuPayload(["appearance": invalid]))
      }
    }
    var missing = try #require(JSONSerialization.jsonObject(with: menuPayload()) as? [String: Any])
    missing.removeValue(forKey: "appearance")
    #expect(throws: (any Error).self) {
      try ProfileMenuFrame.decode(JSONSerialization.data(withJSONObject: missing))
    }
  }

  @Test @MainActor func panelAppearanceTracksAcceptedPageAppearance() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.appearance = NSAppearance(named: .darkAqua)
    parent.orderFront(nil)
    defer { parent.close() }
    let point = parent.convertPoint(toScreen: NSPoint(x: 300, y: 400))
    @MainActor func frame(_ appearance: String, revision: UInt64) throws -> ProfileMenuFrame {
      try ProfileMenuFrame.decode(
        menuPayload([
          "windowNumber": parent.windowNumber, "anchor": ["x": point.x, "y": point.y],
          "appearance": appearance, "revision": revision,
        ]))
    }
    let initial = try frame("light", revision: 1)
    let rectangle = try #require(ProfileMenuWindow.geometry(initial, parent: parent))
    try withMenuLog { log throws in
      let controller = ProfileMenuWindow(
        frame: initial, parent: parent, callback: menuCallback, context: UInt(bitPattern: log))
      controller.show(rectangle)
      defer { controller.finish(nil) }
      #expect(controller.panel.appearance?.name == .aqua)
      #expect(controller.panel.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .aqua)
      parent.appearance = NSAppearance(named: .aqua)
      #expect(controller.update(try frame("dark", revision: 2)) == 1)
      #expect(controller.panel.appearance?.name == .darkAqua)
      #expect(
        controller.panel.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua)
      #expect(controller.update(try frame("light", revision: 1)) == 0)
      #expect(controller.panel.appearance?.name == .darkAqua)
      #expect(controller.update(try frame("light", revision: 3)) == 1)
      #expect(controller.panel.appearance?.name == .aqua)
      #expect(log[0] == 0)
    }
  }

  @Test @MainActor func realWindowDismissalPathsReleaseOnce() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    for trigger in ["escape", "outside", "deactivate", "parent-close"] {
      let parent = NSWindow(
        contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
        styleMask: [.titled, .closable], backing: .buffered, defer: false)
      parent.isReleasedWhenClosed = false
      parent.orderFront(nil)
      defer { parent.close() }
      let point = parent.convertPoint(toScreen: NSPoint(x: 300, y: 400))
      let frame = try ProfileMenuFrame.decode(
        menuPayload([
          "windowNumber": parent.windowNumber, "anchor": ["x": point.x, "y": point.y],
        ]))
      let rectangle = try #require(ProfileMenuWindow.geometry(frame, parent: parent))
      try withMenuLog { log throws in
        let controller = ProfileMenuWindow(
          frame: frame, parent: parent, callback: menuCallback, context: UInt(bitPattern: log))
        controller.show(rectangle)
        switch trigger {
        case "escape":
          let event = try #require(
            NSEvent.keyEvent(
              with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
              windowNumber: controller.panel.windowNumber, context: nil,
              characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}",
              isARepeat: false, keyCode: 53))
          #expect(controller.consumeKey(event))
        case "outside":
          let event = try #require(
            NSEvent.mouseEvent(
              with: .leftMouseDown, location: NSPoint(x: 20, y: 20), modifierFlags: [],
              timestamp: 0, windowNumber: parent.windowNumber, context: nil,
              eventNumber: 1, clickCount: 1, pressure: 1))
          NSApp.sendEvent(event)
        case "deactivate":
          NotificationCenter.default.post(
            name: NSApplication.didResignActiveNotification, object: NSApp)
        case "parent-close": parent.close()
        default: Issue.record("Unrecognized dismissal fixture")
        }
        #expect(log[0] == 1, "dismissal: \(trigger)")
        #expect(log[2] == 0)
        #expect(!controller.panel.isVisible)
        controller.finish(nil)
        #expect(log[0] == 1)
      }
    }
  }

  @Test @MainActor func abiReplacementAndStaleUpdatesNeverReleaseNewContext() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    let point = parent.convertPoint(toScreen: NSPoint(x: 300, y: 400))
    @MainActor func wire(_ session: UInt64, _ revision: UInt64 = 1) throws -> Data {
      try menuPayload([
        "session": session, "revision": revision, "windowNumber": parent.windowNumber,
        "anchor": ["x": point.x, "y": point.y],
      ])
    }
    try withMenuLog { log throws in
      @MainActor func present(_ session: UInt64) throws -> Int32 {
        try wire(session).withUnsafeBytes {
          profileMenuPresent(
            $0.bindMemory(to: UInt8.self).baseAddress, $0.count,
            menuCallback, UInt(bitPattern: log))
        }
      }
      #expect(try present(10_001) == 1)
      #expect(try present(10_002) == 1)
      #expect(log[0] == 1)
      #expect(log[1] == 10_001)
      #expect(try present(10_001) == 2)
      #expect(log[0] == 1)
      #expect(
        try wire(10_001, 2).withUnsafeBytes {
          profileMenuUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        } == 2)
      #expect(
        try wire(10_002, 2).withUnsafeBytes {
          profileMenuUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        } == 1)
      #expect(
        try wire(10_002, 1).withUnsafeBytes {
          profileMenuUpdate($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        } == 0)
      #expect(profileMenuDismiss(10_001) == 2)
      #expect(profileMenuDismiss(10_002) == 1)
      #expect(profileMenuDismiss(10_002) == 2)
      #expect(log[0] == 2)
      #expect(log[1] == 10_002)
      #expect(log[2] == 0)
    }
  }

  @Test @MainActor func anchorsUseActualViewBoundsAndFlipState() throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let parent = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled], backing: .buffered, defer: false)
    parent.isReleasedWhenClosed = false
    parent.orderFront(nil)
    defer { parent.close() }
    final class FlippedView: NSView { override var isFlipped: Bool { true } }
    for view in [
      NSView(frame: NSRect(x: 20, y: 30, width: 400, height: 300)),
      FlippedView(frame: NSRect(x: 20, y: 30, width: 400, height: 300)),
    ] {
      parent.contentView?.addSubview(view)
      defer { view.removeFromSuperview() }
      let pointer = Unmanaged.passUnretained(view).toOpaque()
      var window: Int64 = -1
      var x = -1.0
      var y = -1.0
      #expect(profileMenuAnchor(pointer, 100, 50, 800, 600, &window, &x, &y) == 1)
      let expected = parent.convertPoint(
        toScreen: view.convert(
          NSPoint(x: 50, y: view.isFlipped ? 25 : 275), to: nil))
      #expect(window == parent.windowNumber)
      #expect(abs(x - expected.x) < 0.001)
      #expect(abs(y - expected.y) < 0.001)
      for arguments in [
        (Double.nan, 50.0, 800.0, 600.0), (100, 50, 0, 600),
        (-1, 50, 800, 600), (801, 50, 800, 600), (100, 601, 800, 600),
      ] {
        x = -1
        #expect(
          profileMenuAnchor(
            pointer, arguments.0, arguments.1, arguments.2, arguments.3,
            &window, &x, &y) == 0)
        #expect(x == -1)
      }
      view.removeFromSuperview()
      #expect(profileMenuAnchor(pointer, 100, 50, 800, 600, &window, &x, &y) == 2)
    }
  }

  @Test func offMainThreadCannotTouchAppKitOrReleaseContext() async {
    let status = await Task.detached { profileMenuDismiss(10_002) }.value
    #expect(status == 3)
  }
}
