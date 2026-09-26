import AppKit
import Testing
import WebKit

@testable import CFMNativeDashboard

@MainActor private final class GeometryPageLoader: NSObject, WKNavigationDelegate {
  var completion: CheckedContinuation<Void, any Error>?
  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    completion?.resume()
    completion = nil
  }
  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: any Error)
  {
    completion?.resume(throwing: error)
    completion = nil
  }
  func webView(
    _ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
    withError error: any Error
  ) {
    self.webView(webView, didFail: navigation, withError: error)
  }
}

@Suite(.serialized) struct WebContentGeometryTests {
  @Test(.timeLimit(.minutes(1))) @MainActor
  func fullSizeWebContentExcludesTitlebarAndKeepsDOMAnchorAlignment() async throws {
    NSApplication.shared.setActivationPolicy(.prohibited)
    let window = NSWindow(
      contentRect: NSRect(x: 100, y: 100, width: 850, height: 603),
      styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    defer { window.close() }
    let content = try #require(window.contentView)
    let webview = WKWebView(frame: content.bounds)
    content.addSubview(webview)
    window.orderFront(nil)
    content.layoutSubtreeIfNeeded()
    let loader = GeometryPageLoader()
    webview.navigationDelegate = loader
    defer { withExtendedLifetime(loader) {} }
    try await withCheckedThrowingContinuation { continuation in
      loader.completion = continuation
      webview.loadHTMLString(
        "<!doctype html><meta name='viewport' content='width=device-width,initial-scale=1'><p>TEST DATA ONLY</p>",
        baseURL: nil)
    }
    try #require(webview.safeAreaInsets.top > 0)
    for zoom in [1.0, 2.0] {
      webview.pageZoom = zoom
      let dimensions = try #require(
        try await webview.evaluateJavaScript("[innerWidth, innerHeight]") as? [Double])
      try #require(dimensions.count == 2)
      print(
        "fullsize bounds=\(webview.bounds) safe=\(webview.safeAreaRect) DOM=\(dimensions) zoom=\(zoom)"
      )
      let geometry = try #require(
        WebContentGeometry(
          webview: webview, width: dimensions[0], height: dimensions[1]))
      #expect(abs(dimensions[1] * zoom - webview.safeAreaRect.height) <= zoom)
      #expect(dimensions[1] * zoom < webview.bounds.height)
      let topLeft = geometry.rectangle(x: 0, y: 0, width: 0, height: 0).origin
      let topLeftInWindow = webview.convert(topLeft, to: nil)
      #expect(abs(topLeftInWindow.y - window.contentLayoutRect.maxY) < 0.001)
      // Both the menu and switches must use the same content origin and zoom.
      var number: Int64 = -1
      var x = -1.0
      var y = -1.0
      let pointer = Unmanaged.passUnretained(webview).toOpaque()
      try #require(
        profileMenuAnchor(
          pointer, 100, 50, dimensions[0], dimensions[1], &number, &x, &y) == 1)
      let expected = window.convertPoint(
        toScreen: webview.convert(
          geometry.rectangle(x: 100, y: 50, width: 0, height: 0).origin, to: nil))
      #expect(number == window.windowNumber)
      #expect(abs(x - expected.x) < 0.001 && abs(y - expected.y) < 0.001)
      // Passing full WK bounds as the DOM viewport is the old real-host defect.
      #expect(
        WebContentGeometry(
          webview: webview, width: webview.bounds.width / zoom,
          height: webview.bounds.height / zoom) == nil)
      x = -1
      #expect(
        profileMenuAnchor(
          pointer, 100, 50, dimensions[0], dimensions[1] + 10, &number, &x, &y) == 2)
      #expect(x == -1)
    }
  }
}
