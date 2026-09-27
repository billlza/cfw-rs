import AppKit
import WebKit

/// DOM coordinates start in the WK content viewport, below any titlebar safe
/// area. Wry's full-size WKWebView may include that titlebar in its bounds.
@MainActor
struct WebContentGeometry {
  let viewport: NSRect
  let scale: CGFloat
  let flipped: Bool

  init?(webview: WKWebView, width: Double, height: Double) {
    let viewport = webview.safeAreaRect
    let scale = webview.pageZoom
    guard
      [viewport.minX, viewport.minY, viewport.width, viewport.height, scale]
        .allSatisfy(\.isFinite), viewport.width > 0, viewport.height > 0, scale > 0,
      width.isFinite, height.isFinite, width > 0, height > 0,
      // innerWidth/innerHeight round to integer CSS pixels. Do not stretch a
      // stale DOM frame to fit a resized native view.
      abs(width - viewport.width / scale) < 1,
      abs(height - viewport.height / scale) < 1
    else { return nil }
    self.viewport = viewport
    self.scale = scale
    flipped = webview.isFlipped
  }

  func rectangle(x: Double, y: Double, width: Double, height: Double) -> NSRect {
    let nativeHeight = height * scale
    return NSRect(
      x: viewport.minX + x * scale,
      y: flipped ? viewport.minY + y * scale : viewport.maxY - y * scale - nativeHeight,
      width: width * scale, height: nativeHeight)
  }
}
