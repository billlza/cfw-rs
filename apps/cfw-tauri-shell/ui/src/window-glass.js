/// The glass behind the page. The page measures the regions it lays out (the
/// sidebar, its cards, the active navigation item, the workspace and the
/// status row) and the host draws glass under them. While the host shows that
/// glass the page drops its own opaque backgrounds; whenever it does not, the
/// page looks as it did without native glass, so a transparent window never
/// shows an unreadable page.

const MAXIMUM_PANELS = 32;
const MAXIMUM_RADIUS = 64;
export const GLASS_CLASS = "native-window-glass";

/// The regions, in page order. A region that is not in the document is not
/// measured; one with no size is sent with zero size, so the host still owns
/// its identity.
export const GLASS_REGIONS = Object.freeze([
  { id: "status-row", selector: ".status-bar", kind: "strip", radius: 0 },
  { id: "sidebar", selector: ".sidebar", kind: "panel", radius: 22 },
  { id: "traffic", selector: ".traffic-pane", kind: "card", radius: 16 },
  { id: "nav-active", selector: ".nav-item.active", kind: "pill", radius: 0 },
  { id: "runtime", selector: ".runtime-pane", kind: "card", radius: 16 },
  { id: "sidebar-meta", selector: ".sidebar-meta", kind: "card", radius: 16 },
  { id: "workspace", selector: ".workspace", kind: "panel", radius: 22 },
]);

function finite(value) {
  return Number.isFinite(value);
}

/// The frame of the current layout, or null when nothing measurable is on
/// the page or the viewport has no size.
export function measureGlassFrame(doc, win, appearance) {
  const width = win.innerWidth;
  const height = win.innerHeight;
  if (!finite(width) || !finite(height) || width <= 0 || height <= 0) return null;
  const panels = [];
  for (const region of GLASS_REGIONS) {
    const element = doc.querySelector(region.selector);
    if (!element) continue;
    const rect = element.getBoundingClientRect();
    const x = rect.left, y = rect.top, w = Math.max(0, rect.width), h = Math.max(0, rect.height);
    if (![x, y, w, h].every(finite)) return null;
    panels.push({ id: region.id, kind: region.kind, x, y, width: w, height: h, radius: Math.min(region.radius, MAXIMUM_RADIUS) });
  }
  if (panels.length === 0 || panels.length > MAXIMUM_PANELS) return null;
  return { appearance, viewport: { width, height }, panels };
}

function sameFrame(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/// Owns one native glass session per page load.
///
/// `refresh()` is cheap to call after every render: it measures, and only a
/// changed frame reaches the host. A refusal or a closed session removes the
/// page's glass class, so the page paints its own backgrounds again.
export function createWindowGlass({ invoke, makeChannel, enabled, doc, win, randomUUID, onError }) {
  let session = null;
  let busy = false;
  let queued = false;

  function appearance() {
    return doc.documentElement.dataset.theme === "dark" ? "dark" : "light";
  }

  function setGlass(active) {
    doc.documentElement.classList.toggle(GLASS_CLASS, active);
  }

  function end(requestId) {
    if (session?.requestId !== requestId) return;
    session = null;
    setGlass(false);
  }

  async function present(frame) {
    const requestId = randomUUID();
    const next = { requestId, sequence: 1, acknowledgedSubmission: 0, ...frame };
    const completion = makeChannel((event) => {
      if (event?.kind === "closed" && event.requestId === requestId) end(requestId);
    });
    session = { requestId, sequence: 1, frame };
    try {
      await invoke("present_native_window_glass", { request: next, completion });
    } catch (error) {
      end(requestId);
      onError(error);
      return;
    }
    // A closed event may have ended the session while the host answered.
    if (session?.requestId === requestId) setGlass(true);
  }

  async function update(frame) {
    const current = session;
    const sequence = current.sequence + 1;
    const next = { requestId: current.requestId, sequence, acknowledgedSubmission: 0, ...frame };
    current.sequence = sequence;
    current.frame = frame;
    let accepted;
    try {
      accepted = await invoke("update_native_window_glass", { request: next });
    } catch (error) {
      end(current.requestId);
      onError(error);
      return;
    }
    // The host answers false for a frame whose viewport it no longer has:
    // a resize is in flight and the next render measures again.
    if (accepted !== true && accepted !== false) {
      end(current.requestId);
      onError(new Error("Native window glass returned an invalid result"));
    }
  }

  async function run() {
    if (busy) {
      queued = true;
      return;
    }
    busy = true;
    try {
      do {
        queued = false;
        if (!enabled()) {
          if (session) await stop();
        } else {
          const frame = measureGlassFrame(doc, win, appearance());
          if (!frame) {
            if (session) await stop();
          } else if (!session) {
            await present(frame);
          } else if (!sameFrame(frame, session.frame)) {
            await update(frame);
          }
        }
      } while (queued);
    } finally {
      busy = false;
    }
  }

  async function stop() {
    const current = session;
    if (!current) return;
    session = null;
    setGlass(false);
    try {
      await invoke("dismiss_native_window_glass", { requestId: current.requestId });
    } catch (error) {
      onError(error);
    }
  }

  return {
    refresh: () => run(),
    stop,
    active: () => session !== null,
  };
}
