#ifndef CFM_WINDOW_GLASS_H
#define CFM_WINDOW_GLASS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Main-thread-only ABI of the glass behind the page of one decorated host
 * window: the window's own glass slab, inserted below its WKWebView, and the
 * frosted panels, cards and the navigation pill the page lays out. The
 * backdrop draws no text and takes no input; the page stays in charge.
 *
 * A frame is borrowed UTF-8 JSON of at most 16384 bytes:
 * {version,session,sequence,acknowledgedSubmission,windowNumber,appearance,
 * viewport:{width,height},panels:[{id,kind,x,y,width,height,radius}]}.
 * Every field is required and unknown fields are rejected.
 *   version                 1.
 *   session                 A positive 64-bit integer. Each present must
 *                           exceed every session presented before it.
 *   sequence                1 through 9007199254740991. Each update must
 *                           exceed the sequence of the frame it replaces.
 *   acknowledgedSubmission  Always 0: the backdrop emits no submission.
 *   windowNumber            The visible host window, greater than 0. An
 *                           update cannot change it.
 *   appearance              "light" or "dark".
 *   viewport                The page's innerWidth/innerHeight in CSS pixels,
 *                           both greater than 0. A frame whose viewport no
 *                           longer matches the view is stale (2); the page
 *                           measures again after a resize.
 *   panels                  At most 32, with unique ids matching
 *                           ^[a-z][a-z0-9-]{0,31}$. kind is "panel", "card",
 *                           "pill" or "strip"; x, y, width and height are the
 *                           DOM rectangle in CSS pixels (sizes not negative),
 *                           radius the corner radius, 0 through 64. A pill is
 *                           always a capsule.
 *
 * The event callback is required but never called. The closed callback runs
 * exactly once for an accepted present: after dismiss, when a later present
 * replaces the backdrop, or when the host window closes.
 *
 * cfm_window_glass_present_v1 returns
 *   0  rejected: a null argument, a count outside 1 through 16384, an invalid
 *      frame, a window that is absent, hidden or has no WKWebView, or a
 *      viewport that does not match it. Nothing is retained.
 *   1  accepted: the callbacks and context are retained until exactly one
 *      closed callback. A backdrop that was showing is closed first, through
 *      its own closed callback.
 *   2  stale: session does not exceed the newest presented session.
 *   3  called off the main thread.
 *
 * cfm_window_glass_update_v1 returns 0 (invalid frame, or a frame of the
 * showing session that does not advance sequence or changes windowNumber),
 * 1 (accepted), 2 (no backdrop is showing, another session, or a viewport
 * that no longer matches the view; the showing frame stays) or 3.
 *
 * cfm_window_glass_dismiss_v1 returns 1 (dismissed; the closed callback ran
 * before it returned), 2 (no backdrop of that session is showing) or 3.
 */
typedef int32_t (*CFMWindowGlassEvent)(uintptr_t context, uint64_t session,
                                      const uint8_t *bytes, intptr_t count);
typedef void (*CFMWindowGlassClosed)(uintptr_t context, uint64_t session);

int32_t cfm_window_glass_present_v1(const uint8_t *bytes, intptr_t count,
                                    CFMWindowGlassEvent event_callback,
                                    CFMWindowGlassClosed closed_callback, uintptr_t context);
int32_t cfm_window_glass_update_v1(const uint8_t *bytes, intptr_t count);
int32_t cfm_window_glass_dismiss_v1(uint64_t session);

#ifdef __cplusplus
}
#endif

#endif
