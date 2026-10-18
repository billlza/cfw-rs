#ifndef CFM_PROFILE_MENU_H
#define CFM_PROFILE_MENU_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Only the main thread may call these functions. Bytes are borrowed only for
 * the synchronous call, UTF-8 JSON version 1, at most 16384 bytes. Status:
 * 0 invalid/rejected; 1 accepted; 2 hidden/stale session; 3 wrong thread.
 *
 * A successful present retains the opaque context until exactly one callback.
 * A rejected present never retains it or calls back. The callback runs on the
 * main thread after dismissal. Context ownership returns to the caller there.
 * Sessions must be nonzero and monotonically increase for each present; update
 * requires the same session/window and a strictly increasing revision.
 * Every frame requires appearance: "light" or "dark", matching the effective
 * page theme; present and accepted updates explicitly apply it to the panel.
 * Missing, unknown, or automatic/system appearance values are rejected.
 * Anchor is in Cocoa screen coordinates within the decorated host's content
 * viewport. Menu positioning preserves the page's 10px right/bottom overflow
 * padding and stays within both that content viewport and the visible screen.
 *
 * Action 0 cancels; actions 1..12 retain the existing profile menu order:
 * select, edit, edit-external, update, reveal, outbounds, route, copy, qrcode,
 * credentials, settings, delete. A disabled item cannot emit its action.
 * The UI emits intent only; the Rust host revalidates business authorization.
 */
typedef void (*CFMProfileMenuCallback)(uintptr_t context, uint64_t session, uint32_t action);
int32_t cfm_profile_menu_present_v1(const uint8_t *bytes, intptr_t count,
                                  CFMProfileMenuCallback callback, uintptr_t context);
int32_t cfm_profile_menu_update_v1(const uint8_t *bytes, intptr_t count);
int32_t cfm_profile_menu_dismiss_v1(uint64_t session);

/* Resolve only the visible parent window of the borrowed live WKWebView.
 * This does not validate or synthesize a DOM anchor. No output on failure.
 * 0 invalid input/type; 1 accepted; 2 detached/hidden parent; 3 wrong thread.
 */
int32_t cfm_webview_window_number_v1(void *borrowed_ns_view, int64_t *window_number);

/* borrowed_ns_view must be the live WKWebView/NSView supplied by Tauri's
 * PlatformWebview.inner() in with_webview on the main thread. CSS viewport
 * coordinates use the view's content safe area, page zoom and flip state.
 * No output on failure. Status 2 means a hidden parent or stale viewport.
 */
int32_t cfm_profile_menu_anchor_v1(void *borrowed_ns_view, double client_x, double client_y,
                                 double viewport_width, double viewport_height,
                                 int64_t *window_number, double *screen_x, double *screen_y);

#ifdef __cplusplus
}
#endif
#endif
