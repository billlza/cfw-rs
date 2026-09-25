#ifndef CFM_GENERAL_SWITCHES_H
#define CFM_GENERAL_SWITCHES_H
#include <stddef.h>
#include <stdint.h>
// Main thread only. View and JSON are borrowed for the synchronous call.
// First accepted sync owns context until exactly one closed callback. Updates
// pass null callbacks and zero context; rejected first sync owns nothing.
// Results: 0 invalid, 1 accepted, 2 stale/unavailable, 3 wrong thread.
typedef int32_t (*CFMGeneralSwitchInput)(uintptr_t, uint64_t session,
    uint64_t sequence, uint64_t submission, uint32_t key, uint32_t kind, uint8_t value);
typedef void (*CFMGeneralSwitchClosed)(uintptr_t);
// kind: 1 toggle (monotonic submission), 2 forward Tab, 3 reverse Tab, 4 focused.
// kind 5 requests fresh DOM geometry after native invalidation; key is zero.
// Non-toggle submission/value are zero. The callback performs presentation
// delivery only; the renderer and Rust business use cases revalidate effects.
int32_t cfm_general_switches_sync_v1(void *, const uint8_t *, size_t,
    CFMGeneralSwitchInput, CFMGeneralSwitchClosed, uintptr_t);
int32_t cfm_general_switches_focus_v1(uint64_t session, uint64_t sequence, uint32_t key);
int32_t cfm_general_switches_dismiss_v1(uint64_t session);
#endif
