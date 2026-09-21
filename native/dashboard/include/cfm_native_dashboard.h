#ifndef CFM_NATIVE_DASHBOARD_H
#define CFM_NATIVE_DASHBOARD_H
#include <stddef.h>
#include <stdint.h>

// Main-thread, in-process presentation ABI. No networking or credentials.
// JSON buffer is borrowed for the call only, with 1..32768 bytes.
// Results: 0 rejected, 1 accepted, 2 hidden/superseded, 3 wrong thread.
// On accepted present, Swift retains callback/context until close/replacement
// and calls it exactly once. Rejected present retains neither. context is an
// opaque nonzero word; Swift never dereferences it.
typedef void (*cfm_dashboard_closed_v1)(uintptr_t context);
int32_t cfm_dashboard_present_v1(const uint8_t *, size_t, cfm_dashboard_closed_v1, uintptr_t);
int32_t cfm_dashboard_publish_v1(const uint8_t *, size_t);
int32_t cfm_dashboard_invalidate_v1(uint64_t session);
int32_t cfm_dashboard_close_v1(uint64_t session);
#endif
