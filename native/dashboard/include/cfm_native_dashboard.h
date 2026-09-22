#ifndef CFM_NATIVE_DASHBOARD_H
#define CFM_NATIVE_DASHBOARD_H
#include <stddef.h>
#include <stdint.h>

// Main-thread presentation and intent ABI. Rust owns networking and credentials.
// JSON buffer is borrowed for the call only, with 1..32768 bytes.
// Results: 0 rejected, 1 accepted, 2 hidden/superseded, 3 wrong thread.
// On accepted present, Swift retains callback/context until close/replacement
// and calls it exactly once. Rejected present retains neither. context is an
// opaque nonzero word; Swift never dereferences it.
typedef int32_t (*cfm_dashboard_control_v2)(uintptr_t context, uint64_t session, uint64_t revision, uint64_t request, uint32_t control, uint8_t enabled);
// Controls: 1 core, 2 System Proxy, 3 TUN. Command return: 1 queued, 4 busy, 2 closed, 0 rejected.
// Same-value enables require a Rust-admitted retry; active modes are not restarted.
// Accepted work retains its Rust owner even if the window closes. Its matching
// completion is observable while the session remains open, and failures are logged.
typedef void (*cfm_dashboard_closed_v2)(uintptr_t context);
int32_t cfm_dashboard_present_v2(const uint8_t *, size_t, cfm_dashboard_closed_v2, cfm_dashboard_control_v2, uintptr_t);
int32_t cfm_dashboard_publish_v2(const uint8_t *, size_t);
int32_t cfm_dashboard_invalidate_v2(uint64_t session);
int32_t cfm_dashboard_close_v2(uint64_t session);
// Programmatic UI intent; exactly the same validation as a SwiftUI control.
int32_t cfm_dashboard_request_v2(uint64_t session, uint32_t control, uint8_t enabled);
#endif
