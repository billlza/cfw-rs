#ifndef CFW_NATIVE_BRIDGE_H
#define CFW_NATIVE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CFW_NATIVE_BRIDGE_ABI_VERSION 1
#define CFW_NATIVE_BRIDGE_MAX_REQUEST_BYTES (1024u * 1024u)
#define CFW_NATIVE_BRIDGE_MAX_RESPONSE_BYTES (1024u * 1024u)
#define CFW_NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS 30000u
#define CFW_NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS 20000u
#define CFW_NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS 55000u

typedef void (*cfw_native_bridge_completion_v1)(
    void *context,
    const uint8_t *response_bytes,
    intptr_t response_length);

/// Schedules one versioned native request. The request bytes are copied before
/// this function returns. A return value of zero transfers callback-context
/// ownership to the caller-defined completion, which is invoked exactly once;
/// a nonzero return value means no callback will occur.
int32_t cfw_native_bridge_execute_v1(
    const uint8_t *request_bytes,
    intptr_t request_length,
    cfw_native_bridge_completion_v1 completion,
    void *completion_context);

/// Cancels only the accepted request whose canonical lowercase UUID is supplied.
/// The request identifier is copied before this function returns. Zero means the
/// exact live request was found and cancellation was delivered. A nonzero value
/// means no request was cancelled. An accepted execute still owns its completion
/// context until its exactly-once terminal callback, including after cancellation.
int32_t cfw_native_bridge_cancel_v1(
    const uint8_t *request_id_bytes,
    intptr_t request_id_length);

#ifdef __cplusplus
}
#endif

#endif
