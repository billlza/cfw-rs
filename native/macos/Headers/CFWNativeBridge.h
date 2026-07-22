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

#ifdef __cplusplus
}
#endif

#endif
