#ifndef CFM_RUNTIME_SETTINGS_H
#define CFM_RUNTIME_SETTINGS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Main-thread-only ABI. Borrowed UTF-8 JSON bytes, version 1, maximum 16384
 * bytes. Status: 0 invalid/rejected, 1 accepted, 2 absent/stale session,
 * 3 wrong thread. Sessions increase per present; sequences increase per update.
 *
 * The draft is initialized once and survives frame updates, errors, hiding,
 * deactivation and minimization. Updates refresh labels/theme/saving/error.
 * Submit emits {action:"submit",submissionId,draft:{...}} with synchronously
 * borrowed bytes. IDs increase from 1 through 9007199254740991 per session;
 * a rejected callback consumes its ID. event callback returns 1 to accept,
 * 0 to reject; it never takes ownership.
 * Every frame requires acknowledgedSubmission. Present requires 0; updates
 * cannot decrease it or acknowledge an ID the native model has not emitted.
 * A pending submission is released only by its own acknowledgedSubmission
 * and a saving=true or non-null-error frame. Older acknowledgement/theme/
 * error updates never release a newer pending request. The same acknowledged
 * ID may advance from saving to failed in a later-sequence frame.
 *
 * Successful present retains callback/context until exactly one closed
 * callback. Cancel/Escape are disabled while pending/saving. Host dismiss is
 * unconditional, for successful save/reload/shutdown; it never cancels a host
 * operation. Rejected present neither retains nor returns context.
 *
 * labels.inputTooLong requires {label} and {maximum} placeholders. Text bounds:
 * port/mtu/lanPort 32, lanAddress 255, lanSources 8192 Unicode scalar values. Input resource
 * limits do not replace the host's existing preferences validation.
 */
typedef int32_t (*CFMRuntimeSettingsEvent)(uintptr_t context, uint64_t session,
                                        const uint8_t *bytes, intptr_t count);
typedef void (*CFMRuntimeSettingsClosed)(uintptr_t context, uint64_t session);
int32_t cfm_runtime_settings_present_v1(const uint8_t *bytes, intptr_t count,
                                      CFMRuntimeSettingsEvent event_callback,
                                      CFMRuntimeSettingsClosed closed_callback, uintptr_t context);
int32_t cfm_runtime_settings_update_v1(const uint8_t *bytes, intptr_t count);
int32_t cfm_runtime_settings_dismiss_v1(uint64_t session);
#ifdef __cplusplus
}
#endif
#endif
