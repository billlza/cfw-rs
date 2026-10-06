#ifndef CFM_PROMPT_DIALOG_H
#define CFM_PROMPT_DIALOG_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Main-thread-only ABI of one centered panel that presents a confirmation or
 * a notice and reports which button was chosen. A frame is data, so one family
 * serves every such dialog. The panel presents and reports only; the host
 * decides every effect.
 *
 * A frame is borrowed UTF-8 JSON of at most 16384 bytes:
 * {version,session,sequence,acknowledgedSubmission,windowNumber,locale,
 * appearance,title,message,buttons:[{id,title,role}],transportFailure}.
 * Every field is required and unknown fields are rejected.
 *   version                 1.
 *   session                 A positive 64-bit integer. Each present must
 *                           exceed every session presented before it.
 *   sequence                1 through 9007199254740991. Each update must
 *                           exceed the sequence of the frame it replaces.
 *   acknowledgedSubmission  0 through 9007199254740991.
 *   windowNumber            The visible parent window, greater than 0. An
 *                           update cannot change it.
 *   locale                  "en", "zh-Hans", "zh-Hant" or "ja".
 *   appearance              "light" or "dark".
 *   title, button title     Non-blank, which is not empty and not only
 *                           whitespace or newlines; at most 160 Unicode scalar
 *                           values.
 *   message                 At most 4096 Unicode scalar values. It may be
 *                           empty. Its newlines are shown as line breaks.
 *   transportFailure        Non-blank; at most 1024 Unicode scalar values. It
 *                           is shown when an activation is not delivered.
 *   buttons                 One to three, shown in frame order, with unique
 *                           ids matching ^[a-z][a-z0-9-]{0,31}$. role is
 *                           "cancel", "default" or "destructive". Exactly one
 *                           button is "cancel" and it is first.
 *
 * A non-cancel button emits {action:"activate",submissionId,buttonId} with
 * synchronously borrowed bytes. submissionId increases from 1 through
 * 9007199254740991 per session. The event callback returns 1 to accept and
 * any other value to reject; it never takes ownership. A rejected callback
 * consumes its ID and shows transportFailure.
 * An accepted activation is pending until a frame whose acknowledgedSubmission
 * equals its ID. While it is pending the non-cancel buttons are disabled; an
 * older acknowledgement or a theme update never releases a newer pending
 * activation. Present requires acknowledgedSubmission 0. An update can neither
 * decrease it nor acknowledge an ID the panel has not emitted.
 *
 * The cancel button, Escape and closing the panel stay available while an
 * activation is pending. They close the panel and never emit an activation.
 * Closing, by the user or the host, never cancels an operation the host has
 * admitted. No button answers Return.
 *
 * cfm_prompt_dialog_present_v1 returns
 *   0  rejected: a null argument, a count outside 1 through 16384, an invalid
 *      frame, a non-zero acknowledgedSubmission, or a parent window that is
 *      absent, hidden or too small to hold the panel. Nothing is retained.
 *   1  accepted: the callbacks and context are retained until exactly one
 *      closed callback, which may arrive before present returns. A prompt
 *      that was showing is closed first, through its own closed callback.
 *   2  stale: session does not exceed the newest presented session. Nothing
 *      is retained.
 *   3  called off the main thread. Nothing is retained.
 * A present that does not return 1 neither retains nor returns context.
 *
 * cfm_prompt_dialog_update_v1 returns
 *   0  rejected: null bytes, a count outside 1 through 16384, an invalid
 *      frame, or a frame of the showing session that does not advance
 *      sequence, changes windowNumber or carries an inadmissible
 *      acknowledgedSubmission. The showing frame stays.
 *   1  accepted.
 *   2  no prompt is showing, or the frame belongs to another session.
 *   3  called off the main thread.
 *
 * cfm_prompt_dialog_dismiss_v1 is unconditional, for a completed action, a
 * reload or shutdown. It returns
 *   1  dismissed: the closed callback ran before dismiss returned.
 *   2  no prompt of that session is showing.
 *   3  called off the main thread.
 */
typedef int32_t (*CFMPromptDialogEvent)(uintptr_t context, uint64_t session,
                                      const uint8_t *bytes, intptr_t count);
typedef void (*CFMPromptDialogClosed)(uintptr_t context, uint64_t session);
int32_t cfm_prompt_dialog_present_v1(const uint8_t *bytes, intptr_t count,
                                   CFMPromptDialogEvent event_callback,
                                   CFMPromptDialogClosed closed_callback, uintptr_t context);
int32_t cfm_prompt_dialog_update_v1(const uint8_t *bytes, intptr_t count);
int32_t cfm_prompt_dialog_dismiss_v1(uint64_t session);
#ifdef __cplusplus
}
#endif
#endif
