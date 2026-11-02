// Opens a profile in the inspector and focuses a section of its editor.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";

export async function openProfileInspector(id, mode, focusKey = null) {
  const profile = await invoke("read_profile_text", { id });
  const inspector = { id, mode, profile, focusKey };
  if (mode === "qrcode") {
    try {
      inspector.svg = await invoke("profile_qrcode_svg", { id });
    } catch (error) {
      inspector.error = errorText(error);
      appendLog("error", "profile", t("Could not render the profile QR code: {error}", { error: inspector.error }));
    }
  }
  state.profileInspector = inspector;
}

export function focusProfileEditorSection(key) {
  if (!key) return;
  const editor = document.querySelector("[data-profile-editor]");
  if (!(editor instanceof HTMLTextAreaElement)) return;
  const body = editor.value;
  const match = body.match(new RegExp(`"${key}"\\s*:`, "m"));
  if (!match || match.index == null) return;
  const start = match.index;
  editor.focus();
  editor.setSelectionRange(start, start + match[0].length);
  const before = body.slice(0, start);
  const line = before.split("\n").length - 1;
  const lineHeight = Number.parseFloat(getComputedStyle(editor).lineHeight) || 18;
  editor.scrollTop = Math.max(0, line * lineHeight - 40);
}
