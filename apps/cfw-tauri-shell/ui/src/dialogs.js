import { button, node } from "./dom.js";

export function confirmAction(title, message, confirmLabel = "Continue") {
  return new Promise((resolve) => {
    const dialog = node("dialog", { className: "native-dialog" });
    const finish = (result) => {
      dialog.close();
      dialog.remove();
      resolve(result);
    };
    const cancel = button("Cancel", "dialog-cancel", { className: "button ghost" });
    const confirm = button(confirmLabel, "dialog-confirm", { className: "button danger" });
    cancel.addEventListener("click", () => finish(false), { once: true });
    confirm.addEventListener("click", () => finish(true), { once: true });
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish(false);
    }, { once: true });
    dialog.append(node("section", { className: "dialog-content" }, [
      node("h3", { text: title }),
      node("p", { className: "muted", text: message }),
      node("div", { className: "toolbar-actions" }, [cancel, confirm]),
    ]));
    document.body.append(dialog);
    dialog.showModal();
  });
}
