//! One press of the global shortcut the installed GUI registered, sent as
//! real keyboard input on the input desktop the GUI runs on. Windows takes a
//! registered hot key out of its input stream, so no window of the product is
//! addressed and none needs the focus.
use super::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, SendInput, VK_CONTROL, VK_F9,
    VK_MENU, VK_SHIFT,
};

/// The shortcut the automation session enters in Settings.
const SHORTCUT: &str = "Control+Alt+Shift+F9";
/// Its keys in the order they go down. They come up in the reverse order.
const KEYS: [u16; 4] = [VK_CONTROL, VK_MENU, VK_SHIFT, VK_F9];

fn key(virtual_key: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: virtual_key,
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

pub(super) fn probe(operation: &str) -> Result<()> {
    if !["shortcut-stop", "shortcut-start", "shortcut-removed"].contains(&operation) {
        return Err("unknown GUI shortcut probe".into());
    }
    let (source, receipts) = validation_context()?;
    let observed = network::ObservedGui::open(&source, &receipts)?;
    // Keyboard input reaches the input desktop only. The GUI was started on
    // the interactive station's Default desktop; require the same one here.
    let mut desktop = input_desktop::InputDesktop::open()?;
    // One call inserts the whole press, so no other input comes between its
    // keys and no key stays down if this process ends early.
    let events: Vec<INPUT> = KEYS
        .iter()
        .map(|virtual_key| key(*virtual_key, 0))
        .chain(
            KEYS.iter()
                .rev()
                .map(|virtual_key| key(*virtual_key, KEYEVENTF_KEYUP)),
        )
        .collect();
    let accepted = unsafe {
        SendInput(
            events.len() as u32,
            events.as_ptr(),
            size_of::<INPUT>() as i32,
        )
    };
    if accepted as usize != events.len() {
        return Err(format!(
            "{}; Windows accepted {accepted} of {} keyboard events",
            error("send the shortcut's keys"),
            events.len()
        ));
    }
    observed.recheck("shortcut probe GUI image changed during the key press")?;
    let desktop_observation = desktop.observation();
    desktop.close()?;
    write(
        &receipts,
        &format!("{operation}-probe.json"),
        &serde_json::json!({
            "document": "cfw-installed-gui-shortcut-probe-v1", "source": source,
            "operation": operation,
            "gui_process_id": observed.pid,
            "gui_process_creation_time": observed.process.identity().process_creation_time(),
            "gui_same_user_session": true, "shortcut": SHORTCUT,
            "keyboard_events_sent": events.len(), "keyboard_events_accepted": accepted,
            "desktop_observation": desktop_observation,
            "product_addressed": false, "release_accepted": false
        }),
    )
}
