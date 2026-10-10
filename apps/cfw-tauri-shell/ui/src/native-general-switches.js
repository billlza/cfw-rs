// Presentation only. These keys retain General's existing applyToggle use cases.
export const GENERAL_SWITCH_KEYS = Object.freeze(["allowLan", "ipv6DNS", "tunMode", "mixin", "systemProxy", "startAtLogin"]);

export function resolvedGeneralAppearance(value) {
  // Boot loads the user's appearance asynchronously. Preserve the existing DOM
  // until that authoritative setting arrives, rather than inventing a theme.
  if (value === undefined) return null;
  if (value === "light" || value === "dark") return value;
  throw new Error("General native controls require a resolved page appearance");
}

export function createGeneralSwitchTransport({ invoke, makeChannel, onToggle, onTraverse, onFocus, onLayout, onReady, onError }) {
  const requestId = crypto.randomUUID();
  let sequence = 0, acknowledgedSubmission = 0, submitted = 0, acceptedSequence = 0;
  let resizeProjection = null, resizeRetries = 0;
  let latest = null, projection = null, stopped = false, started = false, currentLayout = false, presented = false;
  let tail = Promise.resolve();
  const enqueue = (operation) => {
    const result = tail.then(operation);
    // Cleanup remains runnable, but each failed operation is reported by its caller.
    tail = result.then(() => undefined, () => undefined);
    return result;
  };
  function fail(error) {
    if (stopped) return;
    stopped = true;
    onError(error);
    void enqueue(async () => {
      if (started) await invoke("dismiss_native_general_switches", { requestId });
    }).catch(onError);
  }
  const receive = (event) => {
    if (stopped) return;
    if (event?.requestId !== requestId) { fail(new Error("Native switches returned an invalid identity")); return; }
    if (event.kind === "closed" && Object.keys(event).sort().join(",") === "kind,requestId") {
      fail(new Error("Native switches closed before their presentation ended")); return;
    }
    if (Object.keys(event).sort().join(",") !== "action,key,kind,requestId,sequence,submission,value"
      || event.kind !== "input" || !Number.isSafeInteger(event.sequence) || event.sequence < 1
      || !Number.isSafeInteger(event.submission) || event.submission < 0
      || !Number.isInteger(event.key) || event.key < (event.action === 5 ? 0 : 1) || event.key > (event.action === 5 ? 0 : 6)
      || ![1, 2, 3, 4, 5].includes(event.action) || typeof event.value !== "boolean"
      || event.action !== 1 && (event.submission !== 0 || event.value)) {
      fail(new Error("Native switches returned an invalid event")); return;
    }
    if (event.action === 5) { onLayout(); return; }
    const item = latest?.items.find((value) => value.key === event.key);
    const current = currentLayout && event.sequence === sequence && item?.enabled;
    if (event.action === 1) {
      if (event.submission !== submitted + 1 || submitted !== acknowledgedSubmission) {
        fail(new Error("Native switches returned a duplicate or unacknowledged submission")); return;
      }
      submitted = event.submission;
      // A page/layout update can supersede an already delivered native click.
      // Acknowledge its presentation debt, but never run the stale business action.
      Promise.resolve().then(() => current && item.checked !== event.value
        ? onToggle(GENERAL_SWITCH_KEYS[event.key - 1], event.value) : undefined)
        .catch(onError).finally(() => {
          acknowledgedSubmission = event.submission;
          if (!stopped && latest) sync(latest, true);
        });
    } else if (current) {
      if (event.action === 4) onFocus(event.key);
      else onTraverse(event.key, event.action === 2 ? 1 : -1);
    }
  };
  function sync(frame, force = false) {
    if (stopped) return;
    const next = JSON.stringify(frame);
    latest = frame;
    currentLayout = true;
    if (!force && projection === next) {
      if (acceptedSequence === sequence) onReady(frame);
      return;
    }
    projection = next;
    const viewport = JSON.stringify(frame.viewport);
    if (viewport !== resizeProjection) { resizeProjection = viewport; resizeRetries = 0; }
    const thisSequence = ++sequence;
    const request = { requestId, sequence: thisSequence, acknowledgedSubmission, ...frame };
    void enqueue(async () => {
      if (stopped) return;
      started = true;
      // Tauri creates a distinct Rust Channel owner for each argument. Only
      // the first successful attach keeps it; updates must not create a second
      // owner whose Drop could end the live callback. A rejected first attach
      // ends its own callback, so a geometry retry receives a fresh Channel ID.
      const completion = presented ? null : makeChannel(receive);
      const accepted = await invoke("sync_native_general_switches", { request, completion });
      if (accepted === false) {
        // Only a stale native/WebKit geometry pair is retried, on the next
        // animation frame and at most eight times for an unchanged viewport.
        if (stopped || sequence !== thisSequence) return;
        currentLayout = false;
        if (++resizeRetries > 8) throw new Error("Native switches could not match the current window layout");
        onLayout();
        return;
      }
      if (accepted !== true) throw new Error("Native switches returned an invalid layout acknowledgement");
      presented = true;
      resizeRetries = 0;
      acceptedSequence = thisSequence;
      if (!stopped && sequence === thisSequence) onReady(frame);
    }).catch(fail);
  }
  function focus(key) {
    const focusSequence = sequence;
    return enqueue(async () => {
      if (stopped || !latest?.items.some((i) => i.key === key && i.enabled)) return false;
      return invoke("focus_native_general_switch", { requestId, sequence: focusSequence, key });
    }).catch((error) => { fail(error); return false; });
  }
  return { sync, focus, fail, invalidate: () => { currentLayout = false; }, sequence: () => sequence,
    canFocus: (key) => !stopped && submitted === acknowledgedSubmission && latest?.items.some((i) => i.key === key && i.enabled) };
}

function intersection(a, b) {
  const x = Math.max(a.x, b.x), y = Math.max(a.y, b.y);
  return { x, y, width: Math.max(0, Math.min(a.x + a.width, b.x + b.width) - x),
    height: Math.max(0, Math.min(a.y + a.height, b.y + b.height) - y) };
}
function rectangle(element) {
  const { x, y, width, height } = element.getBoundingClientRect();
  return { x, y, width, height };
}

export function createNativeGeneralSwitches({ enabled, visible, isGeneral, locale, invoke, makeChannel, onToggle, onError }) {
  let transport = null, frameRequest = null, focusedKey = null, failed = false, forceLayout = false;
  let resizeObserver = null, observedPage = null;
  let returnFocusKey = null;
  function inputs() { return [...document.querySelectorAll(".cfw-general-view .inline-switch input[data-toggle]")]; }
  function inputFor(key) { return inputs().find((input) => GENERAL_SWITCH_KEYS.indexOf(input.dataset.toggle) + 1 === key); }
  function restore() {
    const occluded = isGeneral() && !visible();
    for (const input of inputs()) {
      const label = input.closest(".inline-switch");
      label.classList.remove("native-switch-ready");
      // These DOM mirrors must not become a second accessible/control owner
      // when the native layer is removed for a modal. Do not mutate the saved
      // input's disabled or checked state to express presentation occlusion.
      label.inert = occluded;
      if (occluded) label.setAttribute("aria-hidden", "true");
      else label.removeAttribute("aria-hidden");
      input.removeAttribute("data-native-general-key");
    }
  }
  function report(error) {
    failed = true;
    restore();
    onError(error);
  }
  function focusableElements(anchor = null) {
    return [...document.querySelectorAll("a[href],button,input,select,textarea,[tabindex]")]
      .filter((element) => (!element.disabled || element === anchor) && element.tabIndex >= 0 && element.getClientRects().length
        && (element.hasAttribute("data-native-general-key") || getComputedStyle(element).visibility !== "hidden"))
      .sort((a, b) => (a.tabIndex > 0 ? a.tabIndex : Infinity) - (b.tabIndex > 0 ? b.tabIndex : Infinity));
  }
  function move(from, direction) {
    const elements = focusableElements(from), index = elements.indexOf(from);
    if (index < 0 || !elements.length) return false;
    let next = null;
    for (let step = 1; step <= elements.length; step++) {
      const candidate = elements[(index + direction * step + elements.length) % elements.length];
      const key = Number(candidate.dataset.nativeGeneralKey);
      if (candidate !== from && !candidate.disabled && (!key || transport.canFocus(key))) { next = candidate; break; }
    }
    if (!next) return false;
    const key = Number(next.dataset.nativeGeneralKey);
    if (key) {
      next.closest(".inline-switch").scrollIntoView({ block: "nearest", inline: "nearest", behavior: "auto" });
      // scrollIntoView updates the DOM synchronously. Publish that geometry
      // before requesting native focus, including a previously clipped row.
      const frame = projection();
      if (frame) transport.sync(frame, true);
      void transport.focus(key).then((accepted) => {
        if (!accepted && !failed) transport.fail(new Error("The native switch could not receive keyboard focus"));
      });
    } else {
      focusedKey = null;
      next.focus();
    }
    return true;
  }
  function ensureTransport() {
    if (transport) return;
    transport = createGeneralSwitchTransport({ invoke, makeChannel,
      onToggle: async (key, checked) => {
        const input = inputs().find((i) => i.dataset.toggle === key);
        // Recheck the current DOM's original admission and page, not a saved item.
        if (!visible() || !input || input.disabled || input.checked === checked) return;
        returnFocusKey = GENERAL_SWITCH_KEYS.indexOf(key) + 1;
        await onToggle(key, checked);
        refresh();
      },
      onTraverse: (key, direction) => move(inputFor(key), direction),
      onFocus: (key) => { focusedKey = key; },
      onLayout: () => refresh(true),
      onReady: (frame) => {
        restore();
        for (const item of frame.items) {
          const input = inputFor(item.key);
          if (!input) continue;
          const label = input.closest(".inline-switch");
          // One accessibility/control owner only. The DOM retains layout and
          // business semantics; it is hidden while its native control is shown.
          label.classList.add("native-switch-ready");
          label.setAttribute("aria-hidden", "true");
          input.dataset.nativeGeneralKey = String(item.key);
        }
        // A native click, or the pending disabled interval, can leave WebKit's
        // old focus anchor behind. Restore the initiating control after its
        // acknowledgement or after the original dialog returns to this page.
        if (returnFocusKey && visible() && transport.canFocus(returnFocusKey)) {
          const key = returnFocusKey;
          returnFocusKey = null;
          void transport.focus(key).catch(report);
        }
      }, onError: report,
    });
    document.addEventListener("keydown", (event) => {
      if (failed || !visible() || event.key !== "Tab" || event.ctrlKey || event.metaKey || event.altKey) return;
      const all = focusableElements(), current = document.activeElement, index = all.indexOf(current);
      if (index < 0) return;
      const direction = event.shiftKey ? -1 : 1;
      const next = all[(index + direction + all.length) % all.length];
      if (next?.hasAttribute("data-native-general-key") && move(current, direction)) event.preventDefault();
    }, true);
    document.addEventListener("focusin", () => { focusedKey = null; }, true);
    document.addEventListener("pointerdown", () => { returnFocusKey = null; }, true);
    document.addEventListener("scroll", refresh, true);
    window.addEventListener("resize", refresh);
    window.addEventListener("focus", refresh);
    resizeObserver = new ResizeObserver(refresh);
  }
  function projection() {
    const appearance = resolvedGeneralAppearance(document.documentElement.dataset.theme);
    if (appearance === null) return null;
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    const empty = { locale: locale(), appearance,
      viewport, clip: { x: 0, y: 0, width: 0, height: 0 }, items: [] };
    const page = document.querySelector(".cfw-general-view");
    if (!visible() || !page) return empty;
    let clip = { x: 0, y: 0, ...viewport };
    for (let parent = page.querySelector(".cfw-content") ?? page; parent; parent = parent.parentElement) {
      const style = getComputedStyle(parent);
      if (/(auto|scroll|hidden|clip)/u.test(`${style.overflowX} ${style.overflowY}`)) {
        clip = intersection(clip, rectangle(parent));
      }
    }
    const items = inputs().map((input) => {
      const label = input.closest(".inline-switch"), key = GENERAL_SWITCH_KEYS.indexOf(input.dataset.toggle) + 1;
      if (key < 1) throw new Error("Unknown General switch cannot be presented natively");
      const text = label.querySelector(".visually-hidden")?.textContent.trim();
      const help = label.title ?? "";
      const name = help && text?.endsWith(` — ${help}`) ? text.slice(0, -(help.length + 3)) : text;
      return { key, label: name, help, checked: input.checked, enabled: !input.disabled, rect: rectangle(label) };
    });
    return { ...empty, clip, items };
  }
  function refresh(force = false) {
    if (!enabled() || failed) return;
    forceLayout = forceLayout || force === true;
    ensureTransport();
    if (frameRequest !== null) return;
    frameRequest = requestAnimationFrame(() => {
      frameRequest = null;
      const page = document.getElementById("page");
      if (observedPage !== page) {
        resizeObserver.disconnect(); observedPage = page;
        if (page) resizeObserver.observe(page);
      }
      const force = forceLayout;
      forceLayout = false;
      try {
        const frame = projection();
        if (frame) transport.sync(frame, force);
      } catch (error) { transport.fail(error); }
    });
  }
  function beforeRender() {
    if (!transport) return;
    if (failed) { restore(); return; }
    if (!isGeneral()) returnFocusKey = null;
    // Invalidate old page actions immediately, before asynchronous native layout.
    transport.invalidate();
    if (!visible()) {
      focusedKey = null;
      restore();
      // Publish occlusion now, not at the next animation frame. In particular,
      // an in-flight click acknowledgement must see this empty latest frame
      // instead of republishing the underlying six controls over a dialog.
      try {
        const frame = projection();
        if (frame) transport.sync(frame);
      } catch (error) { transport.fail(error); }
    }
  }
  return { refresh, beforeRender, focusedKey: () => focusedKey };
}
