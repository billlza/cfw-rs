// What the installed application does after each real press of the global
// shortcut entered by automation-rule.js. The driver sends the keys through
// Windows and names the step. The first press stops the core the network rule
// started, and the rule, still in force on the same network, leaves it
// stopped. The second press starts the core; the dialog then refuses a
// shortcut without one of this platform's keys, and the shortcut and the rule
// are removed. The third press finds no shortcut and changes nothing. Nothing
// here presses Start or Stop. All mutations go through visible controls or
// the keyboard; IPC only observes.
(async (page, observeNative, _scenario, _quitInput, _observeController, step) => {
  if (!['automation-shortcut-stop', 'automation-shortcut-start', 'automation-shortcut-removed'].includes(step)) {
    throw new Error(`Unknown automation shortcut step: ${step}`);
  }
  const dialog = 'section.automation-settings-dialog';
  const shortcut = 'Control+Alt+Shift+F9';
  const registered = 'shift+control+alt+F9';
  const refusal = 'global shortcuts require Control, Alt or Super (Windows key)';
  const engine =() => page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  const automation = () => page.evaluate(async () => {
    const view = await window.__TAURI_INTERNALS__.invoke('read_automation_settings');
    // The runner's addresses stay out of the receipt.
    return { ...view, network: view.network === null ? null : { kind: view.network.kind, interface: view.network.interface, ssid: view.network.ssid } };
  });
  // The shortcut and the rule as automation-rule.js left them: stored,
  // registered with Windows and followed on the wired network.
  const inForce = ({ settings, registered_shortcuts, network_active, error, network_error, network }) =>
    settings.shortcuts.length === 1 && settings.shortcuts[0].action === 'toggle_core' && settings.shortcuts[0].shortcut === shortcut &&
    settings.network_enabled === true && settings.network_rules.length === 1 && settings.network_rules[0].mode === 'local_proxy' &&
    JSON.stringify(settings.network_rules[0].network) === JSON.stringify({ type: 'wired' }) &&
    JSON.stringify(registered_shortcuts) === JSON.stringify([registered]) &&
    network_active === true && error === null && network_error === null && network?.kind === 'wired';
  const off = value => value.unavailable_reason === null && value.snapshot.state.state === 'off' && value.snapshot.desired_mode === 'off';
  const running = value => value.unavailable_reason === null && value.snapshot.state.state === 'local_proxy_active' &&
    value.snapshot.desired_mode === 'local_proxy' && value.snapshot.state.runtime.ready === true &&
    value.snapshot.config_digest === value.snapshot.state.runtime.config_digest;
  const identity = value => JSON.stringify([value.snapshot.state.runtime, value.snapshot.generation, value.snapshot.config_digest]);
  // Look at the engine twice a second for the whole time; one look that
  // differs ends the step.
  const hold = async (milliseconds, same, failure) => {
    const until = Date.now() + milliseconds;
    let looks = 0;
    let last;
    do {
      last = await engine();
      if (!same(last)) throw new Error(`${failure}: ${JSON.stringify(last)}`);
      looks += 1;
      await new Promise(resolve => setTimeout(resolve, 500));
    } while (Date.now() < until);
    return { milliseconds, looks, last };
  };
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await automation();

  if (step === 'automation-shortcut-stop') {
    if (!inForce(before)) throw new Error(`The shortcut and the network rule were not in force: ${JSON.stringify(before)}`);
    const stopped = await observeNative(page, async () => {
      const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
      if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
      const state = value.snapshot.state.state;
      if (state === 'off') {
        if (value.snapshot.desired_mode !== 'off') throw new Error('Stopped engine still has a pending desired mode');
        return value;
      }
      if (!['local_proxy_active', 'local_proxy_stopping'].includes(state)) throw new Error(`Unexpected result of the shortcut: ${JSON.stringify(value)}`);
      return false;
    }, undefined, { name: 'LocalProxy stop by the global shortcut', timeoutMs: 30000 });
    await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).waitFor({ timeout: 15000 });
    // The rule looks at the network every five seconds and has acted on this
    // one already: twelve seconds hold at least two more of its looks.
    const held = await hold(12000, off, 'The network rule started the core again after the shortcut had stopped it');
    const after = await automation();
    if (!inForce(after) || after.revision !== before.revision) {
      throw new Error(`The network rule did not stay in force while the core stayed stopped: ${JSON.stringify(after)}`);
    }
    await page.screenshot({ path: `${step}.png` });
    const snapshot = await page.locator('body').ariaSnapshot();
    return { step, before, stopped, held, after, snapshot, mutations: [], core_stopped_by_shortcut: true,
      network_rule_left_core_stopped: true, release_accepted: false };
  }

  if (step === 'automation-shortcut-start') {
    if (!inForce(before)) throw new Error(`The shortcut and the network rule were not in force: ${JSON.stringify(before)}`);
    const active = await observeNative(page, async () => {
      const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
      if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
      const state = value.snapshot.state.state;
      if (state === 'local_proxy_active') {
        if (value.snapshot.desired_mode !== 'local_proxy' || value.snapshot.state.runtime.ready !== true ||
            value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
          throw new Error('The shortcut did not bring a ready LocalProxy runtime');
        }
        return value;
      }
      if (!['off', 'local_proxy_starting'].includes(state)) throw new Error(`Unexpected result of the shortcut: ${JSON.stringify(value)}`);
      return false;
    }, undefined, { name: 'LocalProxy start by the global shortcut', timeoutMs: 30000 });
    await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor({ timeout: 15000 });
    await page.locator('#nav button[data-page="settings"]').click();
    await page.locator('#nav button[data-page="settings"][aria-current="page"]').waitFor();
    await page.locator('[data-action="open-automation-settings"]').click();
    await page.locator(dialog).waitFor({ timeout: 15000 });
    // The dialog opens on what was stored.
    const shown = await page.evaluate((query) => {
      const form = document.querySelector(query);
      return {
        shortcuts: [...form.querySelectorAll('input[data-shortcut-action]')].map(input => [input.dataset.shortcutAction, input.value]),
        enabled: form.querySelector('input[data-network-enabled]').checked,
        rules: [...form.querySelectorAll('.automation-rule-row')].map(row => [
          row.querySelector('select[data-network-match]').value, row.querySelector('select[data-network-mode]').value]),
        alerts: [...form.querySelectorAll('[role="alert"]')].map(node => node.textContent.trim()),
      };
    }, dialog);
    if (JSON.stringify(shown) !== JSON.stringify({
      shortcuts: [['show_dashboard', ''], ['toggle_core', shortcut], ['toggle_system_proxy', ''], ['toggle_tunnel', '']],
      enabled: true, rules: [['wired', 'local_proxy']], alerts: [],
    })) {
      throw new Error(`The dialog did not open on the stored shortcut and rule: ${JSON.stringify(shown)}`);
    }
    // Shift alone is not one of the keys a global shortcut needs. The refusal
    // names the keys as this platform's dialog does, and changes nothing.
    await page.locator(`${dialog} input[data-shortcut-action="toggle_core"]`).fill('Shift+F9');
    await page.locator(`${dialog} button[data-automation-save]`).click();
    await page.locator(`${dialog} [role="alert"]`).waitFor({ timeout: 15000 });
    const refused = {
      alert: await page.evaluate(query => document.querySelector(query).textContent.trim(), `${dialog} [role="alert"]`),
      automation: await automation(),
    };
    await page.screenshot({ path: 'automation-shortcut-refused.png' });
    if (refused.alert !== refusal) {
      throw new Error(`The refusal of a shortcut without a required key did not name this platform's keys: ${JSON.stringify(refused.alert)}`);
    }
    if (!inForce(refused.automation) || refused.automation.revision !== before.revision) {
      throw new Error(`The refused shortcut changed what was stored or registered: ${JSON.stringify(refused.automation)}`);
    }
    await page.locator(`${dialog} input[data-shortcut-action="toggle_core"]`).fill('');
    await page.locator(`${dialog} button[data-network-remove="0"]`).click();
    await page.locator(`${dialog} input[data-network-enabled]`).click();
    await page.locator(`${dialog} button[data-automation-save]`).click();
    await page.locator(dialog).waitFor({ state: 'hidden', timeout: 15000 });
    const removed = await automation();
    if (removed.settings.shortcuts.length !== 0 || removed.settings.network_enabled !== false ||
        removed.settings.network_rules.length !== 0 || removed.registered_shortcuts.length !== 0 || removed.network_active !== false || removed.error !== null ||
        removed.revision === before.revision) {
      throw new Error(`The shortcut and the network rule were not removed: ${JSON.stringify(removed)}`);
    }
    // Changing the background controls leaves the running core alone.
    const kept = await engine();
    if (!running(kept) || identity(kept) !== identity(active)) {
      throw new Error(`Removing the shortcut and the rule changed the running core: ${JSON.stringify(kept)}`);
    }
    await page.locator('#nav button[data-page="general"]').click();
    await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor({ timeout: 15000 });
    await page.screenshot({ path: `${step}.png` });
    const snapshot = await page.locator('body').ariaSnapshot();
    return { step, before, active, shown, refused, removed, kept, snapshot,
      mutations: ['enter-shortcut-without-required-key', 'apply-automation:refused', 'clear-shortcut:toggle_core',
        'remove-network-rule', 'disable-network-rules', 'apply-automation'],
      core_started_by_shortcut: true, refusal_names_platform_keys: true, release_accepted: false };
  }

  if (before.settings.shortcuts.length !== 0 || before.settings.network_enabled !== false || before.settings.network_rules.length !== 0 ||
      before.registered_shortcuts.length !== 0 || before.network_active !== false || before.error !== null) {
    throw new Error(`The shortcut and the network rule were still present: ${JSON.stringify(before)}`);
  }
  const began = await engine();
  if (!running(began)) throw new Error(`The third press changed the core although the shortcut was removed: ${JSON.stringify(began)}`);
  const held = await hold(6000, value => running(value) && identity(value) === identity(began),
    'The removed shortcut still changed the core');
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor({ timeout: 15000 });
  await page.screenshot({ path: `${step}.png` });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { step, before, began, held, snapshot, mutations: [], removed_shortcut_ignored: true, release_accepted: false };
})
