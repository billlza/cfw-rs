// Settings > Background controls > Shortcuts & network rules on the installed
// application. The dialog names this platform's keys and shows the network
// Windows reports. A global shortcut for the core and a rule that starts
// Local proxy on a wired network are entered and applied, and the rule then
// starts the core by itself: nothing here presses Start. The hosted runner's
// network is wired, which the session requires. All mutations go through
// visible controls; IPC only observes.
(async (page, observeNative) => {
  const dialog = 'section.automation-settings-dialog';
  const shortcut = 'Control+Alt+Shift+F9';
  // How the pinned global-hotkey library names the same keys once registered.
  const registered = 'shift+control+alt+F9';
  const hints = [
    'Global shortcuts work while this app is in the background. Include Control, Alt or Super (Windows key); leave a field empty to disable it.',
    'The first matching rule applies after a network change or when enabled. Manual Stop stays stopped on the same network. Rules run while CFW is open.',
  ];
  const read = () => page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const automation = await invoke('read_automation_settings');
    // The runner's addresses stay out of the receipt; their families do not.
    const network = automation.network === null ? null : {
      kind: automation.network.kind, interface: automation.network.interface, ssid: automation.network.ssid,
      address_families: [...new Set(automation.network.addresses.map(address => address.includes(':') ? 'ipv6' : 'ipv4'))].sort(),
    };
    return { automation: { ...automation, network }, engine: await invoke('engine_snapshot') };
  });
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { boot: await invoke('boot_payload'), profiles: await invoke('profiles_snapshot') };
  });
  Object.assign(before, await read());
  const { automation, engine } = before;
  if (before.boot.product.operating_system !== 'windows' || engine.unavailable_reason !== null ||
      engine.snapshot.state.state !== 'off' || engine.snapshot.desired_mode !== 'off' ||
      engine.capabilities.local_proxy !== true || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 1 || before.profiles.profiles[0].active !== true) {
    throw new Error(`The automation case did not begin with the stopped LocalProxy profile alone: ${JSON.stringify(before)}`);
  }
  if (automation.settings.shortcuts.length !== 0 || automation.settings.network_enabled !== false ||
      automation.settings.network_rules.length !== 0 || automation.registered_shortcuts.length !== 0 ||
      automation.network_active !== false || automation.error !== null) {
    throw new Error(`The automation case did not begin without shortcuts and network rules: ${JSON.stringify(automation)}`);
  }
  // A rule for a wired network can only act where Windows reports one.
  if (automation.network_error !== null || automation.network?.kind !== 'wired' || automation.network.ssid !== null ||
      !automation.network.interface || automation.network.address_families.length === 0) {
    throw new Error(`Windows did not report a wired physical network: ${JSON.stringify(automation)}`);
  }
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('#nav button[data-page="settings"][aria-current="page"]').waitFor();
  await page.locator('[data-action="open-automation-settings"]').click();
  await page.locator(dialog).waitFor({ timeout: 15000 });
  const shown = await page.evaluate((query) => {
    const text = node => node.textContent.trim();
    const form = document.querySelector(query);
    return {
      title: text(form.querySelector('h2')),
      copies: [...form.querySelectorAll('p.glass-dialog-copy')].map(text),
      fields: [...form.querySelectorAll('input[data-shortcut-action]')].map(input => ({
        action: input.dataset.shortcutAction, label: text(input.parentElement), value: input.value, example: input.placeholder,
      })),
      enabled: form.querySelector('input[data-network-enabled]').checked,
      rules: form.querySelectorAll('.automation-rule-row').length,
      wifi_help: form.querySelector('[data-wifi-permission]') !== null,
    };
  }, dialog);
  const fields = [['show_dashboard', 'Show dashboard'], ['toggle_core', 'Start / stop core'],
    ['toggle_system_proxy', 'Toggle System Proxy'], ['toggle_tunnel', 'Toggle TUN']];
  if (shown.title !== 'Shortcuts & network rules' ||
      JSON.stringify(shown.copies) !== JSON.stringify([...hints, `Current network: Wired · ${automation.network.interface}`]) ||
      JSON.stringify(shown.fields) !== JSON.stringify(fields.map(([action, label]) => ({ action, label, value: '', example: 'Control+Alt+P' }))) ||
      shown.enabled !== false || shown.rules !== 0 || shown.wifi_help !== false) {
    throw new Error(`The dialog did not show this platform's keys and the wired network: ${JSON.stringify(shown)}`);
  }
  await page.locator(`${dialog} input[data-shortcut-action="toggle_core"]`).fill(shortcut);
  await page.locator(`${dialog} button[data-network-add]`).click();
  await page.locator(`${dialog} select[data-network-match="0"]`).selectOption('wired');
  await page.locator(`${dialog} select[data-network-mode="0"]`).selectOption('local_proxy');
  await page.locator(`${dialog} input[data-network-enabled]`).click();
  await page.screenshot({ path: 'automation-dialog.png' });
  await page.locator(`${dialog} button[data-automation-save]`).click();
  // The dialog closes once the shortcut is registered and the settings are stored.
  await page.locator(dialog).waitFor({ state: 'hidden', timeout: 15000 });
  const applied = Date.now();
  const saved = (await read()).automation;
  const { shortcuts, network_enabled, network_rules } = saved.settings;
  if (shortcuts.length !== 1 || shortcuts[0].action !== 'toggle_core' || shortcuts[0].shortcut !== shortcut ||
      network_enabled !== true || network_rules.length !== 1 || network_rules[0].mode !== 'local_proxy' ||
      JSON.stringify(network_rules[0].network) !== JSON.stringify({ type: 'wired' }) ||
      JSON.stringify(saved.registered_shortcuts) !== JSON.stringify([registered]) ||
      saved.network_active !== true || saved.error !== null || saved.network_error !== null ||
      typeof saved.revision !== 'string' || saved.revision === automation.revision) {
    throw new Error(`The applied shortcut and network rule were not stored and registered: ${JSON.stringify(saved)}`);
  }
  // The rule acts on the second of two equal observations, five seconds apart.
  const active = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'local_proxy_active') {
      if (value.snapshot.desired_mode !== 'local_proxy' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
        throw new Error('The network rule did not bring a ready LocalProxy runtime');
      }
      return value;
    }
    if (!['off', 'local_proxy_starting'].includes(state)) throw new Error(`Unexpected result of the network rule: ${JSON.stringify(value)}`);
    return false;
  }, undefined, { name: 'LocalProxy start by the network rule', timeoutMs: 45000 });
  const waited_ms = Date.now() - applied;
  const after = (await read()).automation;
  if (after.error !== null || after.network_active !== true || after.revision !== saved.revision) {
    throw new Error(`The network rule reported a failure: ${JSON.stringify(after)}`);
  }
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor({ timeout: 15000 });
  await page.screenshot({ path: 'automation-rule-started.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, shown, saved, active, waited_ms, snapshot,
    mutations: ['enter-shortcut:toggle_core', 'add-network-rule:wired:local_proxy', 'enable-network-rules', 'apply-automation'],
    core_started_by_network_rule: true, release_accepted: false };
})
