// The runtime settings of the installed application, changed through the
// Network settings dialog and the General page's own controls: the local
// proxy port, LAN sharing, the log level and the TUN MTU. A change that
// reaches a running engine replaces it with one built from the new settings;
// with the core off it is only saved. IPC only observes. The driver names
// the step and passes the session's plan: a local port and a LAN port that
// nothing listens on, this machine's private address, which is the one source
// the session trusts, and, for the last step, the settings the session began
// with.
(async (page, observeNative, _scenario, _quitInput, observeController, step, plan) => {
  const port = plan?.port;
  const lanPort = plan?.lan_port;
  const trusted = plan?.trusted_source;
  if (![port, lanPort].every(value => Number.isInteger(value) && value >= 1024 && value <= 65535) || port === lanPort ||
      typeof trusted !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trusted)) {
    throw new Error(`The runtime settings plan is invalid: ${JSON.stringify(plan)}`);
  }
  const source = `${trusted}/32`;
  const lan = { listen: '0.0.0.0', port: lanPort, allowed_source_cidrs: [source] };
  // The MTU the session saves with the core off, and the one it changes to
  // while TUN Mode runs. Neither is the product's default.
  const savedMtu = 1400;
  const liveMtu = 1280;
  // Two values are the same when they hold the same data, whatever the order
  // of their keys.
  const canonical = value => JSON.stringify(value, (_key, inner) => inner && typeof inner === 'object' && !Array.isArray(inner)
    ? Object.fromEntries(Object.entries(inner).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))) : inner);
  const same = (left, right) => canonical(left) === canonical(right);
  const fail = (message, view) => new Error(`${message}: ${JSON.stringify(view)}`);
  const read = () => page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const engine = await invoke('engine_snapshot');
    const settings = await invoke('read_runtime_settings_snapshot');
    // What the engine runs in the current mode, or would run once started.
    const config = JSON.parse(await invoke('read_runtime_config_text'));
    return { engine, settings, config };
  });
  const inbounds = (view, tag) => (view.config.inbounds ?? []).filter(entry => entry.tag === tag);
  const listeners = (view, tag) => inbounds(view, tag).map(entry => `${entry.type} ${entry.listen}:${entry.listen_port}`);
  const local = view => listeners(view, 'cfw-system-proxy');
  const shared = view => listeners(view, 'cfw-lan-proxy');
  const tunnel = view => inbounds(view, 'cfw-tunnel').map(entry => `${entry.type} ${entry.mtu}`);
  // Every route rule that names the LAN listener, with its place. Sharing
  // puts one rule first, which refuses every source outside the trusted ranges.
  const lanRules = view => (view.config.route?.rules ?? []).flatMap((rule, index) =>
    JSON.stringify(rule).includes('cfw-lan-proxy') ? [{ index, rule }] : []);
  const refusesOthers = [{ index: 0, rule: { type: 'logical', mode: 'and',
    rules: [{ inbound: ['cfw-lan-proxy'] }, { source_ip_cidr: [source], invert: true }], action: 'reject' } }];
  const running = (view, state, owner) => view.engine.unavailable_reason === null &&
    view.engine.snapshot.state.state === state && view.engine.snapshot.state.runtime?.ready === true &&
    view.engine.snapshot.state.runtime.owner === owner &&
    view.engine.snapshot.config_digest === view.engine.snapshot.state.runtime.config_digest;
  const runningLocal = view => running(view, 'local_proxy_active', 'windows_user_agent');
  const runningTunnel = view => running(view, 'tunnel_active', 'windows_tunnel_service');
  const stopped = view => view.engine.unavailable_reason === null && view.engine.snapshot.state.state === 'off' &&
    view.engine.snapshot.desired_mode === 'off';
  // A newer engine of the same mode, built from another configuration.
  const replaced = (before, after) => after.engine.snapshot.desired_mode === before.engine.snapshot.desired_mode &&
    after.engine.snapshot.generation > before.engine.snapshot.generation &&
    after.engine.snapshot.config_digest !== before.engine.snapshot.config_digest;
  const general = async () => {
    await page.locator('#nav button[data-page="general"]').click();
    await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  };
  // The row of the General page that opens the dialog and shows exactly `text`.
  const row = text => page.locator('[data-action="open-runtime-settings"]:enabled')
    .filter({ hasText: new RegExp(`^${text.replaceAll('.', '\\.')}$`) });
  const dialog = page.getByRole('dialog', { name: 'Network settings', exact: true });
  const field = name => dialog.locator(`[data-runtime-field="${name}"]`);
  // The dialog as the application filled it from the saved settings.
  const open = async (text) => {
    await row(text).click();
    await dialog.waitFor();
    return { port: await field('port').inputValue(), level: await field('level').inputValue(),
      mtu: await field('mtu').inputValue(), allow: await field('allow').isChecked(),
      lanAddress: await field('lanAddress').inputValue(), lanPort: await field('lanPort').inputValue(),
      lanSources: await field('lanSources').inputValue() };
  };
  // Press Apply and wait for the application's answer: it closes the dialog
  // on a change it applied and keeps a refusal on show in it.
  const apply = async (name, refusalExpected = false) => {
    await dialog.locator('[data-runtime-save]:enabled').click();
    return observeNative(page, (refusalExpected) => {
      const shown = document.querySelector('.runtime-settings-dialog');
      const alert = shown?.querySelector('[role="alert"]');
      const save = shown?.querySelector('[data-runtime-save]');
      if (refusalExpected) {
        if (!shown) throw new Error('The dialog closed although its change was to be refused');
        return alert && save && !save.disabled ? { refusal: alert.textContent } : false;
      }
      if (alert) throw new Error(`The change was refused: ${alert.textContent}`);
      return shown ? false : { applied: true };
    }, refusalExpected, { name, timeoutMs: 75000 });
  };
  // A control of the General page was used: wait for a newer active engine,
  // and for the page to offer the control again with the value it was given.
  const changed = (name, before, query, expected) => observeNative(page, async ({ started, query, expected }) => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    // The coordinator publishes Off between retiring the engine and starting its replacement.
    if (!['local_proxy_active', 'local_proxy_stopping', 'off', 'local_proxy_starting'].includes(state)) {
      throw new Error(`Unexpected result of a settings change: ${JSON.stringify(value)}`);
    }
    if (state !== 'local_proxy_active' || value.snapshot.generation <= started) return false;
    const control = document.querySelector(query);
    if (!control || control.disabled) return false;
    const shown = control.type === 'checkbox' ? control.checked : control.value;
    if (shown !== expected) throw new Error(`The page took the control back as ${shown}`);
    return value;
  }, { started: before.engine.snapshot.generation, query, expected }, { name, timeoutMs: 30000 });

  if (step === 'runtime-settings-apply') {
    await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
    const before = await read();
    const profiles = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('profiles_snapshot'));
    const defaults = before.settings.settings;
    if (profiles.invalid_profiles.length !== 0 || profiles.profiles.length !== 1 || profiles.profiles[0].active !== true ||
        !stopped(before) || defaults.preferred_mixed_port !== null || defaults.allow_lan !== false ||
        defaults.lan_proxy !== null || defaults.log_level !== 'info' || before.settings.effective.lan_proxy !== null ||
        [savedMtu, liveMtu].includes(defaults.tunnel_mtu) ||
        [port, lanPort].includes(before.settings.effective.mixed_port)) {
      throw fail('The runtime settings session did not begin stopped, with one profile and the default settings', { profiles, before });
    }
    await page.locator('[data-action="toggle-core"]:enabled').filter({ hasText: 'Start core' }).click();
    const started = await observeNative(page, async () => {
      const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
      if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
      const state = value.snapshot.state.state;
      if (!['off', 'local_proxy_starting', 'local_proxy_active'].includes(state)) {
        throw new Error(`Unexpected start result: ${JSON.stringify(value)}`);
      }
      return state === 'local_proxy_active' ? value : false;
    }, undefined, { name: 'LocalProxy start', timeoutMs: 30000 });
    await page.locator('[data-action="toggle-core"]:enabled').filter({ hasText: 'Stop core' }).waitFor({ timeout: 15000 });
    const automatic = await read();
    const defaultPort = automatic.settings.effective.mixed_port;
    if (!runningLocal(automatic) || !same(automatic.engine.snapshot, started.snapshot) ||
        !same(local(automatic), [`mixed 127.0.0.1:${defaultPort}`]) || shared(automatic).length !== 0 ||
        lanRules(automatic).length !== 0) {
      throw fail('The core did not start on the automatic local port alone', automatic);
    }
    const opened = await open(`127.0.0.1:${defaultPort}`);
    if (!same(opened, { port: '', level: 'info', mtu: String(defaults.tunnel_mtu), allow: false,
      lanAddress: '0.0.0.0', lanPort: '7898', lanSources: '' })) {
      throw fail('The dialog did not show the default settings', opened);
    }
    await field('port').fill(String(port));
    await field('allow').check();
    await field('lanPort').fill(String(lanPort));
    await field('lanSources').fill(source);
    const outcome = await apply('port and LAN sharing');
    const active = await read();
    const saved = active.settings.settings;
    if (!runningLocal(active) || !replaced(automatic, active) ||
        saved.preferred_mixed_port !== port || saved.allow_lan !== true || !same(saved.lan_proxy, lan) ||
        active.settings.effective.mixed_port !== port || !same(active.settings.effective.lan_proxy, lan) ||
        active.settings.revision === before.settings.revision ||
        !same(local(active), [`mixed 127.0.0.1:${port}`]) || !same(shared(active), [`mixed 0.0.0.0:${lanPort}`]) ||
        !same(lanRules(active), refusesOthers)) {
      throw fail('The running core was not replaced by one with the configured port and LAN sharing', active);
    }
    // The General page shows what was applied.
    await row(`127.0.0.1:${port}`).waitFor({ timeout: 15000 });
    const rows = await observeNative(page, (bind) => {
      const text = document.querySelector('.cfw-content')?.innerText ?? '';
      const toggle = document.querySelector('[data-toggle="allowLan"]');
      return text.includes('Configured port') && text.includes(bind) && text.includes('Trusted sources only') &&
        toggle?.checked === true && !toggle.disabled ? { shown: true } : false;
    }, `Bind: 0.0.0.0:${lanPort}`, { name: 'General page after the change', timeoutMs: 15000 });
    const controllerProof = await observeController(page, active.engine, 'local-proxy');
    await page.screenshot({ path: 'runtime-settings-applied.png' });
    return { before, profile: profiles.profiles[0].id, started, default_port: defaultPort, opened, outcome, active, rows,
      ...controllerProof,
      snapshot: await page.locator('body').ariaSnapshot(),
      mutations: ['toggle-core', 'runtime-settings:port', 'runtime-settings:lan'], release_accepted: false };
  }

  if (step === 'runtime-settings-refused') {
    await general();
    const before = await read();
    if (!runningLocal(before) || !same(before.settings.effective.lan_proxy, lan)) {
      throw fail('The core with LAN sharing is no longer running', before);
    }
    const opened = await open(`127.0.0.1:${port}`);
    if (opened.port !== String(port) || opened.allow !== true || opened.lanPort !== String(lanPort) || opened.lanSources !== source) {
      throw fail('The dialog did not show the applied settings', opened);
    }
    // A documentation range of the public Internet beside the trusted source.
    await field('lanSources').fill(`${source}\n203.0.113.0/24`);
    const outcome = await apply('refusal of a public source range', true);
    if (outcome.refusal !== 'unsupported credential-free policy shape at $.runtime_settings: ' +
        'LAN source ranges must be distinct canonical CIDRs within private IPv4 networks') {
      throw fail('The application refused the public source range for another reason', outcome);
    }
    await page.screenshot({ path: 'runtime-settings-refused.png' });
    const kept = await read();
    // Refused before the engine or the saved settings were touched.
    if (!same(kept.engine.snapshot, before.engine.snapshot) || !same(kept.settings, before.settings) ||
        !same(kept.config, before.config)) {
      throw fail('The refused change altered the running core or the saved settings', kept);
    }
    await dialog.locator('button[data-runtime-dismiss]:enabled').click();
    await dialog.waitFor({ state: 'hidden' });
    return { before, opened, outcome, kept, mutations: [], release_accepted: false };
  }

  if (step === 'runtime-settings-general') {
    await general();
    const before = await read();
    if (!runningLocal(before) || before.settings.effective.log_level !== 'info' ||
        !same(before.settings.effective.lan_proxy, lan) || before.config.log?.level !== 'info') {
      throw fail('The core with LAN sharing and the default log level is no longer running', before);
    }
    const level = page.locator('select[data-runtime-log-level]:enabled');
    if (await level.inputValue() !== 'info') throw new Error('The General page does not show the default log level');
    await level.selectOption('debug');
    await changed('log level change', before, 'select[data-runtime-log-level]', 'debug');
    const levelled = await read();
    if (!runningLocal(levelled) || !replaced(before, levelled) || levelled.settings.settings.log_level !== 'debug' ||
        levelled.settings.effective.log_level !== 'debug' || levelled.config.log?.level !== 'debug' ||
        !same(shared(levelled), shared(before)) || !same(lanRules(levelled), refusesOthers)) {
      throw fail('The running core was not replaced by one that logs at the debug level', levelled);
    }
    // The running engine's own account of its level, once its controller answers.
    const reported = await observeNative(page, async () => {
      let controller;
      try { controller = await window.__TAURI_INTERNALS__.invoke('controller_snapshot'); } catch { return false; }
      return { log_level: controller.config['log-level'] };
    }, undefined, { name: 'controller of the replaced core', timeoutMs: 15000 });
    if (reported.log_level !== 'debug') throw fail('The running engine does not log at the debug level', reported);
    // The Allow LAN switch turns sharing off and keeps the saved listener.
    await page.locator('label.inline-switch').filter({ has: page.locator('[data-toggle="allowLan"]') }).click();
    await changed('LAN sharing off', levelled, '[data-toggle="allowLan"]', false);
    const active = await read();
    if (!runningLocal(active) || !replaced(levelled, active) ||
        active.settings.settings.allow_lan !== false || !same(active.settings.settings.lan_proxy, lan) ||
        active.settings.effective.lan_proxy !== null || shared(active).length !== 0 || lanRules(active).length !== 0 ||
        !same(local(active), [`mixed 127.0.0.1:${port}`]) || active.config.log?.level !== 'debug') {
      throw fail('The running core was not replaced by one without LAN sharing', active);
    }
    const rows = await observeNative(page, () => {
      const text = document.querySelector('.cfw-content')?.innerText ?? '';
      return text.includes('Bind: Off') && text.includes('Local devices only') ? { shown: true } : false;
    }, undefined, { name: 'General page without LAN sharing', timeoutMs: 15000 });
    await page.screenshot({ path: 'runtime-settings-general.png' });
    return { before, levelled, reported, active, rows, mutations: ['log-level:debug', 'allowLan:off'], release_accepted: false };
  }

  if (step === 'runtime-settings-mtu') {
    await general();
    const before = await read();
    if (!stopped(before) || [savedMtu, liveMtu].includes(before.settings.effective.tunnel_mtu)) {
      throw fail('The core is not stopped with the default MTU', before);
    }
    const opened = await open(String(before.settings.effective.tunnel_mtu));
    await field('mtu').fill(String(savedMtu));
    const outcome = await apply('MTU with the core off');
    const saved = await read();
    if (!same(saved.engine.snapshot, before.engine.snapshot) || saved.settings.settings.tunnel_mtu !== savedMtu ||
        saved.settings.effective.tunnel_mtu !== savedMtu || saved.settings.revision === before.settings.revision) {
      throw fail('The MTU was not saved with the core off', saved);
    }
    await row(String(savedMtu)).waitFor({ timeout: 15000 });
    return { before, opened, outcome, saved, saved_mtu: savedMtu, mutations: ['runtime-settings:mtu'], release_accepted: false };
  }

  if (step === 'runtime-settings-live-mtu') {
    await general();
    const before = await read();
    if (!runningTunnel(before) || before.settings.effective.tunnel_mtu !== savedMtu || !same(tunnel(before), [`tun ${savedMtu}`])) {
      throw fail('TUN Mode does not run with the saved MTU', before);
    }
    const opened = await open(String(savedMtu));
    if (opened.mtu !== String(savedMtu)) throw fail('The dialog did not show the saved MTU', opened);
    await field('mtu').fill(String(liveMtu));
    const outcome = await apply('MTU while TUN Mode runs');
    const active = await read();
    if (!runningTunnel(active) || !replaced(before, active) || active.settings.settings.tunnel_mtu !== liveMtu ||
        active.settings.effective.tunnel_mtu !== liveMtu || !same(tunnel(active), [`tun ${liveMtu}`])) {
      throw fail('The TUN runtime was not replaced by one with the changed MTU', active);
    }
    await row(String(liveMtu)).waitFor({ timeout: 15000 });
    await observeNative(page, () => {
      const input = document.querySelector('[data-toggle="tunMode"]');
      return input && !input.disabled && input.checked ? { tunnel_on: true } : false;
    }, undefined, { name: 'TUN switch after the MTU change', timeoutMs: 15000 });
    await page.screenshot({ path: 'runtime-settings-live-mtu.png' });
    return { before, opened, outcome, active, live_mtu: liveMtu, mutations: ['runtime-settings:mtu'], release_accepted: false };
  }

  if (step === 'runtime-settings-defaults') {
    const initial = plan.initial;
    if (!initial || typeof initial.settings !== 'object' || typeof initial.effective !== 'object') {
      throw new Error('The settings the session began with were not passed on');
    }
    await general();
    const before = await read();
    const kept = before.settings.settings;
    if (!stopped(before) || kept.preferred_mixed_port !== port || kept.log_level !== 'debug' ||
        kept.tunnel_mtu !== liveMtu || kept.allow_lan !== false || !same(kept.lan_proxy, lan)) {
      throw fail('The core is not stopped with every changed setting saved', before);
    }
    const opened = await open(`127.0.0.1:${port}`);
    if (!same(opened, { port: String(port), level: 'debug', mtu: String(liveMtu), allow: false,
      lanAddress: '0.0.0.0', lanPort: String(lanPort), lanSources: source })) {
      throw fail('The dialog did not show the changed settings', opened);
    }
    await field('port').fill('');
    await field('level').selectOption('info');
    await field('mtu').fill(String(initial.settings.tunnel_mtu));
    await field('lanSources').fill('');
    const outcome = await apply('default settings');
    const restored = await read();
    if (!same(restored.engine.snapshot, before.engine.snapshot) || !same(restored.settings.settings, initial.settings) ||
        !same(restored.settings.effective, initial.effective) || restored.settings.revision === before.settings.revision) {
      throw fail('The settings the session began with were not restored', restored);
    }
    await row(`127.0.0.1:${initial.effective.mixed_port}`).waitFor({ timeout: 15000 });
    await page.screenshot({ path: 'runtime-settings-defaults.png' });
    await page.locator('#nav button[data-page="settings"]').click();
    await page.locator('[data-action="quit-app"]').waitFor();
    return { before, opened, outcome, restored, mutations: ['runtime-settings:defaults'], release_accepted: false };
  }

  throw new Error(`Unknown runtime settings step: ${step}`);
})
