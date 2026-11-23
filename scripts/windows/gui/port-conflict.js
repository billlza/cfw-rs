// Local ports another program holds when the core starts or its settings
// change, with the LocalProxy profile alone. The application moves an
// automatic port it cannot bind to the next one, restores the core it ran when
// a changed setting asks for a port it cannot bind, and says so when a start
// cannot bind the port the user configured. IPC only observes. The driver
// names the step and, after the first one, passes the ports the session holds:
// the automatic proxy and controller ports, a third one to configure and a
// fourth one on every address, for LAN sharing.
(async (page, observeNative, _scenario, _quitInput, observeController, step, plan) => {
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
  const local = view => (view.config.inbounds ?? []).filter(entry => entry.tag === 'cfw-system-proxy')
    .map(entry => `${entry.type} ${entry.listen}:${entry.listen_port}`);
  const controllerPort = (view) => {
    const address = /^127\.0\.0\.1:(\d+)$/.exec(view.config.experimental?.clash_api?.external_controller ?? '');
    return address ? Number(address[1]) : null;
  };
  // The ports a core of this view listens on, or would listen on once started.
  const ports = view => ({ mixed: view.settings.effective.mixed_port, controller: controllerPort(view), local: local(view) });
  const atPorts = (view, mixed, controller) =>
    same(ports(view), { mixed, controller, local: [`mixed 127.0.0.1:${mixed}`] });
  const runningLocal = view => view.engine.unavailable_reason === null &&
    view.engine.snapshot.state.state === 'local_proxy_active' && view.engine.snapshot.desired_mode === 'local_proxy' &&
    view.engine.snapshot.state.runtime?.ready === true && view.engine.snapshot.state.runtime.owner === 'windows_user_agent' &&
    view.engine.snapshot.config_digest === view.engine.snapshot.state.runtime.config_digest;
  const stopped = view => view.engine.unavailable_reason === null && view.engine.snapshot.state.state === 'off' &&
    view.engine.snapshot.desired_mode === 'off';
  const general = async () => {
    await page.locator('#nav button[data-page="general"]').click();
    await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  };
  // The row of the General page that opens the dialog and shows exactly `text`.
  const row = text => page.locator('[data-action="open-runtime-settings"]:enabled')
    .filter({ hasText: new RegExp(`^${text.replaceAll('.', '\\.')}$`) });
  const dialog = page.getByRole('dialog', { name: 'Network settings', exact: true });
  const field = name => dialog.locator(`[data-runtime-field="${name}"]`);
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
  // Press Start core and wait until the core runs, or until the page offers
  // the control again with the reason the start failed. Between attempts the
  // coordinator publishes Off while it still means to run the local proxy.
  const start = async (name) => {
    await page.locator('[data-action="toggle-core"]:enabled').filter({ hasText: 'Start core' }).click();
    return observeNative(page, async () => {
      const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
      if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
      const state = value.snapshot.state.state;
      if (!['off', 'local_proxy_starting', 'local_proxy_stopping', 'local_proxy_active'].includes(state)) {
        throw new Error(`Unexpected start result: ${JSON.stringify(value)}`);
      }
      const toggle = document.querySelector('[data-action="toggle-core"]');
      if (state === 'local_proxy_active') return toggle && !toggle.disabled ? { started: value } : false;
      const reason = document.querySelector('.cfw-row-reason small')?.textContent ?? null;
      return toggle && !toggle.disabled && state === 'off' && reason !== null ? { refused: value, reason } : false;
    }, undefined, { name, timeoutMs: 75000 });
  };
  const held = () => {
    const values = [plan?.mixed, plan?.controller, plan?.configured, plan?.lan];
    if (!values.every(value => Number.isInteger(value) && value >= 1024 && value <= 65535) || new Set(values).size !== 4) {
      throw new Error(`The ports the session holds are invalid: ${JSON.stringify(plan)}`);
    }
    return { mixed: plan.mixed, controller: plan.controller, configured: plan.configured, lan: plan.lan };
  };

  if (step === 'port-conflict-ports') {
    await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
    const before = await read();
    const profiles = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('profiles_snapshot'));
    const saved = before.settings.settings;
    const automatic = ports(before);
    if (profiles.invalid_profiles.length !== 0 || profiles.profiles.length !== 1 || profiles.profiles[0].active !== true ||
        !stopped(before) || saved.preferred_mixed_port !== null || saved.allow_lan !== false || saved.lan_proxy !== null ||
        !Number.isInteger(automatic.controller) || !atPorts(before, automatic.mixed, automatic.controller)) {
      throw fail('The port conflict session did not begin stopped, with one profile and automatic ports', { profiles, before });
    }
    return { before, profile: profiles.profiles[0].id, mixed: automatic.mixed, controller: automatic.controller,
      mutations: [], release_accepted: false };
  }

  if (step === 'port-conflict-start') {
    const { mixed, controller } = held();
    await general();
    const before = await read();
    if (!stopped(before) || !atPorts(before, mixed, controller)) {
      throw fail('The core is not stopped on the automatic ports the session holds', before);
    }
    const outcome = await start('LocalProxy start beside two held ports');
    if (!outcome.started) throw fail('The start did not move past the held ports', outcome);
    const active = await read();
    // Each held port moved to the next candidate of its kind, and nothing was saved.
    if (!runningLocal(active) || !same(active.engine.snapshot, outcome.started.snapshot) ||
        !atPorts(active, mixed + 1, controller + 1) || !same(active.settings.settings, before.settings.settings) ||
        active.settings.revision !== before.settings.revision) {
      throw fail('The core did not start on the next automatic ports', active);
    }
    await page.locator('[data-action="toggle-core"]:enabled').filter({ hasText: 'Stop core' }).waitFor({ timeout: 15000 });
    await row(`127.0.0.1:${mixed + 1}`).waitFor({ timeout: 15000 });
    const rows = await observeNative(page, () => {
      const text = document.querySelector('.cfw-content')?.innerText ?? '';
      return text.includes('Automatic port') && !document.querySelector('.cfw-row-reason') ? { shown: true } : false;
    }, undefined, { name: 'General page after the moved ports', timeoutMs: 15000 });
    const controllerProof = await observeController(page, active.engine, 'local-proxy');
    await page.screenshot({ path: 'port-conflict-started.png' });
    return { before, outcome, active, rows, ...controllerProof,
      snapshot: await page.locator('body').ariaSnapshot(),
      mutations: ['toggle-core'], release_accepted: false };
  }

  if (step === 'port-conflict-settings') {
    const { mixed, controller, configured } = held();
    await general();
    const before = await read();
    if (!runningLocal(before) || !atPorts(before, mixed + 1, controller + 1)) {
      throw fail('The core no longer runs on the ports it moved to', before);
    }
    await row(`127.0.0.1:${mixed + 1}`).click();
    await dialog.waitFor();
    if (await field('port').inputValue() !== '') throw new Error('The dialog does not show an automatic port');
    await field('port').fill(String(configured));
    const outcome = await apply('configured port another program holds', true);
    if (outcome.refusal !== 'native start start_local_proxy encountered MixedEndpointInUse; exact cleanup and ' +
        'independent global Off were proven, so a fresh endpoint projection is required; the previous runtime was restored') {
      throw fail('The application did not restore the previous core for the held port', outcome);
    }
    await page.screenshot({ path: 'port-conflict-restored.png' });
    const restored = await read();
    // A new engine of the previous configuration: the held port was not saved.
    if (!runningLocal(restored) || restored.engine.snapshot.generation <= before.engine.snapshot.generation ||
        !atPorts(restored, mixed + 1, controller + 1) || !same(restored.settings, before.settings)) {
      throw fail('The previous core was not restored with the settings it ran', restored);
    }
    await dialog.locator('button[data-runtime-dismiss]:enabled').click();
    await dialog.waitFor({ state: 'hidden' });
    return { before, outcome, restored, mutations: ['runtime-settings:port'], release_accepted: false };
  }

  if (step === 'port-conflict-lan') {
    const { mixed, controller, lan } = held();
    await general();
    const before = await read();
    if (!runningLocal(before) || !atPorts(before, mixed + 1, controller + 1) || before.settings.settings.allow_lan !== false ||
        before.settings.effective.lan_proxy !== null || lan === mixed + 1 || lan === controller + 1) {
      throw fail('The core does not run on the ports it moved to without LAN sharing', before);
    }
    // LAN sharing on every address, on the port the session holds there: the
    // engine cannot start, which is no endpoint the application moves, and the
    // application restores the core it ran.
    await row(`127.0.0.1:${mixed + 1}`).click();
    await dialog.waitFor();
    await field('allow').check();
    if (await field('lanAddress').inputValue() !== '0.0.0.0') throw new Error('The dialog does not offer every address');
    await field('lanPort').fill(String(lan));
    await field('lanSources').fill('10.0.0.0/8');
    const outcome = await apply('LAN sharing on a port another program holds', true);
    if (outcome.refusal !== 'native operation start_local_proxy failed: SystemProxyRuntimeFailed: Windows Desktop ' +
        'start: the engine could not start; the previous runtime was restored') {
      throw fail('The application did not restore the previous core for the held LAN port', outcome);
    }
    const restored = await read();
    // A new engine of the previous configuration: LAN sharing was not saved.
    if (!runningLocal(restored) || restored.engine.snapshot.generation <= before.engine.snapshot.generation ||
        !atPorts(restored, mixed + 1, controller + 1) || !same(restored.settings, before.settings) ||
        (restored.config.inbounds ?? []).some(entry => entry.tag === 'cfw-lan-proxy')) {
      throw fail('The previous core was not restored with the settings it ran', restored);
    }
    await dialog.locator('button[data-runtime-dismiss]:enabled').click();
    await dialog.waitFor({ state: 'hidden' });
    return { before, outcome, restored, mutations: ['runtime-settings:lan'], release_accepted: false };
  }

  if (step === 'port-conflict-configured') {
    const { mixed, configured } = held();
    await general();
    const before = await read();
    if (!stopped(before) || before.settings.settings.preferred_mixed_port !== null) {
      throw fail('The core is not stopped with an automatic port', before);
    }
    // Saved with the core off, and refused at the start, once the application
    // has cleaned up and proven the core off.
    await row(`127.0.0.1:${before.settings.effective.mixed_port}`).click();
    await dialog.waitFor();
    await field('port').fill(String(configured));
    await apply('configured port with the core off');
    const saved = await read();
    if (!same(saved.engine.snapshot, before.engine.snapshot) || saved.settings.settings.preferred_mixed_port !== configured ||
        saved.settings.effective.mixed_port !== configured || saved.settings.revision === before.settings.revision) {
      throw fail('The configured port was not saved with the core off', saved);
    }
    await row(`127.0.0.1:${configured}`).waitFor({ timeout: 15000 });
    const outcome = await start('LocalProxy start on the held configured port');
    if (!outcome.refused || outcome.reason !== `the configured local proxy port ${configured} is already reserved; ` +
        'choose a different port or automatic selection') {
      throw fail('The start on the held configured port did not end with its reason', outcome);
    }
    const refused = await read();
    // Off as proven by the application, which still records the request.
    if (refused.engine.unavailable_reason !== null || refused.engine.snapshot.state.state !== 'off' ||
        refused.engine.snapshot.desired_mode !== 'local_proxy' || !same(refused.settings, saved.settings)) {
      throw fail('The refused start did not leave the core off with the configured port', refused);
    }
    await page.screenshot({ path: 'port-conflict-refused.png' });
    await page.locator('[data-action="toggle-core"]:enabled').filter({ hasText: 'Stop core' }).click();
    const withdrawn = await observeNative(page, async () => {
      const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
      if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
      if (value.snapshot.state.state !== 'off') throw new Error(`Unexpected withdrawal result: ${JSON.stringify(value)}`);
      const toggle = document.querySelector('[data-action="toggle-core"]');
      return value.snapshot.desired_mode === 'off' && toggle && !toggle.disabled ? value : false;
    }, undefined, { name: 'withdrawn start', timeoutMs: 30000 });
    await page.locator('[data-action="toggle-core"]:enabled').filter({ hasText: 'Start core' }).waitFor({ timeout: 15000 });
    // The automatic port again: the session ends as it began.
    await row(`127.0.0.1:${configured}`).click();
    await dialog.waitFor();
    await field('port').fill('');
    await apply('automatic port');
    const restored = await read();
    if (!stopped(restored) || restored.settings.settings.preferred_mixed_port !== null ||
        restored.settings.effective.mixed_port !== mixed) {
      throw fail('The automatic port was not restored', restored);
    }
    await row(`127.0.0.1:${mixed}`).waitFor({ timeout: 15000 });
    await page.locator('#nav button[data-page="settings"]').click();
    await page.locator('[data-action="quit-app"]').waitFor();
    return { before, saved, outcome, refused, withdrawn, restored,
      mutations: ['runtime-settings:port', 'toggle-core', 'toggle-core', 'runtime-settings:port'], release_accepted: false };
  }

  throw new Error(`Unknown port conflict step: ${step}`);
})
