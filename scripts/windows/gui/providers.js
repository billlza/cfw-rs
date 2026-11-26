// The steps of the providers session; the session tells each step its name.
// Beside the LocalProxy session's profile, a profile of two proxy providers
// and a rule provider is imported from text. "checked" is inline: one HTTP
// node at the session's stand-in, which answers only the health check the
// profile declares and dials nothing. "downloaded", whose node never
// resolves, and the rule provider "listed" are documents GitHub serves from
// the commit under test. With the core off, a health check runs in the
// transient probe engine and the rule provider is updated. With the core on,
// Health Check All runs through the core, and Update All of the unchanged
// documents keeps the runtime it ran. Once the session stops its stand-in, the
// check fails. The profile is deleted with the core off, so the next session
// begins as this one did. All mutations go through visible controls; IPC only
// observes.
(async (page, observeNative, _scenario, _quitInput, _observeController, step, told) => {
  const valid = told !== null && typeof told === 'object' && typeof told.origin === 'string' &&
    told.origin.startsWith('https://') && typeof told.host === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/u.test(told.host) &&
    Number.isInteger(told.port) && told.port > 0 && told.port < 65536 && typeof told.url === 'string' &&
    told.url.startsWith('http://');
  if (!valid) throw new Error(`The providers session did not tell ${step} its documents, stand-in and checked URL`);
  const group = 'provider-nodes';
  const dot = ' \u00b7 ';
  const invoke = (command, args = {}) =>
    page.evaluate(([command, args]) => window.__TAURI_INTERNALS__.invoke(command, args), [command, args]);
  const engine = async () => {
    const value = await invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    return value;
  };
  const off = value => value.snapshot.state.state === 'off' && value.snapshot.desired_mode === 'off';
  const running = value => value.snapshot.state.state === 'local_proxy_active' && value.snapshot.desired_mode === 'local_proxy' &&
    value.snapshot.state.runtime.ready === true;
  const sameRuntime = (first, second) => first.snapshot.generation === second.snapshot.generation &&
    JSON.stringify(first.snapshot.state.runtime) === JSON.stringify(second.snapshot.state.runtime);
  // What the Providers page shows once nothing is in progress and every
  // wanted row text has the wanted beginning; otherwise false.
  const rowsWhen = want => {
    const sections = [...document.querySelectorAll('.providers-layout .provider-section')];
    if (sections.length !== 2) return false;
    const read = section => [...section.querySelectorAll('article.provider-row')].map(row => ({
      empty: row.classList.contains('empty-state'), label: row.querySelector('.label')?.textContent ?? null,
      name: row.querySelector('h3')?.textContent ?? null, text: row.querySelector('.muted')?.textContent ?? null,
      error: row.querySelector('.error')?.textContent ?? null,
      buttons: [...row.querySelectorAll('.row-actions button')].map(button => ({ text: button.textContent, disabled: button.disabled })),
    }));
    const shown = { proxies: read(sections[0]), rules: read(sections[1]),
      toolbar: [...document.querySelectorAll('.providers-layout .toolbar-actions button[data-action]')]
        .map(button => ({ action: button.dataset.action, text: button.textContent, disabled: button.disabled })) };
    const busy = [...shown.proxies, ...shown.rules].some(row => row.buttons.some(button => ['Checking', 'Updating'].includes(button.text))) ||
      shown.toolbar.some(button => ['Checking\u2026', 'Updating\u2026'].includes(button.text));
    const matched = want.every(({ section, name, prefix }) => shown[section].some(row => row.name === name && row.text?.startsWith(prefix)));
    return !busy && matched ? shown : false;
  };
  const shownWhen = (want, name) => observeNative(page, rowsWhen, want, { name, timeoutMs: 60000 });
  const openProviders = async () => {
    await page.locator('#nav button[data-page="providers"]').click();
    await page.locator('.providers-layout').waitFor();
  };
  // The rows the Providers page logged, newest first.
  const logged = async () => {
    await page.locator('#nav button[data-page="logs"]').click();
    await page.locator('.log-stream').waitFor();
    return page.evaluate(() => [...document.querySelectorAll('.log-stream article.log-line')]
      .filter(row => row.querySelector('span')?.textContent === 'provider')
      .map(row => ({ level: row.querySelector('b')?.textContent ?? null, message: row.querySelector('p')?.firstChild?.textContent.trim() ?? null })));
  };
  const expectLogged = async (expected, label) => {
    const rows = await logged();
    if (JSON.stringify(rows.slice(0, expected.length)) !== JSON.stringify(expected)) {
      throw new Error(`The Providers page did not log ${label}: ${JSON.stringify(rows)}`);
    }
    return rows;
  };
  const health = (snapshot, name) => snapshot.proxy_providers.find(provider => provider.name === name)?.extra?.health ?? null;
  const reachable = count => `Proxies: 1${dot}${count}/1 reachable${dot}Updated: `;

  const steps = {
    'providers-import': async () => {
      await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
      const before = await page.evaluate(async () => {
        const invoke = window.__TAURI_INTERNALS__.invoke;
        return { boot: await invoke('boot_payload'), engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
      });
      if (before.boot.product.operating_system !== 'windows' || before.engine.unavailable_reason !== null || !off(before.engine) ||
          before.engine.capabilities.local_proxy !== true || before.profiles.invalid_profiles.length !== 0 ||
          before.profiles.profiles.length !== 1 || before.profiles.profiles[0].active !== true) {
        throw new Error(`The providers case did not begin with the stopped LocalProxy profile alone: ${JSON.stringify(before)}`);
      }
      const kept = before.profiles.profiles[0].id;
      const text = [
        'proxy-providers:', '  checked:', '    type: inline', '    payload:', '      - name: stand-in', '        type: http',
        `        server: ${JSON.stringify(told.host)}`, `        port: ${told.port}`, '    health-check:', '      enable: true',
        `      url: ${JSON.stringify(told.url)}`, '      interval: 600', '      timeout: 5000',
        '  downloaded:', '    type: http', `    url: ${JSON.stringify(`${told.origin}/nodes.yaml`)}`, '    interval: 3600',
        'rule-providers:', '  listed:', '    type: http', '    behavior: domain', `    url: ${JSON.stringify(`${told.origin}/rules.yaml`)}`,
        '    interval: 86400',
        'proxy-groups:', `  - name: ${group}`, '    type: select', '    use:', '      - checked', '      - downloaded',
        'rules:', `  - RULE-SET,listed,${group}`, '  - MATCH,DIRECT', '',
      ].join('\n');
      await page.locator('#nav button[data-page="profiles"]').click();
      await page.locator('[data-profile-url]').fill(text);
      await page.locator('[data-action="import-profile"]').click();
      // A profile imported from text is selected at once, after its two
      // documents are downloaded.
      const selected = await observeNative(page, async (kept) => {
        const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
        if (value.invalid_profiles.length || value.profiles.length > 2 || !value.profiles.some(profile => profile.id === kept)) {
          throw new Error('GUI import produced unexpected profiles');
        }
        const active = value.profiles.filter(profile => profile.active);
        return value.profiles.length === 2 && active.length === 1 && active[0].id !== kept ? value : false;
      }, kept, { name: 'providers profile import', timeoutMs: 75000 });
      const credentials = page.getByRole('dialog', { name: 'Profile credentials', exact: true });
      await credentials.getByText('This profile references no credentials.', { exact: true }).waitFor({ timeout: 15000 });
      await credentials.locator('button[data-glass-dismiss]').click();
      await credentials.waitFor({ state: 'hidden' });
      const id = selected.profiles.find(profile => profile.id !== kept).id;
      const imported = await invoke('read_profile_text', { id });
      const body = JSON.parse(imported.body);
      const catalog = body.providers ?? {};
      const node = tag => (body.outbounds ?? []).find(outbound => outbound.tag === tag) ?? null;
      const members = name => catalog.proxies?.find(provider => provider.name === name)?.members ?? [];
      const standIn = members('checked');
      const unresolved = members('downloaded');
      const check = catalog.proxies?.find(provider => provider.name === 'checked')?.health_check ?? null;
      const stored = standIn.length === 1 && standIn[0].name === 'stand-in' && unresolved.length === 1 &&
        unresolved[0].name === 'unresolved' && node(standIn[0].tag)?.type === 'http' && node(standIn[0].tag).server === told.host &&
        node(standIn[0].tag).server_port === told.port && node(unresolved[0].tag)?.server === 'provider-node.invalid' &&
        node(unresolved[0].tag).server_port === 8080 && check?.url === told.url && check.timeout_ms === 5000 &&
        check.interval_seconds === 600 && JSON.stringify(catalog.rules?.map(provider => provider.name)) === '["listed"]';
      if (!stored) throw new Error(`The providers profile was not stored as declared: ${JSON.stringify(imported)}`);
      const listed = await invoke('providers_snapshot');
      if (!Array.isArray(listed?.proxy_providers) || !Array.isArray(listed.rule_providers)) {
        throw new Error(`The providers snapshot has another shape: ${JSON.stringify(listed)}`);
      }
      const entry = (list, name) => list.find(provider => provider.name === name) ?? null;
      const proxies = [entry(listed.proxy_providers, 'checked'), entry(listed.proxy_providers, 'downloaded')];
      const rule = entry(listed.rule_providers, 'listed');
      if (listed.proxy_providers.length !== 2 || listed.rule_providers.length !== 1 || proxies.includes(null) || rule === null ||
          proxies[0].vehicle_type !== 'Inline' || proxies[0].extra.updatable !== false || proxies[0].extra.health !== null ||
          JSON.stringify(proxies[0].proxies) !== '["stand-in"]' || proxies[1].vehicle_type !== 'HTTP' ||
          proxies[1].extra.updatable !== true || JSON.stringify(proxies[1].proxies) !== '["unresolved"]' ||
          rule.vehicle_type !== 'HTTP' || rule.behavior !== 'domain' || rule.extra.updatable !== true ||
          JSON.stringify(rule.rules) !== '["provider-check.example","rules.provider-check.example"]') {
        throw new Error(`The providers snapshot does not list the declared providers: ${JSON.stringify(listed)}`);
      }
      await openProviders();
      const shown = await shownWhen([
        { section: 'proxies', name: 'checked', prefix: `Proxies: 1${dot}Not tested${dot}Updated: ` },
        { section: 'proxies', name: 'downloaded', prefix: `Proxies: 1${dot}Not tested${dot}Updated: ` },
        { section: 'rules', name: 'listed', prefix: 'Rules: 2' },
      ], 'imported providers');
      const buttons = name => [...shown.proxies, ...shown.rules].find(row => row.name === name).buttons;
      // An inline provider has nothing to download; the others can update.
      if (JSON.stringify(buttons('checked')) !== '[{"text":"Update","disabled":true},{"text":"Health Check","disabled":false}]' ||
          JSON.stringify(buttons('downloaded')) !== '[{"text":"Update","disabled":false},{"text":"Health Check","disabled":false}]' ||
          JSON.stringify(buttons('listed')) !== '[{"text":"Update","disabled":false}]' ||
          shown.toolbar.some(button => button.action !== 'open-rules' && button.disabled)) {
        throw new Error(`The Providers page does not offer the providers' actions: ${JSON.stringify(shown)}`);
      }
      if (!off(await engine())) throw new Error('The providers import started the core');
      await page.screenshot({ path: 'providers-imported.png' });
      const snapshot = await page.locator('body').ariaSnapshot();
      return { before, kept, profile: id, selected, imported, listed, shown, snapshot,
        mutations: ['import-profile'], release_accepted: false };
    },

    'providers-offline': async () => {
      const before = await engine();
      if (!off(before)) throw new Error(`The offline providers step did not begin with the core off: ${JSON.stringify(before)}`);
      await openProviders();
      await page.locator('[data-provider-health="checked"]:enabled').click();
      // With the core off, the transient probe engine reaches the stand-in.
      const checked = await shownWhen([{ section: 'proxies', name: 'checked', prefix: reachable(1) }], 'offline health check');
      await page.locator('[data-rule-provider-update="listed"]:enabled').click();
      await shownWhen([{ section: 'rules', name: 'listed', prefix: 'Rules: 2' }], 'offline rule provider update');
      const listed = await invoke('providers_snapshot');
      const rule = listed.rule_providers.find(provider => provider.name === 'listed');
      if (health(listed, 'checked') !== '1/1 reachable' || rule?.extra.update_error !== null) {
        throw new Error(`The offline check and update were not recorded: ${JSON.stringify(listed)}`);
      }
      await openProviders();
      await page.screenshot({ path: 'providers-offline.png' });
      const snapshot = await page.locator('body').ariaSnapshot();
      const log = await expectLogged([
        { level: 'info', message: 'listed update completed' },
        { level: 'info', message: 'checked health check completed' },
      ], 'the offline check and update');
      const after = await engine();
      if (!off(after)) throw new Error('The offline check or update started the core');
      await page.locator('#nav button[data-page="general"]').click();
      await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).waitFor();
      return { before, checked, listed, log, snapshot, after,
        mutations: ['health-check:checked', 'update-rule-provider:listed'], release_accepted: false };
    },

    'providers-online': async () => {
      await page.locator('#nav button[data-page="general"]').click();
      await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).click();
      const active = await observeNative(page, async () => {
        const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
        if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
        const state = value.snapshot.state.state;
        if (state === 'local_proxy_active') {
          if (value.snapshot.desired_mode !== 'local_proxy' || value.snapshot.state.runtime.ready !== true ||
              value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
            throw new Error('LocalProxy activation did not carry the ready runtime identity');
          }
          return value;
        }
        if (!['off', 'local_proxy_starting'].includes(state)) throw new Error(`Unexpected start result: ${JSON.stringify(value)}`);
        return false;
      }, undefined, { name: 'LocalProxy start with the providers', timeoutMs: 30000 });
      await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
      // The product enables these controls only after its own controller snapshot.
      await page.locator('#nav button[data-page="proxies"]').click();
      await page.locator('button[data-mode="Rule"]:enabled').waitFor({ timeout: 15000 });
      const controller = await invoke('controller_snapshot');
      const offered = controller.proxies.groups.find(item => item.name === group);
      if (offered?.kind !== 'Selector' || offered.options?.length !== 2) {
        throw new Error(`The running core does not offer the providers' group: ${JSON.stringify(controller.proxies)}`);
      }
      await openProviders();
      await page.locator('[data-action="health-check-all"]:enabled').click();
      // Through the core: the stand-in answers, and the node that never
      // resolves fails.
      const checkedAll = await shownWhen([
        { section: 'proxies', name: 'checked', prefix: reachable(1) },
        { section: 'proxies', name: 'downloaded', prefix: reachable(0) },
      ], 'Health Check All through the core');
      const beforeUpdate = await engine();
      if (!sameRuntime(active, beforeUpdate) || !running(beforeUpdate)) throw new Error('The health checks replaced the core');
      await page.locator('[data-action="update-all-providers"]:enabled').click();
      // The documents did not change, so the core and the providers' health stay.
      const updatedAll = await shownWhen([
        { section: 'proxies', name: 'checked', prefix: reachable(1) },
        { section: 'proxies', name: 'downloaded', prefix: reachable(0) },
        { section: 'rules', name: 'listed', prefix: 'Rules: 2' },
      ], 'Update All of the unchanged documents');
      const after = await engine();
      const listed = await invoke('providers_snapshot');
      if (!running(after) || !sameRuntime(active, after) || health(listed, 'checked') !== '1/1 reachable' ||
          health(listed, 'downloaded') !== '0/1 reachable' ||
          [...listed.proxy_providers, ...listed.rule_providers].some(provider => provider.extra.update_error !== null)) {
        throw new Error(`Update All of unchanged documents did not keep the runtime and the health: ${JSON.stringify({ after, listed })}`);
      }
      await page.screenshot({ path: 'providers-online.png' });
      const snapshot = await page.locator('body').ariaSnapshot();
      const log = await expectLogged([
        { level: 'info', message: 'Update All: 2/2 succeeded' },
        { level: 'error', message: 'Health Check All: 1/2 succeeded, 1 failed (downloaded: 0/1 reachable)' },
      ], 'Health Check All and Update All');
      await page.locator('#nav button[data-page="general"]').click();
      await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
      return { active, controller, checkedAll, updatedAll, after, listed, log, snapshot,
        mutations: ['toggle-core', 'health-check-all', 'update-all-providers'], release_accepted: false };
    },

    'providers-unreachable': async () => {
      const before = await engine();
      if (!running(before)) throw new Error(`The unreachable check did not begin with the core on: ${JSON.stringify(before)}`);
      await openProviders();
      await page.locator('[data-provider-health="checked"]:enabled').click();
      const failed = await shownWhen([{ section: 'proxies', name: 'checked', prefix: reachable(0) }], 'health check of the stopped stand-in');
      const after = await engine();
      const listed = await invoke('providers_snapshot');
      if (!running(after) || !sameRuntime(before, after) || health(listed, 'checked') !== '0/1 reachable') {
        throw new Error(`The failed check was not recorded beside the running core: ${JSON.stringify({ after, listed })}`);
      }
      await page.screenshot({ path: 'providers-unreachable.png' });
      const snapshot = await page.locator('body').ariaSnapshot();
      const log = await expectLogged([
        { level: 'error', message: 'checked health check failed: checked: 0/1 reachable' },
      ], 'the failed check');
      await page.locator('#nav button[data-page="general"]').click();
      await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
      return { before, failed, after, listed, log, snapshot, mutations: ['health-check:checked'], release_accepted: false };
    },

    'providers-delete': async () => {
      const before = await page.evaluate(async () => {
        const invoke = window.__TAURI_INTERNALS__.invoke;
        return { engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
      });
      const active = before.profiles.profiles.filter(profile => profile.active);
      if (before.engine.unavailable_reason !== null || !off(before.engine) || before.profiles.invalid_profiles.length !== 0 ||
          before.profiles.profiles.length !== 2 || active.length !== 1) {
        throw new Error(`The stopped providers case did not keep its profile selected: ${JSON.stringify(before)}`);
      }
      const id = active[0].id;
      const kept = before.profiles.profiles.find(profile => profile.id !== id).id;
      await page.locator('#nav button[data-page="profiles"]').click();
      await page.locator(`[data-profile-card="${kept}"] h3`).click();
      const reselected = await observeNative(page, async ({ id, kept }) => {
        const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
        if (value.invalid_profiles.length || value.profiles.length !== 2 || !value.profiles.some(profile => profile.id === id)) {
          throw new Error('Selecting a profile changed the profiles');
        }
        const active = value.profiles.filter(profile => profile.active);
        return active.length === 1 && active[0].id === kept ? value : false;
      }, { id, kept }, { name: 'LocalProxy profile selection', timeoutMs: 15000 });
      await page.locator(`[data-profile-card="${id}"]`).click({ button: 'right' });
      await page.locator(`[data-profile-menu="delete"][data-profile-id="${id}"]:enabled`).click();
      const dialog = page.getByRole('dialog', { name: 'Delete profile', exact: true });
      await dialog.locator(`[data-glass-delete-confirm="${id}"]`).click();
      await dialog.waitFor({ state: 'hidden' });
      const deleted = await observeNative(page, async ({ id, kept }) => {
        const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
        if (value.invalid_profiles.length || value.profiles.length > 2) throw new Error('Profile deletion left unexpected profiles');
        if (value.profiles.length === 2 && value.profiles.some(profile => profile.id === id)) return false;
        if (value.profiles.length !== 1 || value.profiles[0].id !== kept || value.profiles[0].active !== true) {
          throw new Error(`Deleting the providers profile changed the LocalProxy profile: ${JSON.stringify(value)}`);
        }
        return value;
      }, { id, kept }, { name: 'profile deletion', timeoutMs: 15000 });
      await page.locator(`[data-profile-card="${id}"]`).waitFor({ state: 'detached' });
      // The kept profile has no providers to show.
      const listed = await invoke('providers_snapshot');
      if (listed.proxy_providers.length !== 0 || listed.rule_providers.length !== 0) {
        throw new Error(`The kept profile lists providers: ${JSON.stringify(listed)}`);
      }
      await openProviders();
      await page.locator('.provider-section .empty-state h3').filter({ hasText: 'No proxy providers loaded' }).waitFor();
      await page.locator('.provider-section .empty-state h3').filter({ hasText: 'No rule providers loaded' }).waitFor();
      const after = await engine();
      if (!off(after)) throw new Error('Deleting the providers profile changed the stopped core');
      await page.screenshot({ path: 'providers-deleted.png' });
      const snapshot = await page.locator('body').ariaSnapshot();
      await page.locator('#nav button[data-page="settings"]').click();
      await page.locator('[data-action="quit-app"]').waitFor();
      return { before, kept, profile: id, reselected, deleted, listed, after, snapshot,
        mutations: ['select-profile', 'delete-profile'], release_accepted: false };
    },
  };
  if (!Object.hasOwn(steps, step)) throw new Error(`Unknown providers step ${step}`);
  return steps[step]();
})
