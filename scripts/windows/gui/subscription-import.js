// Import a subscription by its URL beside the LocalProxy session's profile, as
// a user pastes it on the Profiles page. GitHub serves the document from the
// commit under test over public HTTPS; the product downloads it with the
// Windows trust store and converts its two Shadowsocks nodes. Their passwords
// go only to Windows protected storage, which the credentials dialog and the
// vault confirm, and the core then starts the profile, which it can do only
// with the stored passwords. Nothing dials the nodes. Before the import the
// vault holds no unused credentials. All mutations go through visible
// controls; IPC only observes.
(async (page, observeNative, _scenario, _quitInput, _observeController, _step, origin) => {
  if (typeof origin !== 'string' || !origin.startsWith('https://')) throw new Error('The subscription session has no document origin');
  const selector = 'cfw-proxy-selector';
  const url = `${origin}/first.yaml`;
  const nodes = [
    { tag: 'first', server: 'first.example.com', server_port: 8388 },
    { tag: 'second', server: 'second.example.com', server_port: 8388 },
  ];
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { boot: await invoke('boot_payload'), engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
  });
  if (before.boot.product.operating_system !== 'windows' || before.engine.unavailable_reason !== null ||
      before.engine.snapshot.state.state !== 'off' || before.engine.snapshot.desired_mode !== 'off' ||
      before.engine.capabilities.local_proxy !== true || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 1 || before.profiles.profiles[0].active !== true) {
    throw new Error(`The subscription case did not begin with the stopped LocalProxy profile alone: ${JSON.stringify(before)}`);
  }
  const kept = before.profiles.profiles[0].id;
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('[data-action="preview-credential-gc"]:enabled').click();
  // A refusal opens another dialog; whatever opens is read and shown.
  const review = await observeNative(page, () => {
    const dialog = document.querySelector('.glass-dialog[role="dialog"]');
    return dialog ? { label: dialog.getAttribute('aria-label'), copy: dialog.querySelector('.glass-dialog-copy')?.textContent ?? null,
      items: dialog.querySelectorAll('.glass-list li').length, confirm: dialog.querySelector('[data-glass-credential-gc-confirm]') !== null } : false;
  }, undefined, { name: 'credential cleanup review', timeoutMs: 15000 });
  if (review.label !== 'Credential cleanup' || review.copy !== 'The credential vault has no unused references.' ||
      review.items !== 0 || review.confirm) {
    throw new Error(`The vault did not begin without unused credentials: ${JSON.stringify(review)}`);
  }
  const cleanup = page.getByRole('dialog', { name: 'Credential cleanup', exact: true });
  await cleanup.locator('[data-glass-credential-gc-cancel]').click();
  await cleanup.waitFor({ state: 'hidden' });
  await page.locator('#nav button[data-page="profiles"]').click();
  await page.locator('[data-profile-url]').fill(url);
  await page.locator('[data-action="import-profile"]').click();
  // A subscription is imported selected; the download takes part of the wait.
  const selected = await observeNative(page, async (kept) => {
    const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
    if (value.invalid_profiles.length || value.profiles.length > 2 || !value.profiles.some(profile => profile.id === kept)) {
      throw new Error('GUI import produced unexpected profiles');
    }
    const active = value.profiles.filter(profile => profile.active);
    return value.profiles.length === 2 && active.length === 1 && active[0].id !== kept ? value : false;
  }, kept, { name: 'subscription import', timeoutMs: 75000 });
  const id = selected.profiles.find(profile => profile.id !== kept).id;
  if (selected.profiles.find(profile => profile.id === id).source_kind !== 'subscription') {
    throw new Error(`The imported profile is not listed as a subscription: ${JSON.stringify(selected)}`);
  }
  const credentials = page.getByRole('dialog', { name: 'Profile credentials', exact: true });
  await credentials.getByText('All 2 credential reference(s) are already present in the vault.', { exact: true }).waitFor({ timeout: 15000 });
  await credentials.locator('button[data-glass-dismiss]').click();
  await credentials.waitFor({ state: 'hidden' });
  const stored = await page.evaluate(async (id) => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { text: await invoke('read_profile_text', { id }), requirements: await invoke('profile_credential_requirements', { id }),
      presence: await invoke('profile_credential_presence', { id }) };
  }, id);
  const { text, requirements, presence } = stored;
  const body = JSON.parse(text.body);
  const outbounds = body.outbounds ?? [];
  const converted = outbounds.length === nodes.length && nodes.every((node, index) => {
    const outbound = outbounds[index];
    return outbound.type === 'shadowsocks' && outbound.tag === node.tag && outbound.server === node.server &&
      outbound.server_port === node.server_port && outbound.method === 'aes-256-gcm' && !('password' in outbound) &&
      outbound.credential_ref?.kind === 'shadowsocks_password';
  });
  // The vault answers in the canonical order of the references, sorted by id.
  const referenced = outbounds.map(outbound => outbound.credential_ref?.id).sort();
  // The passwords stay in the vault: neither the stored profile nor what the
  // page can read carries them.
  if (text.source_url !== url || !converted || text.body.includes('subscription-check') ||
      JSON.stringify(requirements.map(reference => reference.id).sort()) !== JSON.stringify(referenced) ||
      requirements.some(reference => reference.kind !== 'shadowsocks_password') ||
      presence.length !== nodes.length || presence.some((entry, index) => entry.present !== true || entry.reference.id !== requirements[index].id) ||
      text.app_selector?.tag !== selector || JSON.stringify(text.app_selector.members) !== '["first","second"]' ||
      text.app_selector.default !== 'first' || Object.keys(text.proxy_selections).length !== 0) {
    throw new Error(`The subscription was not stored as two Shadowsocks nodes with vault passwords: ${JSON.stringify(stored)}`);
  }
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
  }, undefined, { name: 'LocalProxy start with the subscription', timeoutMs: 30000 });
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  // The product enables these controls only after its own controller snapshot.
  await page.locator('#nav button[data-page="proxies"]').click();
  await page.locator('button[data-mode="Rule"]:enabled').waitFor({ timeout: 15000 });
  const controller = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('controller_snapshot'));
  const group = controller.proxies.groups.find(item => item.name === selector);
  if (group?.kind !== 'Selector' || group.now !== 'first' || JSON.stringify(group.options) !== '["first","second"]' ||
      !nodes.every(node => controller.proxies.proxies.some(proxy => proxy.name === node.tag && proxy.kind === 'Shadowsocks'))) {
    throw new Error(`The running core does not carry the subscription's nodes: ${JSON.stringify(controller.proxies)}`);
  }
  await page.locator(`button.cfw-node-card.selected[data-group="${selector}"][data-node="first"]:enabled`).waitFor({ timeout: 15000 });
  await page.screenshot({ path: 'subscription-imported.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  return { before, review, kept, profile: id, selected, imported: text, requirements, presence, active, controller, snapshot,
    mutations: ['preview-credential-gc', 'import-profile', 'toggle-core'], release_accepted: false };
})
