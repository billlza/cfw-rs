// With the core off, point the imported profile at the document its provider
// changed and update it. The profile's Settings rename it and take the new
// URL; opened again, they show what was saved. Update in the context menu then
// downloads the new document: "first" stays, "second" is gone and "third" is
// new, each with its password in Windows protected storage. All mutations go
// through visible controls; IPC only observes.
(async (page, observeNative, _scenario, _quitInput, _observeController, _step, origin) => {
  if (typeof origin !== 'string' || !origin.startsWith('https://')) throw new Error('The subscription session has no document origin');
  const selector = 'cfw-proxy-selector';
  const first = `${origin}/first.yaml`;
  const second = `${origin}/second.yaml`;
  const name = 'Subscription check';
  const nodes = [
    { tag: 'first', server: 'first.example.com', server_port: 8388 },
    { tag: 'third', server: 'third.example.com', server_port: 8389 },
  ];
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const profiles = await invoke('profiles_snapshot');
    const id = profiles.profiles.find(profile => profile.active)?.id ?? null;
    return { engine: await invoke('engine_snapshot'), profiles, saved: id === null ? null : await invoke('read_profile_text', { id }) };
  });
  if (before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'off' ||
      before.engine.snapshot.desired_mode !== 'off' || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 2 || before.profiles.profiles.filter(profile => profile.active).length !== 1 ||
      before.saved?.source_url !== first) {
    throw new Error(`The stopped subscription case did not keep its imported profile selected: ${JSON.stringify(before)}`);
  }
  const id = before.saved.id;
  const card = page.locator(`[data-profile-card="${id}"]`);
  const update = page.locator(`[data-profile-menu="update"][data-profile-id="${id}"]:enabled`);
  // The menu reads the profile's URL when it opens. Settings, which shows that
  // URL and saves it back, is enabled only once the URL is known.
  const openSettings = async () => {
    await card.click({ button: 'right' });
    await page.locator(`[data-profile-menu="settings"][data-profile-id="${id}"]:enabled`).click();
    const dialog = page.getByRole('dialog', { name: 'Edit profile information', exact: true });
    await dialog.waitFor();
    const shown = await page.evaluate(() => ({ name: document.querySelector('[data-glass-settings-name]').value,
      url: document.querySelector('[data-glass-settings-url]').value }));
    return { dialog, shown };
  };
  await page.locator('#nav button[data-page="profiles"]').click();
  const opened = await openSettings();
  if (opened.shown.url !== first || opened.shown.name !== before.saved.name) {
    throw new Error(`The profile's Settings did not show its name and URL: ${JSON.stringify(opened.shown)}`);
  }
  await opened.dialog.locator('[data-glass-settings-name]').fill(name);
  await opened.dialog.locator('[data-glass-settings-url]').fill(second);
  await opened.dialog.locator(`[data-glass-settings-confirm="${id}"]`).click();
  await opened.dialog.waitFor({ state: 'hidden' });
  const renamed = await observeNative(page, async ({ id, name, second }) => {
    const value = await window.__TAURI_INTERNALS__.invoke('read_profile_text', { id });
    return value.name === name && value.source_url === second ? value : false;
  }, { id, name, second }, { name: 'profile settings', timeoutMs: 15000 });
  // The name and the URL live beside the document, which keeps its digest.
  if (renamed.body !== before.saved.body || renamed.digest !== before.saved.digest) {
    throw new Error('Saving the profile settings changed the profile document');
  }
  await page.locator(`[data-profile-card="${id}"] h3`).filter({ hasText: name }).waitFor();
  const reopened = await openSettings();
  if (reopened.shown.url !== second || reopened.shown.name !== name) {
    throw new Error(`The profile's Settings, opened again, did not show what was saved: ${JSON.stringify(reopened.shown)}`);
  }
  await reopened.dialog.locator('button[data-glass-dismiss]').click();
  await reopened.dialog.waitFor({ state: 'hidden' });
  await card.click({ button: 'right' });
  await update.click();
  // The download takes part of the wait.
  const updated = await observeNative(page, async ({ id, digest }) => {
    const value = await window.__TAURI_INTERNALS__.invoke('read_profile_text', { id });
    return value.digest !== digest ? value : false;
  }, { id, digest: before.saved.digest }, { name: 'subscription update', timeoutMs: 75000 });
  const stored = await page.evaluate(async (id) => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { requirements: await invoke('profile_credential_requirements', { id }), presence: await invoke('profile_credential_presence', { id }),
      engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
  }, id);
  const { requirements, presence, engine, profiles } = stored;
  const outbounds = JSON.parse(updated.body).outbounds ?? [];
  const converted = outbounds.length === nodes.length && nodes.every((node, index) => {
    const outbound = outbounds[index];
    return outbound.type === 'shadowsocks' && outbound.tag === node.tag && outbound.server === node.server &&
      outbound.server_port === node.server_port && outbound.method === 'aes-256-gcm' && !('password' in outbound) &&
      outbound.credential_ref?.kind === 'shadowsocks_password';
  });
  // The vault answers in the canonical order of the references, sorted by id.
  const referenced = outbounds.map(outbound => outbound.credential_ref?.id).sort();
  if (updated.name !== name || updated.source_url !== second || !converted || updated.body.includes('subscription-check') ||
      JSON.stringify(requirements.map(reference => reference.id).sort()) !== JSON.stringify(referenced) ||
      requirements.some(reference => reference.kind !== 'shadowsocks_password') ||
      presence.length !== nodes.length || presence.some((entry, index) => entry.present !== true || entry.reference.id !== requirements[index].id) ||
      updated.app_selector?.tag !== selector || JSON.stringify(updated.app_selector.members) !== '["first","third"]' ||
      updated.app_selector.default !== 'first' || Object.keys(updated.proxy_selections).length !== 0) {
    throw new Error(`The update did not store the changed document with vault passwords: ${JSON.stringify({ updated, stored })}`);
  }
  if (engine.unavailable_reason !== null || engine.snapshot.state.state !== 'off' || engine.snapshot.desired_mode !== 'off' ||
      profiles.profiles.length !== 2 || profiles.profiles.find(profile => profile.active)?.id !== id) {
    throw new Error(`The update changed the stopped core or the profiles: ${JSON.stringify({ engine, profiles })}`);
  }
  await page.screenshot({ path: 'subscription-updated.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, opened: opened.shown, renamed, reopened: reopened.shown, updated, requirements, presence, snapshot,
    mutations: ['profile-settings', 'update-profile'], release_accepted: false };
})
