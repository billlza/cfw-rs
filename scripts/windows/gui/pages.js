// Consumed by `playwright-cli run-code --filename`. All IPC below is the
// installed application's real read-only IPC; no renderer state is injected.
(async (page) => {
  // Product identity is delivered by boot_payload below. The shared page has
  // no #product-name element; wait for its actual navigation to be rendered.
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const backend = await page.evaluate(async () => {
    if (typeof window.__TAURI_INTERNALS__?.invoke !== 'function') {
      throw new Error('The page is not the native Tauri webview');
    }
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return {
      boot: await invoke('boot_payload'),
      engine: await invoke('engine_snapshot'),
      platform: await invoke('current_platform_design'),
    };
  });
  if (backend.boot.product.name !== 'Clash for Windows' ||
      backend.boot.product.operating_system !== 'windows' ||
      backend.engine.unavailable_reason !== null ||
      backend.engine.capabilities.local_proxy !== true ||
      backend.engine.capabilities.system_proxy !== true ||
      backend.engine.snapshot.state.state !== 'off') {
    throw new Error(`Installed desktop bootstrap did not admit the runtime: ${JSON.stringify(backend)}`);
  }
  const expected = ['general', 'proxies', 'profiles', 'providers', 'logs', 'connections', 'rules', 'settings', 'feedback'];
  const actual = await page.locator('#nav button[data-page]').evaluateAll(nodes => nodes.map(node => node.dataset.page));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Shared page inventory differs: ${JSON.stringify(actual)}`);
  }
  const pages = [];
  for (const id of expected) {
    await page.locator(`#nav button[data-page="${id}"]`).click();
    await page.locator(`#nav button[data-page="${id}"][aria-current="page"]`).waitFor();
    const heading = await page.locator('#page-title').innerText();
    const content = await page.locator('#page').innerText();
    if (!heading.trim() || !content.trim()) throw new Error(`Empty shared page: ${id}`);
    if (id === 'feedback' && !content.includes(backend.platform.startup_strategy)) {
      throw new Error('Windows startup architecture is missing from the Feedback page');
    }
    await page.screenshot({ path: `${id}.png` });
    pages.push({ id, heading, content, snapshot: await page.locator('body').ariaSnapshot() });
  }
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('[data-action="quit-app"]').waitFor();
  return { backend, pages, native_gui_exercised: true, network_mode_exercised: false, release_accepted: false };
})
