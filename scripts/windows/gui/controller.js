// Observe the actual controller for any UI-started Windows network mode.
(async (page, active, prefix) => {
  if (!['local-proxy', 'system-proxy', 'tunnel'].includes(prefix)) throw new Error('Unknown controller scenario');
  await page.locator('#nav button[data-page="proxies"]').click();
  await page.locator('button[data-mode="Rule"]:enabled').waitFor({ timeout: 15000 });
  const controller = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { snapshot: await invoke('controller_snapshot'), version: await invoke('controller_version'),
      rules: await invoke('rules_snapshot'), engine: await invoke('engine_snapshot') };
  });
  const checks = {
    exact_engine_snapshot: JSON.stringify(controller.engine.snapshot) === JSON.stringify(active.snapshot),
    reported_version: typeof controller.version.version === 'string' && controller.version.version.trim().length > 0,
    // The pinned engine's clashmode.Manager starts a fresh cache in "Rule".
    // No control in this scenario changes route mode.
    initial_rule_mode: controller.snapshot.config.mode === 'Rule',
    proxy_groups: Array.isArray(controller.snapshot.proxies.groups),
    imported_direct_node: controller.snapshot.proxies.proxies.some(node => node.name === 'direct'),
    connections: Array.isArray(controller.snapshot.connections.connections),
    rules: Array.isArray(controller.rules.rules),
  };
  if (!Object.values(checks).every(value => value === true)) {
    throw new Error(`The GUI controller did not describe the active imported direct profile: ${JSON.stringify({
      checks, observed_mode: controller.snapshot.config.mode, observed_version: controller.version.version,
    })}`);
  }
  await page.screenshot({ path: `${prefix}-controller.png` });
  const controllerSnapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('.core-version-link').filter({ hasText: controller.version.version }).waitFor({ timeout: 15000 });
  return { controller, controllerSnapshot, controller_checks: checks, controller_verified: true };
})
