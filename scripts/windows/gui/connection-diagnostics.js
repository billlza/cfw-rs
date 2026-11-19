// Run the connection diagnostics of the Connections page on the UI-started
// LocalProxy core, each check through its visible control, and read what the
// page shows. The routed checks must pass through the core: its traffic totals
// grow while they run. Cloudflare's trace, HTTP and STUN answers are required,
// as the other installed GUI checks already rely on Cloudflare; the other
// providers' answers (ipify, the three services, bash.ws) are recorded.
// Addresses are read while shown and hidden again before any page capture,
// so the receipt keeps only their families.
(async (page, observeNative) => {
  const dot = ' · ';
  const engineAndTotals = async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { engine: await invoke('engine_snapshot'), controller: await invoke('controller_snapshot') };
  };
  const before = await page.evaluate(engineAndTotals);
  const totals = value => value.controller.connections;
  if (before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'local_proxy_active' ||
      before.engine.snapshot.desired_mode !== 'local_proxy' || before.engine.snapshot.state.runtime.ready !== true ||
      !Number.isSafeInteger(totals(before).download) || !Number.isSafeInteger(totals(before).upload)) {
    throw new Error(`Connection diagnostics did not begin on the verified LocalProxy core: ${JSON.stringify(before.engine)}`);
  }
  await page.locator('#nav button[data-page="connections"]').click();
  await page.locator('[data-action="connections-diagnostics"]').click();
  await page.locator('[data-action="connections-diagnostics"][aria-pressed="true"]').waitFor();
  await page.locator('[data-diagnostics-root][aria-busy="false"]').waitFor();
  await page.locator('[data-action="diagnostic-hide"]').filter({ hasText: 'Show IP addresses' }).click();
  await page.locator('[data-action="diagnostic-hide"]').filter({ hasText: 'Hide IP addresses' }).waitFor();
  // One reading of the rendered page; false until the named check has ended.
  const rendered = check => {
    const root = document.querySelector('[data-diagnostics-root]');
    if (!root || root.getAttribute('aria-busy') !== 'false') return false;
    const text = node => node ? node.textContent.trim() : null;
    const strong = node => text(node.querySelector(':scope > strong'));
    const plain = node => text(node.querySelector(':scope > span:not(.diagnostic-attention):not(.diagnostic-muted)'));
    const failure = node => text(node.querySelector(':scope > .diagnostic-attention, :scope > .diagnostic-muted'));
    const section = action => root.querySelector(`[data-action="${action}"]`).closest('.diagnostic-section');
    const udp = section('diagnostic-udp');
    const dns = section('diagnostic-dns');
    const reading = {
      alert: text(root.querySelector('[role="alert"]')),
      route: text(root.querySelector(':scope > small')),
      egress: [...root.querySelectorAll('.diagnostic-egress')].map(node => ({
        label: text(node.querySelector(':scope > span')), ip: strong(node), failure: failure(node) })),
      families: [...root.querySelectorAll('.diagnostic-families > div')].map(node => ({
        family: text(node.querySelector(':scope > b')), ip: plain(node), failure: failure(node) })),
      services: [...root.querySelectorAll('.diagnostic-service')].map(node => {
        const [identity, response, exit] = node.children;
        const observed = response.tagName === 'DIV';
        return { name: text(identity.querySelector('b')), host: text(identity.querySelector('small')),
          verdict: observed ? text(response.querySelector('span')) : null,
          http: observed ? text(response.querySelector('small')) : null, failure: observed ? null : text(response),
          exit_ip: plain(exit), exit_failure: failure(exit) };
      }),
      udp: { addresses: strong(udp), messages: [...udp.querySelectorAll(':scope > p')].slice(1).map(text) },
      dns: { resolvers: [...dns.querySelectorAll('.diagnostic-facts > div > dt')].map(text), lookups: text(dns.querySelector(':scope > small')) },
    };
    const ended = { connectivity: reading.route !== null, udp: reading.udp.addresses !== null || reading.udp.messages.length > 0,
      dns: reading.dns.lookups !== null }[check];
    return ended || reading.alert !== null ? reading : false;
  };
  const run = async (action, check, timeoutMs) => {
    await page.locator(`[data-action="${action}"]:enabled`).click();
    return observeNative(page, rendered, check, { name: `connection diagnostics: ${check}`, timeoutMs });
  };
  const family = ip => ip === null ? null : /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? 'ipv4' : /^[0-9a-f]*:[0-9a-f:]*$/i.test(ip) ? 'ipv6' : 'invalid';
  const address = ip => ['ipv4', 'ipv6'].includes(family(ip));
  const connectivity = await run('diagnostic-run', 'connectivity', 45000);
  const routed = await page.evaluate(engineAndTotals);
  const udp = await run('diagnostic-udp', 'udp', 20000);
  const dns = await run('diagnostic-dns', 'dns', 45000);
  const after = await page.evaluate(engineAndTotals);
  const [system, cfm] = connectivity.egress;
  const cloudflare = connectivity.services.find(service => service.host === 'www.cloudflare.com');
  const udpAddresses = udp.udp.addresses === null ? [] : udp.udp.addresses.split(dot);
  const checks = {
    no_error: connectivity.alert === null,
    route_through_core: connectivity.route?.startsWith(`Through the running CFM proxy${dot}`) === true,
    system_egress: system?.label === 'System request path' && address(system.ip),
    routed_egress: cfm?.label === 'CFM request path' && address(cfm.ip),
    families_listed: JSON.stringify(connectivity.families.map(item => item.family)) === '["IPv4","IPv6"]' &&
      connectivity.families.every(item => (item.ip === null) !== (item.failure === null)),
    services_listed: JSON.stringify(connectivity.services.map(service => service.host)) ===
      '["claude.ai","chatgpt.com","www.anthropic.com","www.cloudflare.com"]' &&
      connectivity.services.every(service => (service.http === null) !== (service.failure === null)),
    cloudflare_answered: new RegExp(`^HTTP \\d{3}${dot}\\d+ ms$`).test(cloudflare?.http ?? ''),
    // Only the routed checks use the core's listener in this session.
    routed_through_core: totals(routed).download > totals(before).download && totals(routed).upload > totals(before).upload,
    udp_answered: udp.alert === null && udpAddresses.length > 0 && udpAddresses.every(address),
    core_unchanged: JSON.stringify(after.engine.snapshot.state) === JSON.stringify(before.engine.snapshot.state) &&
      after.engine.snapshot.generation === before.engine.snapshot.generation,
  };
  if (!Object.values(checks).every(value => value === true)) {
    throw new Error(`Connection diagnostics did not observe the running core: ${JSON.stringify({ checks, connectivity, udp })}`);
  }
  // Recorded, not required: these depend on providers and the runner's network.
  const recorded = {
    families: connectivity.families.map(item => ({ family: item.family, observed: family(item.ip), failure: item.failure })),
    same_exit: system.ip === cfm.ip,
    services: connectivity.services.map(({ name, host, verdict, http, failure, exit_ip, exit_failure }) =>
      ({ name, host, verdict, http, failure, exit: family(exit_ip), exit_failure })),
    udp: { families: udpAddresses.map(family), messages: udp.udp.messages },
    dns: { error: dns.alert, resolver_families: dns.dns.resolvers.map(family), lookups: dns.dns.lookups },
    traffic: { download: totals(routed).download - totals(before).download, upload: totals(routed).upload - totals(before).upload },
  };
  await page.locator('[data-action="diagnostic-hide"]').filter({ hasText: 'Hide IP addresses' }).click();
  const hidden = await observeNative(page, separator => {
    const root = document.querySelector('[data-diagnostics-root]');
    const shown = [...root.querySelectorAll('.diagnostic-egress > strong, .diagnostic-families span, .diagnostic-service > div:last-child > span, .diagnostic-section > strong, .diagnostic-facts dt')]
      .filter(node => !node.matches('.diagnostic-attention, .diagnostic-muted'));
    return shown.length > 0 && shown.every(node => node.textContent.trim().split(separator).every(part => part === 'Hidden'))
      ? { hidden: shown.length } : false;
  }, dot, { name: 'hidden diagnostic addresses', timeoutMs: 5000 });
  await page.screenshot({ path: 'connection-diagnostics.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  return { before: { engine: before.engine }, after: { engine: after.engine }, checks, recorded, hidden, snapshot,
    connection_diagnostics_exercised: true, mutations: [], release_accepted: false };
})
