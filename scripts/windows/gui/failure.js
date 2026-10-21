// Collect the actual failed window and read-only IPC result. Every unavailable
// observation is recorded explicitly; this file never turns validation green.
(async (page) => {
  const result = { url: page.url(), validation_passed: false };
  try {
    result.window = await page.locator('body').ariaSnapshot();
    await page.screenshot({ path: 'failure.png' });
  } catch (error) { result.window_error = String(error); }
  await Promise.all([
    ['engine', 'engine_snapshot'],
    ['settings', 'read_settings_snapshot'],
  ].map(async ([name, command]) => {
    try {
      result[name] = await page.evaluate(async (readCommand) => {
        let timer;
        try {
          return await Promise.race([
            window.__TAURI_INTERNALS__.invoke(readCommand).then(
              value => ({ status: 'observed', value }),
              error => ({ status: 'rejected', error: String(error) }),
            ),
            new Promise(resolve => { timer = setTimeout(() => resolve({ status: 'deadline_exceeded' }), 3000); }),
          ]);
        } finally { clearTimeout(timer); }
      }, command);
    } catch (error) { result[`${name}_error`] = String(error); }
  }));
  try {
    await page.locator('#nav button[data-page="logs"]').click({ timeout: 2000 });
    result.logs = await page.locator('#page').innerText();
  } catch (error) { result.logs_error = String(error); }
  return result;
})
