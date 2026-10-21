// Private real-browser fixture for the CLI's last-page-close response. Run only
// in a disposable blank session, then exercise either CLI click or gui/quit.js.
// This regression never substitutes for the installed product's native exit.
(async page => {
  if (page.url() !== 'about:blank') throw new Error('Quit regression requires a private blank page');
  const pending = page.waitForEvent('popup', { timeout: 5000 });
  await page.evaluate(() => window.open('about:blank', 'cfw-quit-regression'));
  const popup = await pending;
  await popup.setContent('<button data-action="quit-app" onclick="setTimeout(() => window.close(), 100)">Quit</button>');
  await page.close();
  return { private_fixture: true, product_exercised: false };
})
