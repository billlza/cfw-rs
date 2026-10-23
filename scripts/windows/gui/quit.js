// A regular CLI click automatically snapshots the page after input. Quit can
// close the final WebView2 page before that snapshot. run-code preserves the
// actual awaited click without requesting a snapshot of an exited application.
// The native controller still owns the process-exit, code and restoration checks.
(async page => {
  await page.locator('[data-action="quit-app"]').click({ timeout: 5000 });
  return { quit_click_completed: true, native_exit_verified: false };
})
