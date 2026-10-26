// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the control API's pairing
// window: the window must fit its content (only the connection list may scroll, inside its box), the name must be labelled as self-reported, the executable path shown in full, no connection ticked and
// "Allow" disabled until one is; then the seeded target connection is ticked and allowed once the input lock
// passed. Anything wrong: Deny (the client then fails to pair, and the shell reports it).
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 10000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  // The window fits its content (fit_window): nothing scrolls, and no more than the content's own padding below.
  const fits = () => {
    const page = document.scrollingElement;
    const content = document.getElementById('app')?.getBoundingClientRect().height ?? 0;
    return content > 0 && page.scrollHeight <= page.clientHeight && window.innerHeight - content <= 2;
  };
  // With screenshots on (the driver sets 'pending'), wait here until it took one.
  const shot = async () => {
    if (window.smokeShot === 'pending') await waitFor(() => window.smokeShot === 'done', 30000);
  };
  const target = '91111111-2222-4333-8444-555555555555';
  const allow = await waitFor(() => document.querySelector('.pairing button.allow'));
  const deny = document.querySelector('.pairing button.deny');
  if (!allow || !deny) return;
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  const pairing = vm.pairings[0];
  const path = document.querySelector('.pairing .path')?.textContent;
  const ok =
    !!pairing &&
    document.querySelector('.pairing .name')?.textContent === 'smoke-client' &&
    pairing.name === 'smoke-client' &&
    path === pairing.executable &&
    // An absolute path: `/…` on macOS, `C:\…` on Windows.
    /^(\/|[A-Za-z]:\\)/.test(path) &&
    allow.disabled &&
    ![...document.querySelectorAll('.pairing input[type=checkbox]')].some((c) => c.checked) &&
    !!(await waitFor(fits, 5000));
  await shot();
  const box = document.querySelector(`.pairing input[value="${target}"]`);
  if (!ok || !box) {
    deny.click();
    return;
  }
  await waitFor(() => !box.disabled, 5000);
  // Still disabled with nothing ticked once the lock passed.
  if (!allow.disabled) {
    deny.click();
    return;
  }
  box.click();
  await waitFor(() => !allow.disabled, 3000);
  allow.click();
})();
