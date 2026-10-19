// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window,
// after control.js. The live system VPN list: the run's system VPNs come from the smoke's stand-in list, which
// the driver changes while this window stays open. Opens the fake system VPN "Smoke Live A"; once the driver has
// removed it, checks the read-only detail (the banner in the window's language, every control disabled, the
// selection kept although the row is gone); then waits for the row of "Smoke Live B", which the driver adds.
// Writes the result into a seeded connection's name (`LIVE …`).
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 8000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  // The detail pane's system VPN view (the sidebar's type icons carry a `system` class too).
  const detail = (selector = '') => document.querySelector(`main .system ${selector}`.trim());
  const row = (name) => [...document.querySelectorAll('nav .row')].find((b) => b.textContent.includes(name));
  const checks = {};
  try {
    const vm = await invoke('get_view_model');
    const banner = { en: 'This VPN was removed from macOS', hu: 'Ezt a VPN-t eltávolították a macOS-ből' }[vm.language];
    const a = await waitFor(() => row('Smoke Live A'));
    checks.listed = !!a;
    a.click();
    const psk = await waitFor(() => detail('.form input[type="password"]'));
    checks.editable = !!psk && !psk.disabled;
    // The driver removes the service now.
    const removed = await waitFor(() => detail('.removed'), 15000);
    checks.banner = !!removed && !!banner && removed.textContent.trim() === banner;
    checks.rowGone = !row('Smoke Live A');
    checks.detailKept = detail('h1')?.textContent === 'Smoke Live A';
    const controls = [...document.querySelectorAll('main .system .form input, main .system .form select, main .system .form button, main .system .head button')];
    checks.disabled = controls.length >= 4 && controls.every((c) => c.disabled);
    // The driver adds a service now: its row appears in the open window.
    checks.newRow = !!(await waitFor(() => row('Smoke Live B'), 20000));
    checks.stillKept = !!detail('.removed');
    // Another selection: the removed VPN's detail goes.
    checks.deselected = await invoke('select_connection', { id: null });
    checks.cleared = !!(await waitFor(() => !detail()));
  } catch (e) {
    console.error(e);
    checks.error = false;
  }
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  const id = 'C1111111-2222-4333-8444-555555555555';
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'LIVE OK' : `LIVE FAILED ${failed.join(',')}` } });
})();
