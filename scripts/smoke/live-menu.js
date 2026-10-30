// Driven by scripts/smoke-manage.sh, in the menu popover (created at launch, hidden, never reopened), after
// live.js: the rows follow the live system VPN list – "Smoke Live B" (added) is shown, "Smoke Live A" (removed)
// is not, and the version line shows the backend's version, inside the window (not clipped). Writes the result into a seeded connection's name (`MENU …`).
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
  const names = () => [...document.querySelectorAll('.card .label')].map((l) => l.textContent);
  const checks = {};
  checks.added = !!(await waitFor(() => names().includes('Smoke Live B')));
  checks.removed = !names().includes('Smoke Live A');
  checks.others = names().includes('Zz Control VPN');
  // The version line under the debug hint: the backend's version through the view model.
  // The product's name (MacVPN, WinVPN) as the platform reports it.
  const version = (await invoke('get_view_model')).appVersion;
  const product = (await invoke('get_platform')).productName;
  checks.version = !!version && document.querySelector('.version')?.textContent === `${product} ${version}`;
  // Not clipped: the window's height (set_menu_height, from the measured content) leaves the version line and
  // the bottom padding inside the page. Linux's card panel (the `overlay` page) is not sized to its content: hidden,
  // the overlay has no size; the driver shows it once the rows above were read, and the card with its version line
  // must then fit the overlay, which covers the work area.
  const overlay = document.documentElement.classList.contains('overlay');
  if (overlay) await waitFor(() => window.innerHeight > 0, 20000);
  const fits = () => {
    const line = document.querySelector('.version')?.getBoundingClientRect();
    const main = document.querySelector('main')?.getBoundingClientRect();
    return !!line && !!main && line.height > 0 && line.bottom <= window.innerHeight && main.bottom <= window.innerHeight + 1;
  };
  checks.versionVisible = !!(await waitFor(fits, 4000));
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  if (!checks.versionVisible) {
    // The geometry, for the log: the version line's and the card's bottom, the window's and the work area's height.
    const line = document.querySelector('.version')?.getBoundingClientRect();
    const main = document.querySelector('main')?.getBoundingClientRect();
    failed.push(`line=${Math.round(line?.bottom ?? -1)}/${Math.round(line?.height ?? -1)} main=${Math.round(main?.bottom ?? -1)} window=${window.innerHeight} screen=${window.screen.availHeight}`);
  }
  const id = 'C2111111-2222-4333-8444-555555555555';
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'MENU OK' : `MENU FAILED ${failed.join(',')}` } });
})();
