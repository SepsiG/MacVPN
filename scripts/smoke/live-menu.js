// Driven by scripts/smoke-manage.sh, in the menu popover (created at launch, hidden, never reopened), after
// live.js: the rows follow the live system VPN list – "Smoke Live B" (added) is shown, "Smoke Live A" (removed)
// is not. Writes the result into a seeded connection's name (`MENU …`).
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
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  const id = 'C2111111-2222-4333-8444-555555555555';
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'MENU OK' : `MENU FAILED ${failed.join(',')}` } });
})();
