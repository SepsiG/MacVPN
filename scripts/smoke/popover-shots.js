// Driven by scripts/smoke-manage.sh with SMOKE_SHOTS (MACVPN_SMOKE_DIR, debug build, sandbox only), in the
// Connections window: holds the New menu open, then a connection's context menu at the window's right edge, each
// until the driver took its screenshot (`new-menu`, `context-menu`); then the search with results and with none
// (`search-results`, `search-empty`), cleared after. The checks are in manage.js.
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
  const shot = async () => {
    if (window.smokeShot === 'pending') await waitFor(() => window.smokeShot === 'done', 30000);
  };
  const escape = () => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  const shots = window.smokeShot === 'pending';
  document.querySelector('.sidebar .toolbar button.new')?.click();
  await waitFor(() => document.querySelector('.sidebar .menu'));
  await shot();
  escape();
  await waitFor(() => !document.querySelector('.sidebar .menu'));
  if (shots) window.smokeShot = 'pending';
  const row = await waitFor(() => document.querySelector('nav .row.item'));
  const rect = row?.getBoundingClientRect();
  row?.dispatchEvent(
    new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: innerWidth - 3, clientY: rect ? rect.top + rect.height / 2 : 80 }),
  );
  await waitFor(() => document.querySelector('.menu[role=menu]'));
  await shot();
  escape();
  await waitFor(() => !document.querySelector('.menu[role=menu]'));
  const field = document.querySelector('.sidebar input.query');
  const type = (value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  };
  if (shots) window.smokeShot = 'pending';
  field?.focus();
  type('séeded');
  await waitFor(() => document.querySelector('nav .tree.filtering mark'));
  await shot();
  if (shots) window.smokeShot = 'pending';
  type('árvíztűrő');
  await waitFor(() => document.querySelector('.sidebar .no-match'));
  await shot();
  type('');
  field?.blur();
})();
