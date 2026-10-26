// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), the features plan's Task 15: a
// connection whose engine is missing. The app's smoke driver sets `window.__smoke` (`phase`, `result`, and the
// seeded row's `name`, `id`, `kind`, its expected status `text`, the import's `refusal`):
//   menu   – in the menu popover: the row is greyed, its status says "Not installed: …", its switch is disabled, and
//            its "System Status" link is clicked (the driver checks that the window opens);
//   new    – in the Connections window: the list row is greyed with the same text and its link, the New menu's kinds
//            (above its separator) are the view model's, without this one;
//   import – the report of a file of that kind opened from Finder / Explorer names the refusal; OK closes it;
//   after  – in the popover, the engine installed: the row is normal (no link, the switch enabled).
// Each phase writes `ENGINES <phase> OK` / `… FAILED <checks>` into the result connection's name.
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const S = window.__smoke;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 8000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const card = () => [...document.querySelectorAll('.card')].find((c) => c.querySelector('.label')?.textContent === S.name);
  const checks = {};
  try {
    if (S.phase === 'menu') {
      const row = await waitFor(() => (card()?.classList.contains('unavailable') ? card() : null));
      checks.greyed = !!row;
      checks.text = row?.querySelector('.subtitle .status')?.textContent === S.text;
      checks.switchDisabled = row?.querySelector('button.switch')?.disabled === true;
      const link = row?.querySelector('.subtitle button.link');
      checks.link = !!link;
      link?.click();
    } else if (S.phase === 'new') {
      const vm = await invoke('get_view_model');
      const row = vm.rows.find((r) => r.id === S.id);
      checks.viewModel = !!row && !row.available && row.setupLink === true;
      const item = await waitFor(() =>
        [...document.querySelectorAll('nav .row.item')].find((b) => b.querySelector('.label')?.textContent === S.name),
      );
      checks.listGreyed = !!item?.classList.contains('unavailable');
      checks.listText = !!item?.querySelector('.type')?.textContent.includes(S.text);
      checks.listLink = !!item?.querySelector('.setup-link');
      checks.kinds = vm.manage.kinds.length > 0 && vm.manage.kinds.every((k) => k.value !== S.kind);
      document.querySelector('.sidebar button.new')?.click();
      // The kinds are the items above the separator (New Folder, Import… and the rest follow it).
      const menu = await waitFor(() => document.querySelector('.sidebar .menu'));
      const kindItems = [];
      for (const el of menu?.children ?? []) {
        if (el.tagName === 'HR') break;
        if (el.getAttribute('role') === 'menuitem') kindItems.push(el);
      }
      const titles = kindItems.map((b) => b.textContent.trim());
      checks.menu = titles.length === vm.manage.kinds.length && vm.manage.kinds.every((k) => titles.includes(k.title));
      checks.menuWithout = !!row && !titles.includes(row.typeLabel);
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      checks.menuClosed = !!(await waitFor(() => !document.querySelector('.sidebar .menu')));
    } else if (S.phase === 'import') {
      const alert = await waitFor(() => {
        const a = document.querySelector('.alert');
        return a && a.textContent.includes(S.refusal) ? a : null;
      }, 20000);
      checks.refused = !!alert;
      alert?.querySelector('.buttons button.primary')?.click();
      checks.closed = !!(await waitFor(() => !document.querySelector('.alert')));
    } else if (S.phase === 'after') {
      const row = await waitFor(() => (card() && !card().classList.contains('unavailable') ? card() : null), 4000);
      checks.normal = !!row;
      checks.switchEnabled = row?.querySelector('button.switch')?.disabled === false;
      checks.noLink = !!row && !row.querySelector('.subtitle button.link');
    } else {
      checks.phase = false;
    }
  } catch (e) {
    console.error(e);
    checks.error = false;
  }
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  const view = await invoke('editor_open', { id: S.result });
  await invoke('editor_save', {
    id: S.result,
    fields: { ...view.fields, name: `${S.section} ${S.phase} ${failed.length === 0 ? 'OK' : `FAILED ${failed.join(',')}`}` },
  });
})();
