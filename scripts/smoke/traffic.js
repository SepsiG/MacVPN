// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), the features step `traffic`: the
// live traffic line of a connected connection whose stand-in counters grow (1.5 MB/s down, 40 kB/s up). In the
// Connections window (phase `detail`: the connection's detail header) or in the popover (phase `card`: its card):
// the line appears with the totals ("↓ … ↑ …") and the rates (".../s"), in the run's decimal separator, and the
// totals change between two reads about two seconds apart. Writes `TRAFFIC <phase> OK` / `… FAILED <checks>`
// into the result connection's name.
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
  const checks = {};
  const amount = '\\d+(?:[.,]\\d)? (?:B|kB|MB|GB|TB)';
  const totalsRe = new RegExp(`^↓ ${amount}  ↑ ${amount}$`);
  const ratesRe = new RegExp(`^↓ ${amount}/s  ↑ ${amount}/s$`);
  try {
    let line;
    if (S.phase === 'detail') {
      if (document.querySelector('.detail h1')?.textContent !== S.name) {
        [...document.querySelectorAll('nav .row.item')].find((b) => b.querySelector('.label')?.textContent === S.name)?.click();
      }
      checks.selected = !!(await waitFor(() => document.querySelector('.detail h1')?.textContent === S.name));
      line = () => document.querySelector('.detail .header [data-traffic]');
    } else {
      const card = () => [...document.querySelectorAll('.card')].find((c) => c.querySelector('.label')?.textContent === S.name);
      checks.card = !!(await waitFor(card));
      line = () => card()?.querySelector('[data-traffic]');
    }
    const first = await waitFor(() => (line()?.querySelector('.rates') ? line() : null));
    checks.shown = !!first;
    const totals = () => line()?.querySelector('.totals')?.textContent ?? '';
    const rates = () => line()?.querySelector('.rates')?.textContent ?? '';
    const before = totals();
    checks.totalsFormat = totalsRe.test(before);
    checks.ratesFormat = ratesRe.test(rates());
    // 1.5 MB/s down, 40 kB/s up: "↓ 1.5 MB/s  ↑ 40.0 kB/s" (Hungarian "1,5" and "40,0"); every decimal in the run's
    // separator.
    const decimals = `${before} ${rates()}`.match(/\d[.,]\d/g) ?? [];
    checks.separator =
      / MB\/s {2}/.test(rates()) && / kB\/s$/.test(rates()) && decimals.length >= 2 && decimals.every((d) => d[1] === S.separator);
    checks.tooltip = (line()?.getAttribute('title') ?? '').length > 0;
    checks.grows = !!(await waitFor(() => totals() !== before && totalsRe.test(totals()), 6000));
    const reply = await invoke('get_traffic');
    checks.command = !!reply[S.id]?.totals;
    if (!checks.totalsFormat || !checks.ratesFormat || !checks.separator) console.error(`traffic: ${before} | ${rates()}`);
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
