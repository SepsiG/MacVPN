// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window: a
// team catalog subscribed and used through the real UI, one phase per run (`window.__smokeCatalog`, set by the app's
// smoke driver, which also fills in __TEAM_KEY__ and __FINGERPRINT__; they are never logged). The catalog file is a
// fixture the driver sealed with the core's functions; "Choose File…" gets it in place of the open panel.
//   preview     – Team catalogs → "Add team catalog…": the file source, the team key and the fingerprint typed
//                 ("Check" disabled until the fingerprint is complete), "Check", the preview (name, version, the
//                 fingerprint to compare, "Subscribe" disabled until the comparison is ticked; no key in the DOM);
//   subscribe   – ticked and subscribed: the detail (status, fingerprint), the Team badge on the catalog's folder and
//                 its connections in the tree;
//   readonly    – a team connection's editor: the "Managed by" note, the disabled config, the risky checkbox active;
//                 its context menu (no "Move to Top Level", "Duplicate as personal connection…" there); a drag refused
//                 with its reason;
//   update      – (the driver wrote version 2) "Refresh now": the outcome line, the renamed and the added connection;
//   ask         – "Unsubscribe…": the question names the catalog and the count;
//   unsubscribe – confirmed: the catalog and its connections are gone.
// Each phase writes its result into the result connection's name (`CATALOG <phase> OK` / `… FAILED <checks>`).
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 10000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const setValue = (el, value) => {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const $ = (selector) => document.querySelector(selector);
  const RESULT = 'E5111111-2222-4333-8444-555555555555';
  const phase = window.__smokeCatalog;
  const vm = await invoke('get_view_model');
  const lang = vm.language;
  const t = (en, hu) => (lang === 'hu' ? hu : en);
  const checks = {};
  const openSection = async () => {
    $('nav button.link-team-catalogs')?.click();
    return waitFor(() => $('.team-catalogs-section'));
  };
  const teamRows = () => [...document.querySelectorAll('nav [data-tree-row]')].filter((r) => r.querySelector('.team-badge'));
  const rowNamed = (name) => [...document.querySelectorAll('nav [data-tree-row]')].find((r) => r.querySelector('.label')?.textContent.trim() === name);
  try {
    if (phase === 'preview') {
      checks.section = !!(await openSection());
      $('.team-catalogs-section button.add').click();
      const sheet = await waitFor(() => $('.sheet'));
      checks.dialog = !!sheet && sheet.querySelector('h1')?.textContent.trim() === t('Add Team Catalog', 'Csapatkatalógus hozzáadása');
      [...document.querySelectorAll('.sheet .source-kind button')][1]?.click();
      (await waitFor(() => $('.sheet button.choose-file'))).click();
      checks.file = !!(await waitFor(() => $('.sheet .file-name')?.textContent.trim() === 'smoke.macvpncatalog'));
      setValue($('.sheet input.team-key'), '__TEAM_KEY__');
      await sleep(100);
      checks.noFingerprintNoCheck = $('.sheet button.check').disabled;
      setValue($('.sheet input.fingerprint'), '__FINGERPRINT__'.replace(/-/g, ''));
      await sleep(100);
      checks.fingerprintFormatted = $('.sheet input.fingerprint').value === '__FINGERPRINT__';
      checks.checkEnabled = !$('.sheet button.check').disabled;
      $('.sheet button.check').click();
      const preview = await waitFor(() => $('.sheet [data-preview]'), 20000);
      checks.preview = !!preview && preview.querySelector('.name')?.textContent.trim() === 'Smoke Catalog';
      checks.previewFingerprint = !!preview?.textContent.includes('__FINGERPRINT__');
      checks.previewCounts = !!preview?.textContent.includes(t('2 connections', '2 kapcsolat'));
      checks.subscribeGated = $('.sheet button.subscribe')?.disabled === true;
      checks.noKeyInDom = !document.documentElement.outerHTML.includes('__TEAM_KEY__') && !$('.sheet input.team-key');
      // Without a preview, the sheet's error names the cause in the result.
      const error = $('.sheet .form-error')?.textContent.trim();
      if (!preview && error) checks[`error:${error.slice(0, 120).replace(/\s+/g, '_')}`] = false;
    } else if (phase === 'subscribe') {
      $('.sheet .compared input').click();
      await sleep(100);
      checks.subscribeEnabled = $('.sheet button.subscribe')?.disabled === false;
      $('.sheet button.subscribe').click();
      const detail = await waitFor(() => $('.catalog-detail'), 20000);
      checks.detail = !!detail && detail.querySelector('h1')?.textContent.trim() === 'Smoke Catalog';
      checks.closed = !$('.sheet');
      checks.fingerprint = detail?.querySelector('.fingerprint')?.textContent.trim() === '__FINGERPRINT__';
      checks.status = detail?.querySelector('.status')?.textContent.trim() === t('Up to date', 'Naprakész');
      checks.badges = !!(await waitFor(() => teamRows().length >= 3));
      checks.rootBadge = !!rowNamed('Smoke Catalog')?.querySelector('.team-badge');
      checks.listed = (await invoke('get_view_model')).catalogs?.length === 1;
    } else if (phase === 'readonly') {
      const row = await waitFor(() => rowNamed('Smoke Team A'));
      row.querySelector('button').click();
      const note = await waitFor(() => $('.readonly-note'), 10000);
      checks.note = note?.textContent.trim() === t('Managed by the team catalog “Smoke Catalog”', 'A(z) „Smoke Catalog” csapatkatalógus kezeli');
      checks.configDisabled = !!$('textarea.config')?.matches(':disabled');
      const risky = $('.risky input[type=checkbox]');
      checks.riskyActive = !!risky && !risky.matches(':disabled');
      checks.noDelete = !$('.detail .actions button.destructive');
      checks.bar = !!$('.team-bar button.duplicate-personal');
      // The context menu offers only what the user may change.
      const button = row.querySelector('button');
      const r = button.getBoundingClientRect();
      button.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: r.left + 40, clientY: r.top + r.height / 2 }));
      const menu = await waitFor(() => $('.menu [data-action="duplicate"]'));
      checks.menu = !!menu && !$('.menu [data-action="top-level"]') && !$('.menu [data-action="new-folder"]') && !!$('.menu [data-action="colour"]');
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      await sleep(200);
      // A drag is refused, with its reason.
      const before = (await invoke('get_view_model')).tree.find((x) => x.type === 'item' && rowNamed('Smoke Team A')?.dataset.id === x.id)?.parent;
      button.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, button: 0, clientX: r.left + 30, clientY: r.top + r.height / 2 }));
      for (let i = 1; i <= 6; i++) {
        window.dispatchEvent(new PointerEvent('pointermove', { bubbles: true, clientX: r.left + 30, clientY: r.top + r.height / 2 + i * 25 }));
        await sleep(40);
      }
      checks.dragReason = $('.ghost .reason')?.textContent.trim() === t('Team catalog items cannot be moved.', 'A csapatkatalógus elemei nem helyezhetők át.');
      window.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, clientX: r.left + 30, clientY: r.top + r.height / 2 + 150 }));
      await sleep(300);
      const after = (await invoke('get_view_model')).tree.find((x) => x.type === 'item' && rowNamed('Smoke Team A')?.dataset.id === x.id)?.parent;
      checks.notMoved = before !== undefined && before === after;
    } else if (phase === 'update') {
      await openSection();
      (await waitFor(() => $('.team-catalogs-section button.subscription')))?.click();
      (await waitFor(() => $('.catalog-detail button.refresh'))).click();
      const line = await waitFor(() => $('.catalog-detail .result'), 20000);
      checks.result = line?.textContent.trim() === t('Updated: 1 added, 1 changed', 'Frissítve: 1 hozzáadva, 1 módosítva');
      checks.version = !!(await waitFor(() => $('.catalog-detail')?.textContent.includes('v2')));
      checks.renamed = !!(await waitFor(() => rowNamed('Smoke Team A2') && rowNamed('Smoke Team C') && !rowNamed('Smoke Team A')));
    } else if (phase === 'ask') {
      $('.catalog-detail button.unsubscribe').click();
      const sheet = await waitFor(() => $('.sheet'));
      checks.title = sheet?.querySelector('h1')?.textContent.trim() === t('Unsubscribe from Smoke Catalog?', 'Leiratkozol a(z) Smoke Catalog katalógusról?');
      checks.count = !!sheet?.textContent.includes(t('Its 3 connections', 'A(z) 3 kapcsolata'));
    } else if (phase === 'unsubscribe') {
      $('.sheet button.confirm').click();
      checks.gone = !!(await waitFor(async () => (await invoke('get_view_model')).catalogs?.length === 0, 20000));
      checks.rowsGone = !!(await waitFor(() => teamRows().length === 0));
      checks.notice = !!(await waitFor(() => $('.team-catalogs-section .notice')));
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
  const view = await invoke('editor_open', { id: RESULT });
  await invoke('editor_save', {
    id: RESULT,
    fields: { ...view.fields, name: failed.length === 0 ? `CATALOG ${phase} OK` : `CATALOG ${phase} FAILED ${failed.join(',')}` },
  });
})();
