// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window,
// after prompt.js and before system.js. The quit flows' edge cases, through the real commands:
// - the menu's Quit with an unsaved change, then a selection meanwhile (a notification click, a debug connect):
//   the quit's "Unsaved Changes" must stay; cancelling it frees the quit guard, then the selection follows;
// - "Download and Install" with the unsaved change, the Update window closed during the download: the question
//   still appears (here); then the Update window is opened and closed again while the question is shown: the
//   update's quit is cancelled, the question here goes away, the install ends (no stage left; the shell checks
//   that its files were cleaned up).
// Nothing here quits the app. The result goes into a seeded connection's name.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const waitFor = async (fn, ms = 10000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const vm = () => invoke('get_view_model');
  const id = '71111111-2222-4333-8444-555555555555';
  const other = '21111111-2222-4333-8444-555555555555';
  const checks = {};
  const dirty = async (name) => {
    const view = await invoke('editor_open', { id });
    await invoke('editor_update', { id, fields: { ...view.fields, name } });
  };
  try {
    // The menu's Quit, then a selection while its question is shown.
    await invoke('select_connection', { id });
    await dirty('Dirty Q');
    checks.quitAsks = (await invoke('quit', { choice: null })) === 'unsaved';
    let v = await vm();
    checks.quitQuestion = v.quit?.origin === 'menu' && v.quit.step === 'unsaved' && v.manage.pending === 'quit';
    checks.selectionWaits = (await invoke('select_connection', { id: other })) === false;
    v = await vm();
    checks.quitQuestionKept = v.manage.pending === 'quit' && v.manage.selected === id;
    await invoke('resolve_unsaved', { choice: 'cancel' });
    v = await vm();
    checks.guardFreed = v.quit === null;
    checks.selectionFollows = v.manage.pending === 'select';
    await invoke('resolve_unsaved', { choice: 'cancel' });
    v = await vm();
    checks.selectionCancelled = v.manage.pending === null && v.manage.selected === id && v.manage.dirty.includes(id);

    // Download and Install; the Update window closes during the download.
    await invoke('update_install');
    checks.installing = !!(await waitFor(async () => (await vm()).update.installStage !== null, 3000));
    await invoke('close_window', { name: 'update' });
    const asked = await waitFor(async () => {
      const x = await vm();
      return x.quit?.origin === 'update' && x.quit.step === 'unsaved' && x.manage.pending === 'quit' ? x : null;
    }, 15000);
    checks.askedWithoutUpdateWindow = !!asked;
    // The Update window opens and closes again while the question is shown here: the update's quit is cancelled.
    await invoke('open_window', { name: 'update' });
    await sleep(1500);
    await invoke('close_window', { name: 'update' });
    const ended = await waitFor(async () => {
      const x = await vm();
      return x.quit === null && x.update.installStage === null ? x : null;
    }, 10000);
    checks.updateCancelled = !!ended;
    checks.questionDismissed = ended?.manage.pending === null;
    checks.editingKept = !!ended?.manage.dirty.includes(id);
    checks.stillOffered = ended?.update.available !== null && ended?.update.installError === null;
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  // Clean up: no unsaved change and no question are left for system.js.
  for (let i = 0; i < 3 && (await vm()).manage.pending; i++) await invoke('resolve_unsaved', { choice: 'cancel' });
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'QUIT OK' : `QUIT FAILED ${failed.join(',')}` } });
})();
