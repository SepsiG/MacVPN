// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window,
// last: leaves an unsaved change, then the shell asks the app to quit the way logout does (a quit Apple Event,
// NSRunningApplication.terminate). applicationShouldTerminate must answer "later" and show "Unsaved Changes" here
// (the system's request); the script notes that in a seeded connection's name and answers Discard, and the app
// must then quit.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const dirty = '11111111-2222-4333-8444-555555555555';
  const result = '66666666-7777-4888-9999-AAAAAAAAAAAA';
  const view = await invoke('editor_open', { id: dirty });
  await invoke('editor_update', { id: dirty, fields: { ...view.fields, name: 'Not saved' } });
  for (let i = 0; i < 600; i++) {
    const vm = await invoke('get_view_model');
    if (vm.quit?.origin === 'system' && vm.quit.step === 'unsaved' && vm.manage.pending === 'quit') {
      const b = await invoke('editor_open', { id: result });
      await invoke('editor_save', { id: result, fields: { ...b.fields, name: 'SYSTEM ASKED' } });
      await invoke('resolve_unsaved', { choice: 'discard' });
      return;
    }
    await sleep(200);
  }
})();
