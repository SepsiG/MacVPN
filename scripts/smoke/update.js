// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Update window over the
// mock release (its notes hold markup that must stay text). With unsaved changes, "Download and Install" runs the
// sandbox's update steps up to the quit questions; the unsaved-changes question is cancelled, which stops the
// update and cleans up. The result goes into a seeded connection's name.
(async () => {
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
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const id = '51111111-2222-4333-8444-555555555555';
  const checks = {};
  try {
    checks.title = !!(await waitFor(() => document.querySelector('.update h1')?.textContent.includes('v9.9.9')));
    const notes = document.querySelector('.notes');
    checks.inlineMarkup = !!notes.querySelector('.bold') && !!notes.querySelector('code') && !!notes.querySelector('.italic');
    checks.noHtml = !notes.querySelector('script, img, a') && notes.textContent.includes('<script>') && !window.smokeInjected;
    checks.linkText = notes.textContent.includes('a link') && !notes.textContent.includes('https://example.com');

    // An unsaved change: the update's quit step asks about it first.
    const view = await invoke('editor_open', { id });
    await invoke('editor_update', { id, fields: { ...view.fields, name: 'Dirty U' } });
    document.querySelector('.update .install').click();
    checks.stage = !!(await waitFor(() => document.querySelector('.update .stage')));
    const asked = await waitFor(async () => {
      const vm = await invoke('get_view_model');
      return vm.manage.pending === 'quit' && vm.quit?.origin === 'update' && vm.quit.step === 'unsaved' ? vm : null;
    }, 15000);
    checks.unsavedAsked = !!asked;
    await invoke('resolve_unsaved', { choice: 'cancel' });
    checks.cancelled = !!(await waitFor(() => !document.querySelector('.update .stage') && !document.querySelector('.update .error')));
    checks.questionGone = (await invoke('get_view_model')).quit === null;
    checks.stillOffered = !!document.querySelector('.update .install:not(:disabled)');
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'UPDATE OK' : `UPDATE FAILED ${failed.join(',')}` } });
})();
