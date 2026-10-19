// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the backup window: the
// warning in the view model's language; "Use my master password…" asks first (the question is cancelled, and the
// own password stays); "Back Up…" stays disabled until the password is typed twice and the master password
// (__MASTER__, filled in by the app's smoke driver; always checked) is typed; then the backup (the smoke
// run's backend takes the sandbox file in place of the save panel) and Done, which closes the window. Anything
// wrong: the window is left open without a backup, which the backend reports.
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
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const save = await waitFor(() => document.querySelector('.backup button.save'));
  if (!save) return;
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  const warning = {
    en: 'Anyone with this file and its password can read all your VPN credentials.',
    hu: 'Aki birtokolja ezt a fájlt és a jelszavát, az összes VPN-hitelesítő adatodat elolvashatja.',
  }[vm.language];
  const shown = document.querySelector('.backup .warning')?.textContent.trim() === warning;
  // The master password needs its own confirmation step.
  document.querySelector('.backup button.use-master')?.click();
  const dialog = await waitFor(() => document.querySelector('.backup [role=alertdialog]'), 3000);
  const askedFirst = !!dialog && !document.querySelector('.backup input[data-field=master]');
  dialog?.querySelector('button.cancel-master')?.click();
  await sleep(200);
  const input = (field) => document.querySelector(`.backup input[data-field=${field}]`);
  if (!shown || !askedFirst || !save.disabled || !input('password') || !input('repeat')) return;
  setValue(input('password'), 'smoke backup pw 4711');
  await sleep(100);
  if (!document.querySelector('.backup button.save').disabled) return;
  setValue(input('repeat'), 'smoke backup pw 4711');
  await sleep(100);
  if (!input('current-master') || !document.querySelector('.backup button.save').disabled) return;
  setValue(input('current-master'), '__MASTER__');
  const ready = await waitFor(() => !document.querySelector('.backup button.save').disabled, 3000);
  if (!ready) return;
  document.querySelector('.backup button.save').click();
  const done = await waitFor(() => document.querySelector('.backup button.done'), 60000);
  done?.click();
})();
