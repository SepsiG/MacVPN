// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the restore window, with
// `window.__SMOKE_RESTORE__` set by the backend to `merge` or `replace`. The file comes from the smoke run's
// backend (no open panel). `merge`: a wrong password first (the generic message, the field cleared), then the right
// one, Merge with "Overwrite" as the single conflict answer. `replace`: Replace everything; its question must name
// the one connection added since the backup; then the preferences step must show the control API unticked (the
// backup has it on) and applies the ticked ones. Done closes the window. Anything wrong: the window stays open
// without a restore, which the backend reports.
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
  const mode = window.__SMOKE_RESTORE__;
  const root = '.vault-window.restore';
  const choose = await waitFor(() => document.querySelector(`${root} button.choose`));
  if (!choose) return;
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  const generic = {
    en: 'The backup cannot be opened. The password is wrong, or the file is damaged.',
    hu: 'A mentés nem nyitható meg. Hibás a jelszó, vagy sérült a fájl.',
  }[vm.language];
  choose.click();
  const field = () => {
    const input = document.querySelector(`${root} input[data-field=backup-password]`);
    return input && !input.disabled ? input : null;
  };
  if (!(await waitFor(field))) return;
  const open = () => document.querySelector(`${root} button.open`);
  if (mode === 'merge') {
    setValue(field(), 'wrong password 1234');
    await sleep(100);
    open().click();
    const error = await waitFor(() => document.querySelector(`${root} .banner.error`), 30000);
    if (!error || error.textContent.trim() !== generic || field()?.value !== '') return;
  }
  setValue(field(), 'smoke backup pw 4711');
  await sleep(100);
  open().click();
  const restore = await waitFor(() => document.querySelector(`${root} button.restore`), 30000);
  if (!restore) return;
  if (mode === 'merge') {
    const overwrite = document.querySelector(`${root} input[name=conflict][value=overwrite]`);
    if (!overwrite) return;
    overwrite.click();
    await sleep(100);
    restore.click();
  } else {
    document.querySelector(`${root} input[name=restore-mode][value=replace]`)?.click();
    await sleep(200);
    document.querySelector(`${root} button.restore`).click();
    const dialog = await waitFor(() => document.querySelector(`${root} [role=alertdialog]`), 3000);
    if (!dialog || !dialog.querySelector('.lost')?.textContent.includes(': 1 ')) return;
    dialog.querySelector('button.confirm-replace').click();
  }
  const done = await waitFor(() => document.querySelector(`${root} button.done`), 60000);
  if (!done) return;
  if (mode === 'replace') {
    const control = document.querySelector(`${root} [data-preference=controlApi] input`);
    if (!control || control.checked) return;
    document.querySelector(`${root} button.apply`)?.click();
    if (!(await waitFor(() => document.querySelector(`${root} .applied`), 10000))) return;
  }
  done.click();
})();
