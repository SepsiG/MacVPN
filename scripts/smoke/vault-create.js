// Driven by scripts/smoke-manage.sh, in the create window (`vault-create`, migration mode: the seeded 1.1 data is
// the migration's input). Checks each step's title in the view model's language and that the buttons wait for the
// one-second input lock; types the master password twice (__PASSWORD__, filled in by the app's smoke driver), reads
// the recovery key from the window, says "I saved it", retypes the asked group (in lower case: compared
// case-insensitively), waits for the migration's result and closes. Anything unexpected stops the script, and the
// driver reports that the vault did not open.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 60000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    throw new Error('timeout');
  };
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const enabled = (selector) => () => {
    const b = document.querySelector(selector);
    return b && !b.disabled ? b : null;
  };
  const title = () => document.querySelector('.create h1')?.textContent.trim();
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  const texts = {
    en: { intro: 'Set up the vault', key: 'Your recovery key', verified: 'Your data is in the vault', done: 'The vault is ready' },
    hu: { intro: 'A széf beállítása', key: 'A helyreállítási kulcsod', verified: 'Az adataid a széfben vannak', done: 'A széf elkészült' },
  }[vm.language];
  if (!vm.vaultSetup?.migrating) throw new Error('not in migration mode');

  // Intro: the Keychain note, then Continue once the input lock passed.
  await waitFor(() => title() === texts.intro);
  if (!document.querySelector('.create .note')) throw new Error('no Keychain note');
  (await waitFor(enabled('.create button.continue'))).click();

  // The password twice; Create waits for both.
  const password = await waitFor(() => document.querySelector('.create input[data-field=password]:not(:disabled)'));
  setValue(password, '__PASSWORD__');
  await sleep(100);
  if (!document.querySelector('.create button.create-vault')?.disabled) throw new Error('Create before the repeat');
  setValue(document.querySelector('.create input[data-field=again]'), '__PASSWORD__');
  (await waitFor(enabled('.create button.create-vault'))).click();

  // The key, shown once.
  await waitFor(() => title() === texts.key);
  const key = await waitFor(() => document.querySelector('[data-recovery-key]')?.textContent.trim());
  if (!/^[0-9A-Z]{4}(-[0-9A-Z]{4}){5}$/.test(key)) throw new Error('no key');
  (await waitFor(enabled('.create button.saved'))).click();

  // Retype the asked group.
  const field = await waitFor(() => document.querySelector('.create input[data-field=group]'));
  if (document.body.textContent.includes(key)) throw new Error('the key is still shown');
  const asked = (await window.__TAURI_INTERNALS__.invoke('get_view_model')).vaultSetup.group;
  setValue(field, key.split('-')[asked].toLowerCase());
  (await waitFor(enabled('.create button.confirm'))).click();

  // The migration, its result, and the end.
  await waitFor(() => title() === texts.verified, 90000);
  (await waitFor(enabled('.create button.finish'))).click();
  await waitFor(() => title() === texts.done);
  (await waitFor(enabled('.create button.close'))).click();
})();
