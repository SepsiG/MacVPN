// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window,
// after credentials.js. Shared credentials (spec 3a) through the real UI; the driver sets `window.__smokeShared`
// to the phase before each run and checks the backend afterwards:
//   setup  – the Credentials section (its title in the window's language) adds "Smoke Cred" with a user name and
//            no password; then the two seeded "Zz Shared" OpenVPN connections are linked to it through their
//            editors' selector, each after the confirmation;
//   delete – Delete on the card asks "Copy into each connection" or Cancel, naming both connections; Copy;
//   import – the import's question (the driver imports a file whose metadata names "Smoke Import"): the title names
//            the config's server and the buttons are "Use Shared Credential" / "Use Own Fields"; Use.
// Anything wrong: the step is not done (or the question is answered the other way), which the driver reports.
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
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
  const row = (name) => [...document.querySelectorAll('nav .list .row')].find((b) => b.textContent.includes(name));
  const card = (name) =>
    [...document.querySelectorAll('[data-credential]')].find((c) => c.querySelector('.name')?.textContent === name);
  const openSection = async () => {
    document.querySelector('nav .shared-credentials').click();
    return waitFor(() => document.querySelector('.credentials-section h1'));
  };
  const vm = await invoke('get_view_model');
  const phase = window.__smokeShared;

  if (phase === 'setup') {
    const title = { en: 'Credentials', hu: 'Hitelesítő adatok' }[vm.language];
    const h1 = await openSection();
    if (!h1 || h1.textContent.trim() !== title) return;
    (await waitFor(() => document.querySelector('.credentials-section button.add:not([disabled])'))).click();
    const name = await waitFor(() => document.querySelector('.alert input.cred-name'));
    setValue(name, 'Smoke Cred');
    setValue(document.querySelector('.alert input.cred-user'), 'smoke-shared');
    document.querySelector('.alert button.primary').click();
    const added = await waitFor(() => card('Smoke Cred'));
    // Never a password in the section (none stored yet, and none ever sent).
    if (!added || document.querySelector('.credentials-section input[type=password]')) return;
    for (const connection of ['Zz Shared one', 'Zz Shared two']) {
      (await waitFor(() => row(connection))).click();
      // The connection's own detail (not the previous one's, still shown for a moment).
      if (!(await waitFor(() => document.querySelector('main .detail h1')?.textContent === connection))) return;
      const select = await waitFor(() => {
        const s = document.querySelector('main .credential-choice');
        return s && [...s.options].some((o) => o.textContent.includes('Smoke Cred')) ? s : null;
      });
      if (!select) return;
      const option = [...select.options].find((o) => o.textContent.includes('Smoke Cred'));
      select.value = option.value;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      // The confirmation: the own user name and password are deleted.
      (await waitFor(() => document.querySelector('.alert button.primary'))).click();
      // Linked: the own fields are gone, the note names the credential.
      if (!(await waitFor(() => document.querySelector('main .credential-selector .linked')?.textContent.includes('Smoke Cred')))) return;
      if (document.querySelector('main fieldset input[type=text]')) return;
    }
    await openSection();
  } else if (phase === 'delete') {
    await openSection();
    const c = await waitFor(() => card('Smoke Cred'));
    if (!c) return;
    c.querySelector('button.delete').click();
    const items = await waitFor(() => {
      const li = [...document.querySelectorAll('.alert .in-use li')].map((l) => l.textContent.trim());
      return li.length > 0 ? li : null;
    });
    const named = !!items && items.length === 2 && items.includes('Zz Shared one') && items.includes('Zz Shared two');
    document.querySelector(named ? '.alert button.destructive' : '.alert button.cancel').click();
    await waitFor(() => !card('Smoke Cred'));
  } else if (phase === 'import') {
    const question = await (async () => {
      for (let i = 0; i < 100; i++) {
        const v = await invoke('get_view_model');
        if (v.manage.question) return v.manage.question;
        await sleep(100);
      }
      return null;
    })();
    const buttons = await waitFor(() => {
      const b = [...document.querySelectorAll('.alert .buttons button')];
      return b.length === 2 ? b : null;
    });
    if (!question || !buttons) return;
    const labels = {
      en: ['Use Own Fields', 'Use Shared Credential'],
      hu: ['Saját adatok használata', 'Közös hitelesítő adat használata'],
    }[vm.language];
    const ok =
      question.title.includes('vpn.example.com') &&
      question.title.includes('Smoke Import') &&
      document.querySelector('.alert h1')?.textContent === question.title &&
      buttons.map((b) => b.textContent.trim()).join('|') === labels.join('|') &&
      !document.querySelector('.alert [autofocus]');
    buttons[ok ? 1 : 0].click();
  }
})();
