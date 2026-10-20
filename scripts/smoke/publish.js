// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window.
// Publishing a team catalog through the real UI (spec 7, plan Task 17); the smoke run's backend takes sandbox files
// in place of the save and open panels. The driver sets `window.__smokePublish` to the phase before each run and
// checks the backend afterwards (the published file, its mode, its versions, the admin keys):
//   keys     – the Publishing section (its title in the window's language): Generate Admin Key, Generate Backup
//              Admin Key; both fingerprints shown;
//   select   – Publish Catalog…: the folder __FOLDER__ ticked in the tree (its connection then ticked and locked);
//   review   – Next: the review with the counts (1 connection, 1 folder);
//   name     – Next, the name "Smoke Team", Publish…: version 1 and the team key shown once;
//   reveal   – the key read from the page, I Saved It (the key is gone from the page), the asked group retyped,
//              Done; the wizard's Done;
//   again    – Publish New Version… on the publication: its review, Publish…, Done (version 2);
//   rotate   – Rotate Team Key…: the revoke text, Review…, the review, Rotate and Save…, the new key once, retyped,
//              Done (version 3);
//   export   – Export Backup Key…: the password twice, "Remove the backup key from this Mac after export", Export…;
//   import   – Import Admin Key…: Choose File…, the password, Import.
// Anything wrong: the step is left undone, which the driver reports.
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
  const $ = (selector) => document.querySelector(selector);
  const click = async (selector, ms = 10000) => {
    const el = await waitFor(() => {
      const found = $(selector);
      return found && !found.disabled ? found : null;
    }, ms);
    el?.click();
    return !!el;
  };
  const say = (line) => console.log(`MacVPN smoke publish: ${line}`);
  const vm = await invoke('get_view_model');
  const phase = window.__smokePublish;
  const PASSWORD = 'smoke key file 4711';

  // The team key shown once: read it, I Saved It (gone from the page), retype the asked group, Done.
  const retype = async () => {
    const shown = await waitFor(() => $('[data-team-key]'), 30000);
    if (!shown) return false;
    const key = shown.textContent.trim();
    const groups = key.replace(/^TEAM-/, '').split('-');
    $('.team-key-reveal button.saved-it').click();
    const label = await waitFor(() => $('.team-key-reveal .form-row span'));
    if (!label || document.body.textContent.includes(key) || $('[data-team-key]')) return false;
    const index = Number.parseInt(/\d+/.exec(label.textContent)?.[0] ?? '0', 10) - 1;
    setValue($('.team-key-reveal input[data-field=group]'), groups[index] ?? '');
    return (await click('.team-key-reveal button.confirm-group', 3000)) && !!(await waitFor(() => !$('.team-key-reveal')));
  };

  if (phase === 'keys') {
    const title = { en: 'Publishing', hu: 'Közzététel' }[vm.language];
    $('nav .link-publishing').click();
    const h1 = await waitFor(() => $('.publishing h1'));
    if (!h1 || h1.textContent.trim() !== title) return;
    if (!(await click('.publishing button.generate-primary'))) return;
    if (!(await click('.publishing button.generate-backup'))) return;
    await waitFor(() => document.querySelectorAll('.publishing [data-fingerprint]').length === 2);
  } else if (phase === 'select') {
    if (!(await click('.publishing button.publish-new'))) return;
    const box = await waitFor(() => $('input[data-pick="__FOLDER__"]'));
    if (!box) return;
    box.click();
    await waitFor(() => [...document.querySelectorAll('.tree input[type=checkbox]')].filter((b) => b.disabled && b.checked).length > 0);
  } else if (phase === 'review') {
    if (!(await click('.wizard button.next'))) return;
    await waitFor(() => $('.wizard .counts'), 15000);
  } else if (phase === 'name') {
    if (!(await click('.wizard button.next'))) return;
    const name = await waitFor(() => $('.wizard input.catalog-name'));
    if (!name) return;
    setValue(name, 'Smoke Team');
    if (!(await click('.wizard button.next'))) return;
    await waitFor(() => $('[data-team-key]'), 30000);
  } else if (phase === 'reveal') {
    if (!(await retype())) return say('reveal failed');
    await click('.wizard button.finish');
  } else if (phase === 'again') {
    if (!(await click('.publication button.again'))) return;
    await waitFor(() => $('.wizard .counts'), 15000);
    if (!(await click('.wizard button.next'))) return;
    await waitFor(() => $('.wizard .result'), 30000);
    await click('.wizard button.finish');
  } else if (phase === 'rotate') {
    if (!(await click('.publication button.rotate'))) return;
    const dialog = await waitFor(() => $('.alert[role=alertdialog]'));
    if (!dialog || !/revoke|visszavond/.test(dialog.textContent)) return;
    dialog.querySelector('button.primary').click();
    await waitFor(() => $('.wizard .revoke') && $('.wizard .counts'), 15000);
    if (!(await click('.wizard button.next'))) return;
    if (!(await retype())) return say('rotate reveal failed');
    await click('.wizard button.finish');
  } else if (phase === 'export') {
    if (!(await click('.publishing button.export-key'))) return;
    const pw = await waitFor(() => $('input[data-field=key-password]'));
    if (!pw) return;
    setValue(pw, PASSWORD);
    setValue($('input[data-field=key-repeat]'), PASSWORD);
    $('input.remove-after').click();
    await sleep(100);
    $('.alert button.primary').click();
    await waitFor(() => !$('input[data-field=key-password]'), 60000);
  } else if (phase === 'import') {
    if (!(await click('.publishing button.import-key'))) return;
    if (!(await click('.alert button.choose-key-file'))) return;
    if (!(await waitFor(() => $('.alert .file-name')))) return;
    setValue($('input[data-field=import-password]'), PASSWORD);
    $('.alert button.primary').click();
    await waitFor(() => !$('input[data-field=import-password]'), 60000);
  }
})();
