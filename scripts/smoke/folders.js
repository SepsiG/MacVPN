// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window,
// after live.js. Folders and colours through the real UI (the sandbox keeps them in memory): "New Folder" from the
// New menu (named in place: the default name in the window's language), a subfolder from the folder's context
// menu, a colour from the picker (the subfolder inherits it), a seeded connection dragged into the subfolder, the
// folder collapsed (its rows hidden), and the subfolder deleted with "move its contents up" (the default), which
// puts the connection into the parent folder. Writes the result into the seeded connection's name (`FOLDERS …`).
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
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
  const ID = 'E1111111-2222-4333-8444-555555555555';
  const tree = async () => (await invoke('get_view_model')).tree;
  const folderNamed = async (name) => (await tree()).find((r) => r.type === 'folder' && r.name === name);
  const rowOf = (id) => document.querySelector(`nav [data-tree-row][data-id="${id}"]`);
  const buttonOf = (id) => rowOf(id)?.querySelector('button');
  const contextMenu = (id) => {
    const b = buttonOf(id);
    const r = b.getBoundingClientRect();
    b.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: r.left + 40, clientY: r.top + r.height / 2 }));
  };
  const action = (name) => waitFor(() => document.querySelector(`.menu [data-action="${name}"]`));
  /// Types a name into the in-place rename field and confirms it with Return.
  const rename = async (name) => {
    const input = await waitFor(() => document.querySelector('input.rename'));
    if (!input) return null;
    const initial = input.value;
    input.value = name;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    return initial;
  };
  const checks = {};
  try {
    const vm = await invoke('get_view_model');
    checks.enabled = vm.foldersEnabled === true;
    const defaultName = { en: 'New Folder', hu: 'Új mappa' }[vm.language];
    // Create: the New menu's "New Folder", named in place.
    document.querySelector('nav .toolbar .new').click();
    (await action('new-folder')).click();
    checks.defaultName = (await rename('SMOKE Work')) === defaultName;
    const work = await waitFor(() => folderNamed('SMOKE Work'));
    checks.created = !!work && work.depth === 0;
    // Nest: "New Folder" in the folder's context menu.
    await waitFor(() => buttonOf(work.id));
    contextMenu(work.id);
    (await action('new-folder')).click();
    await rename('SMOKE Clients');
    const clients = await waitFor(() => folderNamed('SMOKE Clients'));
    checks.nested = !!clients && clients.parent === work.id && clients.depth === 1;
    // Colour: teal on the folder; the subfolder inherits it.
    contextMenu(work.id);
    (await action('colour')).click();
    (await waitFor(() => document.querySelector('.picker [data-color="teal"]'))).click();
    checks.colour = !!(await waitFor(async () => {
      const t = await tree();
      const w = t.find((r) => r.id === work.id);
      const c = t.find((r) => r.id === clients.id);
      return w?.color === 'teal' && w.colorSource === 'own' && c?.color === 'teal' && c.colorSource === 'inherited';
    }));
    // Drag: the seeded connection onto the subfolder.
    await waitFor(() => buttonOf(clients.id) && buttonOf(ID));
    const source = buttonOf(ID).getBoundingClientRect();
    const target = buttonOf(clients.id).getBoundingClientRect();
    buttonOf(ID).dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, button: 0, clientX: source.left + 30, clientY: source.top + source.height / 2 }));
    for (let i = 1; i <= 8; i++) {
      const x = source.left + 30 + ((target.left + 80 - source.left - 30) * i) / 8;
      const y = source.top + source.height / 2 + ((target.top + target.height / 2 - source.top - source.height / 2) * i) / 8;
      window.dispatchEvent(new PointerEvent('pointermove', { bubbles: true, clientX: x, clientY: y }));
      await sleep(40);
    }
    checks.dropIndicator = !!rowOf(clients.id)?.classList.contains('drop-into');
    window.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, clientX: target.left + 80, clientY: target.top + target.height / 2 }));
    checks.dragged = !!(await waitFor(async () => (await tree()).find((r) => r.id === ID)?.parent === clients.id));
    // The item shows the inherited colour.
    checks.itemColour = (await tree()).find((r) => r.id === ID)?.color === 'teal';
    // Collapse: a click on the folder row hides its contents (persisted for the menu).
    buttonOf(work.id).click();
    checks.collapsed = !!(await waitFor(async () => (await tree()).find((r) => r.id === work.id)?.collapsed === true));
    checks.hidden = !!(await waitFor(() => !rowOf(clients.id) && !rowOf(ID)));
    buttonOf(work.id).click();
    await waitFor(async () => (await tree()).find((r) => r.id === work.id)?.collapsed === false);
    // Delete the subfolder, moving its contents up (the dialog's default).
    await waitFor(() => buttonOf(clients.id));
    contextMenu(clients.id);
    (await action('delete')).click();
    const dialog = await waitFor(() => document.querySelector('.alert'));
    checks.defaultMoveUp = !!dialog?.querySelector('input[value="moveUp"]')?.checked;
    [...dialog.querySelectorAll('.buttons button')].find((b) => !b.classList.contains('cancel'))?.click();
    checks.deleted = !!(await waitFor(async () => {
      const t = await tree();
      return !t.some((r) => r.id === clients.id) && t.find((r) => r.id === ID)?.parent === work.id;
    }));
  } catch (e) {
    console.error(e);
    checks.error = false;
  }
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  const view = await invoke('editor_open', { id: 'E1111111-2222-4333-8444-555555555555' });
  await invoke('editor_save', {
    id: 'E1111111-2222-4333-8444-555555555555',
    fields: { ...view.fields, name: failed.length === 0 ? 'FOLDERS OK' : `FOLDERS FAILED ${failed.join(',')}` },
  });
})();
