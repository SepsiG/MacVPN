<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    onViewModel,
    type FolderTreeRow,
    type Notice,
    type QuitChoice,
    type Row,
    type VaultWindowName,
    type ViewModel,
    type WindowName,
  } from './api';
  import { i18n, setLanguage, tr } from './l10n.svelte';
  import Icon from './Icon.svelte';
  import MenuRow from './MenuRow.svelte';
  import FolderRow from './folders/FolderRow.svelte';
  import { indentLevel, treeOf, visibleRows } from './folders/tree';
  import { versionLabel } from './format';
  import LockedMenu from './vault/LockedMenu.svelte';
  import { backupApi } from './vault/backupApi';
  import { isTeamRoot } from './catalog/status';
  import { browserDeps, pollTraffic, type TrafficMap } from './traffic';

  let vm = $state<ViewModel | null>(null);
  let now = $state(Date.now());
  /// The connected rows' live traffic (read while the popover is shown).
  let traffic = $state<TrafficMap>({});
  /// The active-connections question of a quit (not an update's: the Update window asks that).
  const askingQuit = $derived(vm?.quit?.step === 'activeConnections' && vm.quit.origin !== 'update');
  /// An alert's text (update check result, launch-at-login failure), shown in place of the menu.
  let notice = $state<Notice | null>(null);
  let busy = $state(false);
  let root: HTMLElement | undefined = $state();
  let list: HTMLElement | undefined = $state();
  /// The connection list's height limit: what the screen (and the backend's bound) leaves next to the rest.
  let listMax = $state<number | null>(null);
  /// The list scrolls (its scroll bar then takes the right margin).
  let scrollable = $state(false);
  let settingsOpen = $state(false);
  const unlocked = $derived(vm?.vault.state === 'unlocked');
  const hasSettings = $derived(!!vm && (vm.update.enabled || vm.loginItem !== null || !!vm.appearance || vm.connectionNotifications !== undefined || unlocked || vm.backupAvailable));
  /// The vault is locked or not set up yet: the menu shows no connection (the backend sends none either).
  const vaultClosed = $derived(vm?.vault.state === 'locked' || vm?.vault.state === 'notCreated');
  /// "Unlock Automatically" is being turned off: the menu asks first.
  let confirmAutoUnlockOff = $state(false);
  /// The folder tree (spec 3); collapsed folders hide their contents. A toggle shows at once, then the backend
  /// persists it.
  let collapsedNow = $state<Record<string, boolean>>({});
  const isCollapsed = (f: FolderTreeRow) => collapsedNow[f.id] ?? f.collapsed;
  const tree = $derived(vm ? treeOf(vm) : []);
  const entries = $derived(visibleRows(tree, isCollapsed));
  const rowById = $derived(new Map((vm?.rows ?? []).map((r) => [r.id, r])));

  function toggleFolder(folder: FolderTreeRow) {
    const collapsed = !isCollapsed(folder);
    collapsedNow = { ...collapsedNow, [folder.id]: collapsed };
    api.folderSetCollapsed(folder.id, collapsed).catch(console.error);
  }

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
    // The backend caught up with the toggles.
    const settled = Object.keys(collapsedNow).filter((id) => (next.tree ?? []).some((r) => r.type === 'folder' && r.id === id && r.collapsed === collapsedNow[id]));
    if (settled.length > 0) {
      const rest = { ...collapsedNow };
      for (const id of settled) delete rest[id];
      collapsedNow = rest;
    }
  }

  onMount(() => {
    const unlisten = [onViewModel(apply)];
    api.viewModel().then(apply, console.error);
    const timer = setInterval(() => (now = Date.now()), 1000);
    const stopTraffic = pollTraffic(
      () => !!vm?.rows.some((r) => r.state === 'connected'),
      (t) => (traffic = t),
      browserDeps(api.traffic),
    );
    // The popover window follows the content's height; many connections scroll inside the list instead.
    const observer = new ResizeObserver(measure);
    if (root) observer.observe(root);
    return () => {
      clearInterval(timer);
      stopTraffic();
      observer.disconnect();
      for (const u of unlisten) u.then((f) => f());
    };
  });

  /// The backend accepts 40…900 points; the list gets what the screen leaves (at least a few cards).
  const MAX_HEIGHT = 900;

  function measure() {
    if (!root) return;
    const total = root.getBoundingClientRect().height;
    if (list) {
      const others = total - list.getBoundingClientRect().height;
      const limit = Math.min(MAX_HEIGHT, (window.screen?.availHeight || MAX_HEIGHT) - 40);
      const next = Math.max(150, Math.floor(limit - others));
      if (next !== listMax) listMax = next;
      scrollable = list.scrollHeight > list.clientHeight + 1;
    }
    api.setMenuHeight(Math.max(40, Math.min(MAX_HEIGHT, Math.ceil(total)))).catch(console.error);
  }

  function toggle(row: Row, debug: boolean) {
    const action = row.switchOn ? api.disconnect(row.id) : api.connect(row.id, debug);
    action.catch(console.error);
  }

  function open(name: WindowName) {
    api.openWindow(name).catch(console.error);
  }

  async function checkNow() {
    const result = await api.checkForUpdates();
    if (result.result === 'available') open('update');
    else notice = { title: result.title, message: result.message };
  }

  function setUpdateOption(option: 'autoCheck' | 'delayUpdates', event: Event) {
    api.setUpdateOption(option, (event.currentTarget as HTMLInputElement).checked).catch(console.error);
  }

  async function setLaunchAtLogin(event: Event) {
    const failure = await api.setLaunchAtLogin((event.currentTarget as HTMLInputElement).checked);
    if (failure) notice = failure;
  }

  async function quit() {
    await api.quit(null);
  }

  function showVault(window: VaultWindowName) {
    api.vaultShow(window).catch(console.error);
  }

  /// The switch shows the backend's state: on opens the password confirmation, off asks first.
  function setAutoUnlock(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const on = input.checked;
    input.checked = !on;
    if (on) showVault('confirmPassword');
    else confirmAutoUnlockOff = true;
  }

  async function autoUnlockOff() {
    confirmAutoUnlockOff = false;
    try {
      await api.vaultAutoUnlockOff();
    } catch (e) {
      notice = { title: tr('Unlock automatically'), message: String(e) };
    }
  }

  async function answer(choice: QuitChoice) {
    busy = choice === 'disconnectAndQuit';
    try {
      await api.quit(choice);
    } finally {
      busy = false;
    }
  }
</script>

<main bind:this={root}>
  {#if notice}
    <section class="question" aria-live="polite">
      <h1>{notice.title}</h1>
      <p class="message">{notice.message}</p>
      <div class="buttons">
        <button class="primary" onclick={() => (notice = null)}>{tr('OK')}</button>
      </div>
    </section>
  {:else if askingQuit}
    <section class="question" aria-live="polite">
      <h1>{tr('There are active VPN connections')}</h1>
      <p>{tr('Disconnect them before quitting?')}</p>
      {#if vm?.quitNote}<p class="note">{vm.quitNote}</p>{/if}
      <div class="buttons">
        <button class="primary" disabled={busy} onclick={() => answer('disconnectAndQuit')}>{tr('Disconnect and Quit')}</button>
        <button disabled={busy} onclick={() => answer('keepRunning')}>{tr('Quit, Keep Them Running')}</button>
        <button disabled={busy} onclick={() => answer('cancel')}>{tr('Cancel')}</button>
      </div>
    </section>
  {:else if confirmAutoUnlockOff}
    <section class="question" aria-live="polite">
      <h1>{tr('Turn off automatic unlock?')}</h1>
      <p>{tr('MacVPN will ask for the master password at every launch.')}</p>
      <div class="buttons">
        <button class="primary" onclick={() => autoUnlockOff().catch(console.error)}>{tr('Turn Off')}</button>
        <button onclick={() => (confirmAutoUnlockOff = false)}>{tr('Cancel')}</button>
      </div>
    </section>
  {:else if vm && vaultClosed}
    <LockedMenu
      vault={vm.vault}
      version={versionLabel(vm.appVersion, i18n.platform.product)}
      onunlock={() => showVault(vm?.vault.state === 'notCreated' ? 'create' : 'unlock')}
      onquit={() => quit().catch(console.error)}
    />
  {:else}
    {#if vm?.vault.state === 'legacyReadOnly'}
      <button class="banner update legacy" onclick={() => showVault('create')}>
        <Icon name="lock" />
        <span class="banner-text">{vm.vault.legacyError ? tr('The move into the vault did not finish. Try again…') : tr('Finish setting up the vault…')}</span>
        <Icon name="chevron" class="chevron" />
      </button>
    {/if}
    {#if vm?.statusError}
      <button class="banner status-error" title={tr('Open System Status')} onclick={() => open('setup')}>
        <Icon name="warning" />
        <span class="banner-text">{vm.statusError}</span>
        <Icon name="chevron" class="chevron" />
      </button>
    {/if}
    <div class="list" class:scrollable bind:this={list} style:max-height={listMax === null ? null : `${listMax}px`}>
      {#if vm && tree.length === 0}
        <div class="empty">
          <Icon name="globe" />
          <p>{tr('No connections yet')}</p>
        </div>
      {/if}
      {#each entries as entry (entry.id)}
        {#if entry.type === 'folder'}
          <div class="indent" style:--level={indentLevel(entry.depth)}>
            <FolderRow folder={entry} collapsed={isCollapsed(entry)} team={isTeamRoot(vm?.teamFolders, entry)} ontoggle={() => toggleFolder(entry)} />
          </div>
        {:else if rowById.get(entry.id)}
          <div class="indent" style:--level={indentLevel(entry.depth)}>
            <MenuRow row={rowById.get(entry.id)!} {now} onToggle={toggle} color={entry.color} traffic={traffic[entry.id] ?? null} />
          </div>
        {/if}
      {/each}
    </div>
    {#if vm?.update.available}
      <button class="banner update" onclick={() => open('update')}>
        <Icon name="download" />
        <span class="banner-text">{tr('Update available: %@', vm.update.available)}</span>
        <Icon name="chevron" class="chevron" />
      </button>
    {/if}
    <div class="tiles">
      <button class="tile" onclick={() => open('manage')}>
        <span class="tile-icon new"><Icon name="plus" /></span>
        <span class="tile-label">{tr('New Connection / Import…')}</span>
      </button>
      <button class="tile" onclick={() => open('manage')}>
        <span class="tile-icon manage"><Icon name="list" /></span>
        <span class="tile-label">{tr('Manage Connections…')}</span>
      </button>
      <button class="tile" onclick={() => open('setup')}>
        <span class="tile-icon status">
          <Icon name="status" />
          {#if vm && !vm.setupComplete}<span class="warn" aria-hidden="true">!</span>{/if}
        </span>
        <span class="tile-label">{tr('System Status')}</span>
      </button>
    </div>
    {#if vm && hasSettings}
      <div class="group">
        <button class="disclosure" class:open={settingsOpen} aria-expanded={settingsOpen} aria-controls="menu-settings" onclick={() => (settingsOpen = !settingsOpen)}>
          <Icon name="gear" />
          <span class="disclosure-label">{tr('Settings')}</span>
          <Icon name="chevron" class="chevron" />
        </button>
        <div id="menu-settings" class="settings" hidden={!settingsOpen}>
          {#if vm.appearance}
            <div class="setting appearance">
              <span>{tr('Appearance')}</span>
              <div class="segmented small" role="radiogroup" aria-label={tr('Appearance')}>
                {#each [['system', tr('Match System')], ['light', tr('Light')], ['dark', tr('Dark')]] as [mode, label] (mode)}
                  <button
                    role="radio"
                    aria-checked={vm.appearance === mode}
                    class:on={vm.appearance === mode}
                    onclick={() => api.setAppearance(mode as 'system' | 'light' | 'dark').catch(console.error)}>{label}</button
                  >
                {/each}
              </div>
            </div>
          {/if}
          {#if vm.connectionNotifications !== undefined}
            <label class="setting">
              <span>{tr('Connection Notifications')}</span>
              <input
                type="checkbox"
                class="switch"
                role="switch"
                checked={vm.connectionNotifications}
                onchange={(e) => api.setConnectionNotifications((e.currentTarget as HTMLInputElement).checked).catch(console.error)}
              />
            </label>
          {/if}
          {#if vm.update.enabled}
            <label class="setting">
              <span>{tr('Check for Updates Automatically')}</span>
              <input type="checkbox" class="switch" role="switch" checked={vm.update.autoCheck} onchange={(e) => setUpdateOption('autoCheck', e)} />
            </label>
            <label class="setting">
              <span>{tr('Only Offer Updates Published at Least 24 Hours Ago')}</span>
              <input type="checkbox" class="switch" role="switch" checked={vm.update.delayUpdates} onchange={(e) => setUpdateOption('delayUpdates', e)} />
            </label>
            <button class="setting action" disabled={vm.update.checking} onclick={() => checkNow().catch(console.error)}>
              <span>{vm.update.checking ? tr('Checking for Updates…') : tr('Check for Updates Now')}</span>
              {#if vm.update.checking}<span class="spinner" aria-hidden="true"></span>{:else}<Icon name="refresh" />{/if}
            </button>
          {/if}
          {#if vm.loginItem}
            <label class="setting">
              <span>{tr('Launch at Login')}</span>
              <input
                type="checkbox"
                class="switch"
                role="switch"
                checked={vm.loginItem.isOn}
                disabled={!vm.loginItem.canToggle}
                onchange={(e) => setLaunchAtLogin(e).catch(console.error)}
              />
            </label>
            {#if vm.loginItem.note || vm.loginItem.showsOpenSettings}
              <div class="setting-extra">
                {#if vm.loginItem.note}
                  <p class="note">{vm.loginItem.note}</p>
                {/if}
                {#if vm.loginItem.showsOpenSettings}
                  <button class="small" onclick={() => api.openLoginItemsSettings().catch(console.error)}>{tr('Open Login Items Settings…')}</button>
                {/if}
              </div>
            {/if}
          {/if}
          <!-- The vault: unlocking, the master password and the recovery key, then the backup. -->
          {#if unlocked}
            <label class="setting">
              <span>{tr('Unlock automatically')}</span>
              <input type="checkbox" class="switch auto-unlock" role="switch" checked={vm.vault.autoUnlock} onchange={setAutoUnlock} />
            </label>
            <label class="setting">
              <span>{tr('Show “Lock Now”')}</span>
              <input
                type="checkbox"
                class="switch show-lock-now"
                role="switch"
                checked={vm.vault.showLockNowPref}
                onchange={(e) => api.vaultSetShowLockNow(e.currentTarget.checked).catch(console.error)}
              />
            </label>
            <button class="setting action change-password" onclick={() => showVault('changePassword')}>
              <span>{tr('Change Master Password…')}</span>
              <Icon name="lock" />
            </button>
            <button class="setting action new-recovery-key" onclick={() => showVault('newRecoveryKey')}>
              <span>{tr('New Recovery Key…')}</span>
              <Icon name="key" />
            </button>
          {/if}
          {#if vm.backupAvailable}
            <button class="setting action backup" onclick={() => backupApi.showWindow('backup').catch(console.error)}>
              <span>{tr('Back Up Everything…')}</span>
              <Icon name="download" />
            </button>
            <button class="setting action restore" onclick={() => backupApi.showWindow('restore').catch(console.error)}>
              <span>{tr('Restore from Backup…')}</span>
              <Icon name="refresh" />
            </button>
          {/if}
        </div>
      </div>
    {/if}
    <div class="footer">
      <button class="pill" onclick={() => api.openUserGuide().catch(console.error)}>
        <Icon name="help" />
        {tr('Help')}
      </button>
      <span class="spacer"></span>
      {#if vm?.vault.showLockNow}
        <button class="pill lock-now" onclick={() => api.vaultLockNow().catch(console.error)}>
          <Icon name="lock" />
          {tr('Lock Now')}
        </button>
      {/if}
      <button class="pill quit" onclick={quit}>
        <Icon name="power" />
        {tr('Quit MacVPN')}
      </button>
    </div>
    <p class="hint">{tr('Option-click a switch: debug mode')}</p>
    {#if vm}<p class="version">{versionLabel(vm.appVersion, i18n.platform.product)}</p>{/if}
  {/if}
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-4);
  }

  /* The connections. */
  .list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    /* Room for the cards' shadows when the list scrolls, and for a slim scroll bar in the right margin. */
    margin: -3px calc(-1 * var(--space-4)) -3px -3px;
    padding: 3px var(--space-4) 3px 3px;
    /* The measured max-height (listMax) includes this padding: otherwise a long list ends up 6 px taller than
       the height left for it and the window's 900 px cap clips the bottom (the version line's padding). */
    box-sizing: border-box;
    overflow-y: auto;
    overscroll-behavior: contain;
  }
  /* Nesting: indented, capped at three levels (deeper folders still work). */
  .indent {
    padding-left: calc(var(--level, 0) * 12px);
  }
  .list.scrollable {
    padding-right: calc(var(--space-4) - 8px);
  }
  .list::-webkit-scrollbar {
    width: 8px;
  }
  .list::-webkit-scrollbar-thumb {
    border: 2px solid transparent;
    border-radius: 4px;
    background: var(--fill-pressed) padding-box;
  }
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-6) var(--space-4);
    border-radius: var(--radius-card);
    border: 1px dashed var(--border-strong);
    color: var(--tertiary);
  }
  .empty :global(.icon) {
    width: 22px;
    height: 22px;
  }
  .empty p {
    margin: 0;
    color: var(--secondary);
  }

  /* The status error and the offered update. */
  .banner {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    padding: 8px 10px;
    border: none;
    border-radius: var(--radius-card);
    font: inherit;
    text-align: left;
    transition: background-color var(--duration) var(--ease);
  }
  .banner-text {
    flex: 1;
    min-width: 0;
  }
  .banner :global(.chevron) {
    width: 12px;
    height: 12px;
    opacity: 0.6;
  }
  .status-error {
    font-size: var(--text-sm);
    color: var(--text);
    background: var(--state-busy-soft);
  }
  .status-error > :global(.icon:first-child) {
    color: var(--state-busy);
  }
  .status-error .banner-text {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .status-error:hover {
    background: color-mix(in srgb, var(--state-busy) 22%, transparent);
  }
  .update {
    font-weight: 600;
    color: var(--accent-text);
    background: var(--accent-soft);
  }
  .update:hover {
    background: color-mix(in srgb, var(--accent) 18%, transparent);
  }
  .banner:active {
    filter: brightness(0.96);
  }

  /* The actions. */
  .tiles {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
  }
  .tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 5px;
    min-width: 0;
    padding: 9px 3px 8px;
    border: none;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    color: var(--text);
    font: inherit;
    transition:
      background-color var(--duration) var(--ease),
      transform var(--duration) var(--ease);
  }
  .tile:hover {
    background: var(--surface-hover);
  }
  .tile:active {
    background: var(--surface-pressed);
    transform: scale(0.97);
  }
  .tile:focus-visible {
    box-shadow: var(--focus-ring);
  }
  .tile-icon {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    border-radius: var(--radius-pill);
    color: var(--accent);
    background: var(--accent-soft);
  }
  .tile-icon.manage {
    color: var(--vpn-wireguard);
    background: color-mix(in srgb, var(--vpn-wireguard) 16%, transparent);
  }
  .tile-icon.status {
    color: var(--state-on-text);
    background: var(--state-on-soft);
  }
  .tile-icon :global(.icon) {
    width: 15px;
    height: 15px;
  }
  .tile-label {
    max-width: 100%;
    font-size: var(--text-sm);
    font-weight: 500;
    line-height: 13px;
    text-align: center;
    text-wrap: balance;
    overflow-wrap: anywhere;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .warn {
    position: absolute;
    top: -4px;
    right: -6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    border: 1.5px solid var(--surface);
    background: var(--state-busy);
    color: #fff;
    font-size: 9px;
    font-weight: 800;
    line-height: 1;
  }

  /* The settings. */
  .group {
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    overflow: hidden;
  }
  .disclosure {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    padding: 8px 10px;
    border: none;
    border-radius: var(--radius-card);
    background: transparent;
    color: var(--text);
    font: inherit;
    font-weight: 500;
    text-align: left;
  }
  .disclosure:hover {
    background: var(--fill-hover);
  }
  .disclosure > :global(.icon:first-child) {
    color: var(--secondary);
  }
  .disclosure-label {
    flex: 1;
  }
  .disclosure :global(.chevron) {
    width: 12px;
    height: 12px;
    color: var(--tertiary);
    transition: transform var(--duration) var(--ease);
  }
  .disclosure.open :global(.chevron) {
    transform: rotate(90deg);
  }
  .disclosure:focus-visible {
    box-shadow: inset 0 0 0 2px var(--focus-border);
  }
  .settings {
    padding: 0 10px 4px;
  }
  .settings[hidden] {
    display: none;
  }
  .setting {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    width: 100%;
    min-height: 34px;
    padding: 6px 0;
    border: none;
    border-top: 1px solid var(--separator);
    background: transparent;
    color: var(--text);
    font: inherit;
    font-size: var(--text-md);
    text-align: left;
    box-sizing: border-box;
  }
  .setting span {
    flex: 1;
  }
  .setting.action {
    color: var(--accent-text);
    font-weight: 500;
  }
  .setting.action:disabled {
    color: var(--secondary);
  }
  .setting.action:hover:not(:disabled) {
    color: var(--accent-hover);
  }
  .setting.action:focus-visible {
    box-shadow: none;
    text-decoration: underline;
  }
  /* The Appearance choice: the Connections window's segmented control (manage.css), smaller. */
  .segmented {
    display: inline-flex;
    gap: 2px;
    padding: 2px;
    border-radius: 9px;
    background: var(--surface-sunken);
  }
  .segmented button {
    min-height: 22px;
    padding: 2px 8px;
    border-radius: 7px;
    background: transparent;
    box-shadow: none;
    color: var(--secondary);
    font-size: var(--text-sm);
  }
  .segmented button:hover:not(:disabled):not(.on) {
    background: var(--fill-hover);
    color: var(--text);
  }
  .segmented button.on,
  .segmented button.on:hover:not(:disabled) {
    background: var(--segment-on);
    color: var(--text);
    box-shadow: var(--shadow-control);
  }
  .segmented button:focus-visible {
    box-shadow: var(--focus-ring);
  }
  .setting-extra {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
    padding: 0 0 8px;
  }
  .note {
    margin: 0;
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .small {
    padding: 3px 10px;
    font: inherit;
    font-size: var(--text-sm);
    border-radius: var(--radius-pill);
    border: none;
    background: var(--fill-hover);
    color: var(--text);
  }
  .small:hover {
    background: var(--fill-pressed);
  }
  .spinner {
    width: 12px;
    height: 12px;
    flex: none;
    border: 2px solid var(--separator);
    border-top-color: var(--secondary);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* Help, Quit and the hint. */
  .footer {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .spacer {
    flex: 1;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 11px 5px 9px;
    border: none;
    border-radius: var(--radius-pill);
    background: var(--fill-hover);
    color: var(--text);
    font: inherit;
    font-size: var(--text-md);
    font-weight: 500;
    transition: background-color var(--duration) var(--ease);
  }
  .pill :global(.icon) {
    width: 14px;
    height: 14px;
    color: var(--secondary);
  }
  .pill:hover {
    background: var(--fill-pressed);
  }
  .pill:active {
    filter: brightness(0.94);
  }
  .quit:hover {
    color: var(--state-fail-text);
  }
  .quit:hover :global(.icon) {
    color: var(--state-fail-text);
  }
  .hint {
    margin: -2px 0 0;
    font-size: var(--text-xs);
    color: var(--tertiary);
    text-align: center;
  }
  /* Right under the hint, as one quiet block (the column's gap would push it away). */
  .version {
    margin: calc(2px - var(--space-3)) 0 0;
    font-size: var(--text-xs);
    color: var(--tertiary);
    text-align: center;
    font-variant-numeric: tabular-nums;
    user-select: text;
  }

  /* An alert in place of the menu (a notice, the quit question). */
  .message {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .question {
    padding: 14px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .question h1 {
    font-size: var(--text-base);
    font-weight: 600;
    margin: 0 0 4px;
  }
  .question p {
    margin: 0 0 12px;
    color: var(--secondary);
  }
  .question p.note {
    margin-top: -6px;
    padding: 7px 9px;
    border-radius: var(--radius-control);
    background: var(--state-busy-soft);
    color: var(--text);
    font-size: var(--text-md);
  }
  .buttons {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .buttons button {
    padding: 6px 10px;
    border-radius: var(--radius-control);
    border: none;
    background: var(--fill-hover);
    color: var(--text);
    font: inherit;
    font-weight: 500;
    transition: background-color var(--duration) var(--ease);
  }
  .buttons button:hover:not(:disabled) {
    background: var(--fill-pressed);
  }
  .buttons button:disabled {
    opacity: 0.5;
  }
  .buttons .primary,
  .buttons .primary:hover:not(:disabled) {
    background: var(--accent);
    color: var(--on-accent);
  }
  .buttons .primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }
</style>
