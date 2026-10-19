<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    onViewModel,
    type Notice,
    type QuitChoice,
    type Row,
    type ViewModel,
    type WindowName,
  } from './api';
  import { setLanguage, tr } from './l10n.svelte';
  import MenuRow from './MenuRow.svelte';

  let vm = $state<ViewModel | null>(null);
  let now = $state(Date.now());
  /// The active-connections question of a quit (not an update's: the Update window asks that).
  const askingQuit = $derived(vm?.quit?.step === 'activeConnections' && vm.quit.origin !== 'update');
  /// An alert's text (update check result, launch-at-login failure), shown in place of the menu.
  let notice = $state<Notice | null>(null);
  let busy = $state(false);
  let root: HTMLElement | undefined = $state();

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = [onViewModel(apply)];
    api.viewModel().then(apply, console.error);
    const timer = setInterval(() => (now = Date.now()), 1000);
    // The popover window follows the content's height.
    const observer = new ResizeObserver(() => {
      if (root) api.setMenuHeight(Math.ceil(root.getBoundingClientRect().height)).catch(console.error);
    });
    if (root) observer.observe(root);
    return () => {
      clearInterval(timer);
      observer.disconnect();
      for (const u of unlisten) u.then((f) => f());
    };
  });

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
      <div class="buttons">
        <button class="primary" disabled={busy} onclick={() => answer('disconnectAndQuit')}>{tr('Disconnect and Quit')}</button>
        <button disabled={busy} onclick={() => answer('keepRunning')}>{tr('Quit, Keep Them Running')}</button>
        <button disabled={busy} onclick={() => answer('cancel')}>{tr('Cancel')}</button>
      </div>
    </section>
  {:else}
    {#if vm?.statusError}
      <button class="status-error" title={tr('Open System Status')} onclick={() => open('setup')}>
        <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5l7 12.5H1z M7.3 6v4.2h1.4V6z M7.3 11.2v1.4h1.4v-1.4z" fill="currentColor" fill-rule="evenodd" /></svg>
        <span>{vm.statusError}</span>
      </button>
      <hr />
    {/if}
    {#if vm && vm.rows.length === 0}
      <p class="empty">{tr('No connections yet')}</p>
    {/if}
    {#each vm?.rows ?? [] as row (row.id)}
      <MenuRow {row} {now} onToggle={toggle} />
    {/each}
    <hr />
    {#if vm?.update.available}
      <button class="item accent" onclick={() => open('update')}>{tr('Update available: %@', vm.update.available)}</button>
    {/if}
    <button class="item" onclick={() => open('manage')}>{tr('New Connection / Import…')}</button>
    <button class="item" onclick={() => open('manage')}>{tr('Manage Connections…')}</button>
    <button class="item" onclick={() => open('setup')}>
      {tr('System Status')}
      {#if vm && !vm.setupComplete}<span class="warn" aria-hidden="true">!</span>{/if}
    </button>
    <button class="item" onclick={() => api.openUserGuide().catch(console.error)}>{tr('Help')}</button>
    {#if vm?.update.enabled}
      <button class="item" disabled={vm.update.checking} onclick={() => checkNow().catch(console.error)}>
        {vm.update.checking ? tr('Checking for Updates…') : tr('Check for Updates Now')}
      </button>
      <label class="check">
        <input type="checkbox" checked={vm.update.autoCheck} onchange={(e) => setUpdateOption('autoCheck', e)} />
        {tr('Check for Updates Automatically')}
      </label>
      <label class="check">
        <input type="checkbox" checked={vm.update.delayUpdates} onchange={(e) => setUpdateOption('delayUpdates', e)} />
        {tr('Only Offer Updates Published at Least 24 Hours Ago')}
      </label>
    {/if}
    {#if vm?.loginItem}
      <label class="check">
        <input
          type="checkbox"
          checked={vm.loginItem.isOn}
          disabled={!vm.loginItem.canToggle}
          onchange={(e) => setLaunchAtLogin(e).catch(console.error)}
        />
        {tr('Launch at Login')}
      </label>
      {#if vm.loginItem.note}
        <p class="note">{vm.loginItem.note}</p>
      {/if}
      {#if vm.loginItem.showsOpenSettings}
        <button class="small" onclick={() => api.openLoginItemsSettings().catch(console.error)}>{tr('Open Login Items Settings…')}</button>
      {/if}
    {/if}
    <button class="item" onclick={quit}>{tr('Quit MacVPN')}</button>
    <p class="hint">{tr('Option-click a switch: debug mode')}</p>
  {/if}
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px;
  }
  hr {
    border: none;
    border-top: 1px solid var(--separator);
    margin: 4px 0;
    width: 100%;
  }
  .empty {
    color: var(--secondary);
    padding: 8px;
    margin: 0;
  }
  .item,
  .status-error {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    text-align: left;
    padding: 4px 8px;
    border: none;
    border-radius: 5px;
    background: transparent;
    color: inherit;
    font: inherit;
  }
  .item:hover,
  .item:focus-visible {
    background: var(--hover);
    outline: none;
  }
  .status-error {
    font-size: 11px;
    color: var(--orange);
  }
  .status-error svg {
    width: 12px;
    height: 12px;
    flex: none;
  }
  .status-error span {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .item:disabled {
    opacity: 0.5;
  }
  .accent {
    color: var(--accent);
  }
  .check {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    padding: 2px 8px;
    font-size: 12px;
  }
  .check input {
    margin: 2px 0 0;
    flex: none;
  }
  .note {
    margin: 0 8px 2px 28px;
    font-size: 11px;
    color: var(--secondary);
  }
  .small {
    align-self: flex-start;
    margin: 0 0 4px 28px;
    padding: 2px 8px;
    font: inherit;
    font-size: 11px;
    border-radius: 5px;
    border: 1px solid var(--separator);
    background: var(--button);
    color: inherit;
  }
  .message {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .warn {
    color: var(--orange);
    font-weight: 700;
  }
  .hint {
    margin: 2px 8px 0;
    font-size: 10px;
    color: var(--tertiary);
  }
  .question {
    padding: 8px;
  }
  .question h1 {
    font-size: 13px;
    margin: 0 0 4px;
  }
  .question p {
    margin: 0 0 10px;
    color: var(--secondary);
  }
  .buttons {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .buttons button {
    padding: 4px 10px;
    border-radius: 5px;
    border: 1px solid var(--separator);
    background: var(--button);
    color: inherit;
    font: inherit;
  }
  .buttons .primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }
</style>
