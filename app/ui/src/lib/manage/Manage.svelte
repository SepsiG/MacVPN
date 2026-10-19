<script lang="ts">
  // The Connections window (the Swift `ManageView`): the ranked list, the detail of the selection, the status
  // error banner, and the window's alerts – unsaved changes, saving failed, import report, the import's
  // credential question, other notices. A file dropped anywhere on the window is imported by the backend.
  import { onMount } from 'svelte';
  import { getCurrentWebview } from '@tauri-apps/api/webview';
  import { api, onImportReport, onViewModel, type Notice, type Report, type UnsavedChoice, type ViewModel } from '../api';
  import { setLanguage, tr } from '../l10n.svelte';
  import './manage.css';
  import Detail from './Detail.svelte';
  import Modal from './Modal.svelte';
  import { flushActive } from './session.svelte';
  import Sidebar from './Sidebar.svelte';
  import SystemDetail from './SystemDetail.svelte';

  let vm = $state<ViewModel | null>(null);
  let report = $state<Report | null>(null);
  let notice = $state<Notice | null>(null);
  let dropping = $state(false);
  let resolving = $state(false);

  const selected = $derived(vm?.manage.selected ?? null);
  const row = $derived(vm?.rows.find((r) => r.id === selected) ?? null);

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = [
      onViewModel(apply),
      onImportReport((r) => (report = r)),
      getCurrentWebview().onDragDropEvent((event) => {
        dropping = event.payload.type === 'enter' || event.payload.type === 'over';
      }),
    ];
    api.viewModel().then(apply, console.error);
    return () => {
      for (const u of unlisten) u.then((f) => f());
    };
  });

  // No managed connection shown: no log is followed.
  $effect(() => {
    if (vm && !(row && row.managed)) api.logSubscribe(null).catch(console.error);
  });

  async function select(id: string) {
    await flushActive();
    await api.selectConnection(id);
  }

  async function importFiles() {
    const result = await api.importFiles();
    if (result) report = result;
  }

  async function resolve(choice: UnsavedChoice) {
    if (resolving) return;
    resolving = true;
    try {
      await flushActive();
      const failure = await api.resolveUnsaved(choice);
      if (failure) notice = failure;
    } finally {
      resolving = false;
    }
  }

  function showNotice(n: Notice) {
    notice = n;
  }
</script>

<div class="manage" class:dropping>
  <Sidebar
    rows={vm?.rows ?? []}
    {selected}
    kinds={vm?.manage.kinds ?? []}
    onselect={(id) => select(id).catch(console.error)}
    onimport={() => importFiles().catch(console.error)}
  />
  <main class="main">
    {#if vm?.statusError}
      <div class="status-error">
        <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5l7 12.5H1z M7.3 6v4.2h1.4V6z M7.3 11.2v1.4h1.4v-1.4z" fill="currentColor" fill-rule="evenodd" /></svg>
        <span>{vm.statusError}</span>
        <button onclick={() => api.openWindow('setup').catch(console.error)}>{tr('System Status')}</button>
      </div>
    {/if}
    {#if row && row.managed && row.kind}
      {#key row.id}
        <Detail {row} manage={vm!.manage} filters={vm!.manage.logFilters} onnotice={showNotice} />
      {/key}
    {:else if row}
      {#key row.id}
        <SystemDetail {row} epoch={vm!.manage.editorsEpoch} />
      {/key}
    {:else}
      <div class="empty">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 1.6c1 0 2.2 1.6 2.9 4.4H9.1C9.8 5.2 11 3.6 12 3.6zM8.6 4.3C8.1 5.3 7.7 6.6 7.5 8H4.6a8.4 8.4 0 014-3.7zm6.8 0a8.4 8.4 0 014 3.7h-2.9c-.2-1.4-.6-2.7-1.1-3.7zM3.9 9.6h3.4a20 20 0 000 4.8H3.9a8.4 8.4 0 010-4.8zm5 0h6.2a18 18 0 010 4.8H8.9a18 18 0 010-4.8zm7.8 0h3.4a8.4 8.4 0 010 4.8h-3.4a20 20 0 000-4.8zM4.6 16h2.9c.2 1.4.6 2.7 1.1 3.7a8.4 8.4 0 01-4-3.7zm4.5 0h5.8c-.7 2.8-1.9 4.4-2.9 4.4S9.8 18.8 9.1 16zm7.4 0h2.9a8.4 8.4 0 01-4 3.7c.5-1 .9-2.3 1.1-3.7z" fill="currentColor" /></svg>
        <h1>{tr('Select a Connection')}</h1>
        <p>{tr('Or drop an .ovpn / .conf / .sstp file here.')}</p>
      </div>
    {/if}
  </main>
</div>

{#if vm?.manage.pending}
  <Modal
    title={tr('Unsaved Changes')}
    message={tr('The edited settings have not been saved yet.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => resolve('cancel').catch(console.error) },
      { label: tr('Discard'), kind: 'destructive', action: () => resolve('discard').catch(console.error) },
      { label: tr('Save'), kind: 'primary', action: () => resolve('save').catch(console.error) },
    ]}
  />
{:else if vm?.manage.question}
  {@const q = vm.manage.question}
  <Modal
    title={q.title}
    message={q.message}
    buttons={[
      { label: q.no, action: () => api.answerQuestion(q.id, false).catch(console.error) },
      { label: q.yes, kind: 'primary', action: () => api.answerQuestion(q.id, true).catch(console.error) },
    ]}
  />
{:else if notice}
  <Modal title={notice.title} message={notice.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (notice = null) }]} />
{:else if report}
  <Modal title={report.title} message={report.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (report = null) }]} />
{/if}

<style>
  .manage {
    display: grid;
    grid-template-columns: minmax(220px, 250px) 1fr;
    height: 100vh;
  }
  .manage.dropping::after {
    content: '';
    position: fixed;
    inset: 4px;
    border: 3px solid var(--accent);
    border-radius: 8px;
    pointer-events: none;
  }
  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }
  .status-error {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px;
    background: rgba(255, 149, 0, 0.12);
    font-size: 12px;
  }
  .status-error svg {
    width: 14px;
    height: 14px;
    flex: none;
    color: var(--orange);
  }
  .status-error span {
    flex: 1;
  }
  .empty {
    margin: auto;
    text-align: center;
    color: var(--secondary);
  }
  .empty svg {
    width: 40px;
    height: 40px;
  }
  .empty h1 {
    font-size: 17px;
    color: var(--text);
    margin: 8px 0 4px;
  }
  .empty p {
    margin: 0;
  }
</style>
