<script lang="ts">
  // The Connections window (the Swift `ManageView`): the ranked list, the detail of the selection, the status
  // error banner, and the window's alerts – unsaved changes, saving failed, import report, the import's
  // credential question, other notices. A file dropped anywhere on the window is imported by the backend.
  import { onMount } from 'svelte';
  import { getCurrentWebview } from '@tauri-apps/api/webview';
  import { api, onImportReport, onViewModel, type Notice, type Report, type UnsavedChoice, type ViewModel } from '../api';
  import Icon from '../Icon.svelte';
  import { setLanguage, tr } from '../l10n.svelte';
  import './manage.css';
  import Detail from './Detail.svelte';
  import Modal from './Modal.svelte';
  import PairedApps from './PairedApps.svelte';
  import { flushActive } from './session.svelte';
  import Sidebar from './Sidebar.svelte';
  import SystemDetail from './SystemDetail.svelte';
  import { removedRow, shownRow } from './live';
  import type { Row } from '../api';

  let vm = $state<ViewModel | null>(null);
  let report = $state<Report | null>(null);
  let notice = $state<Notice | null>(null);
  let dropping = $state(false);
  let resolving = $state(false);
  /// The Paired apps section is shown (in place of a connection: the selection is cleared first).
  let showPaired = $state(false);

  const selected = $derived(vm?.manage.selected ?? null);
  /// The selected system VPN was removed from macOS: its last row stays shown (read-only).
  const removed = $derived(vm?.manage.selectedRemoved ?? false);
  /// The last row seen for the selection (what a removed VPN's detail keeps showing).
  let lastRow = $state<Row | null>(null);
  const listed = $derived(vm?.rows.find((r) => r.id === selected) ?? null);
  $effect(() => {
    if (listed) lastRow = listed;
  });
  const row = $derived.by(() => {
    const shown = shownRow(vm?.rows ?? [], selected, removed, lastRow);
    return shown && shown !== listed ? removedRow(shown) : shown;
  });

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
    showPaired = false;
    await api.selectConnection(id);
  }

  async function openPaired() {
    await flushActive();
    showPaired = true;
    // Through the unsaved-changes check, like any selection change.
    await api.selectConnection(null);
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
    paired={showPaired && !selected}
    pairedCount={vm?.control.clients.length ?? 0}
    onpaired={() => openPaired().catch(console.error)}
  />
  <main class="main">
    {#if vm?.statusError}
      <div class="status-error">
        <Icon name="warning" />
        <span>{vm.statusError}</span>
        <button onclick={() => api.openWindow('setup').catch(console.error)}>{tr('System Status')}</button>
      </div>
    {/if}
    {#if showPaired && !selected && vm}
      <PairedApps control={vm.control} rows={vm.rows} />
    {:else if row && row.managed && row.kind}
      {#key row.id}
        <Detail {row} manage={vm!.manage} filters={vm!.manage.logFilters} onnotice={showNotice} />
      {/key}
    {:else if row}
      {#key row.id}
        <SystemDetail {row} epoch={vm!.manage.editorsEpoch} selectedRemoved={removed} />
      {/key}
    {:else}
      <div class="empty">
        <span class="empty-icon"><Icon name="globe" /></span>
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
    inset: 6px;
    border: 2px dashed var(--accent);
    border-radius: var(--radius-panel);
    background: var(--accent-soft);
    pointer-events: none;
  }
  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    background: var(--background);
  }
  .status-error {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin: var(--space-5) var(--space-7) 0;
    padding: 8px 8px 8px 12px;
    border-radius: var(--radius-card);
    background: var(--state-busy-soft);
    font-size: var(--text-md);
  }
  .status-error :global(.icon) {
    width: 15px;
    height: 15px;
    color: var(--state-busy);
  }
  .status-error span {
    flex: 1;
  }
  .empty {
    margin: auto;
    padding: 28px 36px;
    max-width: 320px;
    text-align: center;
    color: var(--secondary);
    border: 1.5px dashed var(--border-strong);
    border-radius: 18px;
  }
  .empty-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 52px;
    height: 52px;
    border-radius: 50%;
    color: var(--accent);
    background: var(--accent-soft);
  }
  .empty-icon :global(.icon) {
    width: 26px;
    height: 26px;
  }
  .empty h1 {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--text);
    margin: 12px 0 4px;
  }
  .empty p {
    margin: 0;
  }
</style>
