<script lang="ts">
  // A managed connection's detail (the Swift `ConnectionDetailView`): the header with connect / debug / export /
  // delete, the failure or authentication line, and the Settings and Log tabs (both stay mounted, so switching
  // tab, or a forced switch to the Log, keeps the editing).
  import { untrack } from 'svelte';
  import { api, type Choice, type Kind, type LogFilter, type ManageView, type Notice, type Report, type Row } from '../api';
  import { tr } from '../l10n.svelte';
  import StatusDot from '../StatusDot.svelte';
  import EditorHost from './EditorHost.svelte';
  import LogPanel from './LogPanel.svelte';
  import Modal from './Modal.svelte';

  let {
    row,
    manage,
    filters,
    onnotice,
  }: { row: Row; manage: ManageView; filters: Choice<LogFilter>[]; onnotice: (n: Notice) => void } = $props();

  const id = untrack(() => row.id);
  const kind = untrack(() => row.kind as Kind);
  const native = kind === 'l2tp' || kind === 'cisco';
  let tab = $state<'settings' | 'log'>('settings');
  let confirmDelete = $state(false);
  let exportWarning = $state<Report | null>(null);

  // One-time requests: the Settings tab after a failed save comes first, then the Log tab of a debug connect.
  $effect(() => {
    if (manage.settingsRequest === id || manage.logRequest === id) {
      untrack(() => {
        api.takeTabRequest(id).then((t) => {
          if (t) tab = t;
        }, console.error);
      });
    }
  });

  function toggle() {
    (row.switchOn ? api.disconnect(id) : api.connect(id, false)).catch(console.error);
  }

  async function startExport() {
    const warning = await api.exportCheck(id);
    if (warning) exportWarning = warning;
    else await exportNow(false);
  }

  async function exportNow(withKeys: boolean) {
    exportWarning = null;
    const failure = await api.exportConnection(id, withKeys);
    if (failure) onnotice(failure);
  }
</script>

<div class="detail">
  <div class="header">
    <StatusDot state={row.state} />
    <div class="title">
      <h1>{row.name}</h1>
      <span class="secondary">{row.typeLabel}</span>
    </div>
    <span class="spacer"></span>
    <button onclick={toggle} disabled={!row.available || row.state === 'disconnecting'}>
      {row.switchOn ? tr('Disconnect') : tr('Connect')}
    </button>
    <button onclick={() => api.connect(id, true).catch(console.error)} disabled={row.switchOn || !row.available}>
      {tr('Connect in Debug Mode')}
    </button>
    <button class="icon" title={tr('Export… (passwords are never included)')} aria-label={tr('Export… (passwords are never included)')} onclick={() => startExport().catch(console.error)}>
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1l3 3-.9.9L8.6 3.4V10H7.4V3.4L5.9 4.9 5 4zM3 7h2.5v1.2H4.2v5.6h7.6V8.2h-1.3V7H13v8H3z" fill="currentColor" /></svg>
    </button>
    <button class="icon destructive" title={tr('Delete')} aria-label={tr('Delete')} onclick={() => (confirmDelete = true)}>
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1h4l.5 1H14v1.2H2V2h3.5zM3.2 4.4h9.6l-.7 10.6H3.9zm2.3 1.4l.3 7.8h1.1L6.6 5.8zm3.9 0l-.3 7.8h1.1l.3-7.8z" fill="currentColor" /></svg>
    </button>
  </div>
  {#if row.state === 'failed'}
    <p class="banner error">{row.reason}</p>
  {:else if row.state === 'awaitingAuth'}
    <p class="banner warn">{tr('Waiting for authentication')}</p>
  {/if}
  <div class="tabs segmented" role="tablist">
    <button role="tab" aria-selected={tab === 'settings'} class:on={tab === 'settings'} onclick={() => (tab = 'settings')}>
      {tr('Settings')}
    </button>
    <button role="tab" aria-selected={tab === 'log'} class:on={tab === 'log'} onclick={() => (tab = 'log')}>{tr('Log')}</button>
  </div>
  <div class="panes">
    <div class="pane" class:hidden={tab !== 'settings'} aria-hidden={tab !== 'settings'}>
      <EditorHost {id} {kind} active={tab === 'settings'} epoch={manage.editorsEpoch} />
    </div>
    <div class="pane" class:hidden={tab !== 'log'} aria-hidden={tab !== 'log'}>
      <LogPanel {id} {filters} {onnotice} />
    </div>
  </div>
</div>

{#if confirmDelete}
  <Modal
    title={tr('Delete %@?', row.name)}
    message={native
      ? tr('You have to remove the installed profile yourself in the Profiles pane that opens.')
      : tr('The config and the saved passwords will be deleted.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (confirmDelete = false) },
      {
        label: tr('Delete'),
        kind: 'destructive',
        action: () => {
          confirmDelete = false;
          api.deleteConnection(id).catch(console.error);
        },
      },
    ]}
  />
{/if}

{#if exportWarning}
  <Modal
    title={exportWarning.title}
    message={exportWarning.message}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (exportWarning = null) },
      { label: tr('Export With Keys'), action: () => exportNow(true).catch(console.error) },
      { label: tr('Export Without Keys'), kind: 'primary', action: () => exportNow(false).catch(console.error) },
    ]}
  />
{/if}

<style>
  .detail {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 16px;
  }
  .title {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  h1 {
    font-size: 15px;
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .banner {
    margin: 0 16px 8px;
  }
  .tabs {
    margin: 0 16px 8px;
    align-self: stretch;
  }
  .tabs button {
    flex: 1;
  }
  .panes {
    position: relative;
    flex: 1;
    min-height: 0;
    border-top: 1px solid var(--separator);
  }
  .pane {
    position: absolute;
    inset: 0;
    overflow: auto;
  }
  .pane.hidden {
    visibility: hidden;
    pointer-events: none;
  }
</style>
