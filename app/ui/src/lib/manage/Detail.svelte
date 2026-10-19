<script lang="ts">
  // A managed connection's detail (the Swift `ConnectionDetailView`): the header with connect / debug / export /
  // delete, the failure or authentication line, and the Settings and Log tabs (both stay mounted, so switching
  // tab, or a forced switch to the Log, keeps the editing).
  import { onMount, untrack } from 'svelte';
  import { api, type Choice, type Kind, type LogFilter, type ManageView, type Notice, type Report, type Row } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import { statusLine } from '../status';
  import TypeIcon from '../TypeIcon.svelte';
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
  let now = $state(Date.now());
  const line = $derived(statusLine(row, now));
  /// A failure or the wait for authentication has its own banner below the header.
  const headerStatus = $derived(row.state === 'failed' || row.state === 'awaitingAuth' ? null : line.status);

  onMount(() => {
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

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
    <TypeIcon kind={row.kind} state={row.state} size="lg" />
    <div class="title">
      <h1>{row.name}</h1>
      <span class="subtitle {line.tone}">
        <span class="secondary">{line.type}</span>{#if headerStatus}<span class="secondary dot" aria-hidden="true">·</span><span class="status">{headerStatus}</span>{/if}
      </span>
      {#if row.heldBy.length > 0}<span class="held">{tr('Held by %@', row.heldBy.join(', '))}</span>{/if}
    </div>
    <div class="actions">
      <button class:primary={!row.switchOn} onclick={toggle} disabled={!row.available || row.state === 'disconnecting'}>
        <Icon name={row.switchOn ? 'stop' : 'play'} />
        {row.switchOn ? tr('Disconnect') : tr('Connect')}
      </button>
      <button
        class="icon"
        title={tr('Connect in Debug Mode')}
        aria-label={tr('Connect in Debug Mode')}
        onclick={() => api.connect(id, true).catch(console.error)}
        disabled={row.switchOn || !row.available}
      >
        <Icon name="bug" />
      </button>
      <button class="icon" title={tr('Export… (passwords are never included)')} aria-label={tr('Export… (passwords are never included)')} onclick={() => startExport().catch(console.error)}>
        <Icon name="export" />
      </button>
      <button class="icon destructive" title={tr('Delete')} aria-label={tr('Delete')} onclick={() => (confirmDelete = true)}>
        <Icon name="trash" />
      </button>
    </div>
  </div>
  {#if row.state === 'failed'}
    <p class="banner error"><Icon name="warning" /><span>{row.reason}</span></p>
  {:else if row.state === 'awaitingAuth'}
    <p class="banner warn"><Icon name="key" /><span>{tr('Waiting for authentication')}</span></p>
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
    --badge-ring: var(--background);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-5);
    padding: 18px var(--space-7) 14px;
  }
  .title {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
    flex: 1 1 140px;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .held {
    align-self: flex-start;
    margin-top: 3px;
    padding: 1px 8px;
    border-radius: var(--radius-pill);
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--state-on-text);
    background: var(--state-on-soft);
  }
  .subtitle {
    font-size: var(--text-md);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dot {
    padding: 0 5px;
  }
  .status {
    font-weight: 500;
    font-variant-numeric: tabular-nums;
  }
  .on .status {
    color: var(--state-on-text);
  }
  .busy .status {
    color: var(--state-busy-text);
  }
  .fail .status {
    color: var(--state-fail-text);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex: none;
  }
  .actions button {
    flex: none;
  }
  .actions :global(svg.icon) {
    width: 12px;
    height: 12px;
  }
  .actions button.icon :global(svg.icon) {
    width: 15px;
    height: 15px;
  }
  .banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    margin: 0 var(--space-7) var(--space-5);
    padding: 8px 12px;
    border-radius: var(--radius-control);
    overflow-wrap: anywhere;
  }
  .banner :global(.icon) {
    margin-top: 1px;
    width: 14px;
    height: 14px;
  }
  .banner.error {
    background: var(--state-fail-soft);
  }
  .banner.warn {
    background: var(--state-busy-soft);
  }
  .tabs {
    align-self: flex-start;
    margin: 0 var(--space-7) var(--space-2);
    min-width: 240px;
  }
  .tabs button {
    flex: 1;
  }
  .panes {
    position: relative;
    flex: 1;
    min-height: 0;
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
