<script lang="ts">
  // The Connections window's "Paired apps" section (the control API): the setting "Allow other apps to control
  // VPNs" (off by default; a start failure is shown under it), one card per paired app – its self-reported name, the
  // executable path it is pinned to, a "path changed" note after a hello from another copy, when it was paired and
  // last used, the connections it may use (editable), Revoke with a confirmation – and the recent activity, with
  // "Save…" for the audit log. While a change of an app is on its way its controls are disabled; a failed one is
  // undone and shown on the app's card.
  import { api, type ControlView, type Notice, type PairedApp, type Row } from '../api';
  import Icon from '../Icon.svelte';
  import { i18n, tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';

  let { control, rows }: { control: ControlView; rows: Row[] } = $props();

  let switching = $state(false);
  let revoking = $state<PairedApp | null>(null);
  /// The apps with a change on its way.
  let pending = $state<Record<string, boolean>>({});
  /// The last failed change per app (shown on its card).
  let failures = $state<Record<string, string>>({});
  let notice = $state<Notice | null>(null);

  function when(seconds: number): string {
    return new Date(seconds * 1000).toLocaleString(i18n.language === 'hu' ? 'hu-HU' : 'en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  }

  async function setEnabled(event: Event) {
    const on = (event.currentTarget as HTMLInputElement).checked;
    switching = true;
    try {
      await api.controlSetEnabled(on);
    } finally {
      switching = false;
    }
  }

  async function change(app: PairedApp, call: () => Promise<void>, failure: (e: unknown) => string, undo?: () => void) {
    pending[app.id] = true;
    delete failures[app.id];
    try {
      await call();
    } catch (e) {
      undo?.();
      failures[app.id] = failure(e);
    } finally {
      delete pending[app.id];
    }
  }

  function toggle(app: PairedApp, box: HTMLInputElement) {
    const on = box.checked;
    const keys = rows.map((r) => r.id).filter((id) => (id === box.value ? on : app.allowed.includes(id)));
    change(
      app,
      () => api.controlSetAllowed(app.id, keys),
      (e) => tr('Could not change the allowed connections: %@', String(e)),
      () => (box.checked = !on),
    ).catch(console.error);
  }

  async function revoke() {
    const app = revoking;
    revoking = null;
    if (app) await change(app, () => api.controlRevoke(app.id), (e) => tr('Could not revoke %@: %@', app.name, String(e)));
  }

  async function saveAudit() {
    const failure = await api.controlAuditSave();
    if (failure) notice = failure;
  }
</script>

<div class="paired">
  <header class="hero">
    <span class="hero-icon" aria-hidden="true"><Icon name="link" /></span>
    <div class="hero-text">
      <h1>{tr('Paired apps')}</h1>
      <p class="secondary">
        {tr('Programs on this Mac that you pair can list the connections you allow, and bring them up and down. They never see configurations or passwords.')}
      </p>
    </div>
  </header>

  <div class="card">
    <label class="toggle">
      <span>{tr('Allow other apps to control VPNs')}</span>
      <input
        type="checkbox"
        class="switch control-switch"
        role="switch"
        checked={control.enabled}
        disabled={switching}
        onchange={(e) => setEnabled(e).catch(console.error)}
      />
    </label>
    {#if control.error}
      <p class="warning control-error"><Icon name="warning" /><span>{control.error}</span></p>
    {/if}
  </div>

  {#each control.clients as app (app.id)}
    <div class="card app" data-client={app.id}>
      <div class="app-head">
        <span class="app-icon" aria-hidden="true">{app.name.slice(0, 1).toUpperCase()}</span>
        <div class="app-text">
          <strong class="app-name">{app.name}</strong>
          <span class="path">{app.executable}</span>
        </div>
        <button class="revoke" disabled={pending[app.id]} onclick={() => (revoking = app)}>{tr('Revoke')}</button>
      </div>
      {#if failures[app.id]}
        <p class="warning change-error"><Icon name="warning" /><span>{failures[app.id]}</span></p>
      {/if}
      {#if app.pathChanged}
        <p class="flag path-changed">
          <Icon name="warning" />
          <span><strong>{tr('Path changed')}</strong> · {tr('This app was started from another location: %@. Revoke it and pair it again to use the new copy.', app.pathChanged)}</span>
        </p>
      {/if}
      <p class="caption">
        {app.lastUsed !== null ? tr('Last used: %@', when(app.lastUsed)) : tr('Never used')}
        <span class="dot" aria-hidden="true">·</span>
        {tr('Paired: %@', when(app.created))}
      </p>
      <p class="caption heading">{tr('Allowed connections')}</p>
      <div class="allowed">
        {#each rows as row (row.id)}
          <label class="item">
            <input type="checkbox" value={row.id} checked={app.allowed.includes(row.id)} disabled={pending[app.id]} onchange={(e) => toggle(app, e.currentTarget)} />
            <span class="item-name">{row.name}</span>
            {#if row.heldBy.includes(app.name)}
              <span class="held">{tr('Held by %@', app.name)}</span>
            {/if}
          </label>
        {/each}
      </div>
    </div>
  {:else}
    <div class="card">
      <p class="caption none">{tr('No paired apps yet. An app asks for pairing while this is on.')}</p>
    </div>
  {/each}

  <details class="card activity">
    <summary>{tr('Activity')}</summary>
    {#if control.activity.length > 0}
      <pre class="lines">{control.activity.join('\n')}</pre>
    {:else}
      <p class="caption">{tr('No activity yet.')}</p>
    {/if}
    <div class="activity-actions">
      <button class="save-audit" onclick={() => saveAudit().catch(console.error)}><Icon name="save" />{tr('Save…')}</button>
    </div>
  </details>
</div>

{#if notice}
  <Modal title={notice.title} message={notice.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (notice = null) }]} />
{:else if revoking}
  <Modal
    title={tr('Revoke %@?', revoking.name)}
    message={tr('The app can no longer control VPNs, and its open sessions end now. Connections that only it brought up are disconnected.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (revoking = null) },
      { label: tr('Revoke'), kind: 'destructive', action: () => revoke().catch(console.error) },
    ]}
  />
{/if}

<style>
  .paired {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-7) var(--space-7) var(--space-8);
    height: 100%;
    box-sizing: border-box;
    overflow: auto;
  }
  .hero {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 2px;
  }
  .hero-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: 10px;
    color: #fff;
    background: linear-gradient(180deg, var(--accent), var(--accent-pressed));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .hero-icon :global(.icon) {
    width: 22px;
    height: 22px;
    stroke-width: 1.7;
  }
  .hero-text {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
  }
  p {
    margin: 0;
  }
  .secondary,
  .caption {
    color: var(--secondary);
  }
  .hero .secondary {
    font-size: var(--text-md);
  }
  .caption {
    font-size: var(--text-sm);
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: 14px 16px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    font-weight: 500;
  }
  .warning,
  .flag {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 8px 10px;
    border-radius: var(--radius-control);
    font-size: var(--text-md);
    overflow-wrap: anywhere;
  }
  .warning {
    background: var(--state-fail-soft);
  }
  .warning :global(.icon) {
    color: var(--state-fail);
  }
  .flag {
    background: var(--state-busy-soft);
  }
  .flag :global(.icon) {
    color: var(--state-busy);
  }
  .warning :global(.icon),
  .flag :global(.icon) {
    flex: none;
    width: 15px;
    height: 15px;
    margin-top: 1px;
  }
  .app-head {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
  .app-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-icon);
    color: var(--accent-text);
    background: var(--accent-soft);
    font-weight: 650;
  }
  .app-text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    flex: 1;
    min-width: 0;
  }
  .app-name {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .path {
    font: 11px / 1.4 var(--mono);
    color: var(--secondary);
    overflow-wrap: anywhere;
    word-break: break-all;
    -webkit-user-select: text;
    user-select: text;
  }
  .revoke {
    flex: none;
    color: var(--state-fail-text);
  }
  .dot {
    padding: 0 4px;
  }
  .heading {
    font-weight: 600;
    margin-top: 2px;
  }
  .allowed {
    display: flex;
    flex-direction: column;
    padding: 3px;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
  }
  .item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 4px 8px;
    border-radius: var(--radius-sm);
  }
  .item:hover {
    background: var(--fill-hover);
  }
  .item-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .held {
    flex: none;
    font-size: var(--text-xs);
    font-weight: 600;
    padding: 1px 7px;
    border-radius: var(--radius-pill);
    color: var(--state-on-text);
    background: var(--state-on-soft);
  }
  .activity-actions {
    display: flex;
    justify-content: flex-end;
  }
  .activity-actions :global(.icon) {
    width: 13px;
    height: 13px;
    color: var(--secondary);
  }
  .activity summary {
    cursor: default;
    font-weight: 500;
  }
  .lines {
    margin: 0;
    max-height: 180px;
    overflow: auto;
    padding: 8px 10px;
    border-radius: var(--radius-control);
    background: var(--code-background);
    font: 11px / 1.5 var(--mono);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
</style>
