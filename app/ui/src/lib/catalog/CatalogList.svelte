<script lang="ts">
  // The "Team catalogs" section's list (spec 6, plan Task 16): one card per subscription with its name, status,
  // source, version, the publisher fingerprint's short form, the last refresh and the error. Only props: the
  // container (`TeamCatalogs.svelte`) does the calls, so this view renders the same on the server (tests).
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import type { SubscriptionView } from './catalogApi';
  import { shortFingerprint, statusOf, when } from './status';

  let {
    catalogs,
    language,
    message = null,
    refreshing = false,
    onadd,
    onrefreshall,
    onselect,
  }: {
    catalogs: SubscriptionView[];
    language: 'en' | 'hu';
    /// Why the section cannot be used now (the vault is locked).
    message?: string | null;
    refreshing?: boolean;
    onadd: () => void;
    onrefreshall: () => void;
    onselect: (id: string) => void;
  } = $props();
</script>

<div class="card actions-card">
  <div class="toolbar">
    <button class="add" disabled={message !== null} onclick={onadd}><Icon name="plus" />{tr('Add team catalog…')}</button>
    {#if catalogs.length > 0}
      <button class="refresh-all" disabled={refreshing} onclick={onrefreshall}><Icon name="refresh" />{refreshing ? tr('Refreshing…') : tr('Refresh all')}</button>
    {/if}
  </div>
  {#if message}
    <p class="warning locked"><Icon name="warning" /><span>{message}</span></p>
  {/if}
</div>

{#each catalogs as sub (sub.id)}
  {@const status = statusOf(sub)}
  <button class="card subscription" data-catalog={sub.id} onclick={() => onselect(sub.id)}>
    <div class="head">
      <span class="badge" aria-hidden="true"><Icon name="globe" /></span>
      <div class="text">
        <strong class="name">{sub.name}</strong>
        <span class="meta">
          {sub.source}{#if sub.version !== null}<span class="dot" aria-hidden="true">·</span>v{sub.version}{/if}<span class="dot" aria-hidden="true">·</span><span
            class="mono"
            title={sub.fingerprint}>{shortFingerprint(sub.fingerprint)}</span
          >
        </span>
      </div>
      <span class="status {status.severity}">{status.text}</span>
      <span class="chevron" aria-hidden="true"><Icon name="chevron" /></span>
    </div>
    <p class="caption refreshed">{tr('Last refresh: %@', when(sub.lastRefresh, language))}</p>
    {#if sub.error}
      <p class="caption error">{sub.error}</p>
    {/if}
  </button>
{:else}
  {#if message === null}
    <div class="card">
      <p class="caption none">
        {tr('No team catalogs yet. Add one with the subscription string or the details your administrator sent you.')}
      </p>
    </div>
  {/if}
{/each}

<style>
  .card {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: var(--space-3);
    padding: 14px 16px;
    border: none;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    color: inherit;
    font: inherit;
    font-weight: 400;
    text-align: left;
  }
  button.card {
    min-height: 0;
    justify-content: flex-start;
    cursor: default;
  }
  button.card:hover {
    background: var(--surface-hover);
  }
  button.card:focus-visible {
    box-shadow: var(--focus-ring);
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .toolbar :global(.icon) {
    width: 13px;
    height: 13px;
    color: var(--accent);
  }
  .head {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    min-width: 0;
  }
  .badge {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-icon);
    color: var(--accent-text);
    background: var(--accent-soft);
  }
  .badge :global(.icon) {
    width: 16px;
    height: 16px;
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    flex: 1;
    min-width: 0;
  }
  .name,
  .meta {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name {
    font-weight: 600;
  }
  .meta {
    font-size: var(--text-md);
    color: var(--secondary);
  }
  .dot {
    margin: 0 5px;
  }
  .mono {
    font-family: var(--mono);
    font-size: 11px;
  }
  .status {
    flex: none;
    font-size: var(--text-xs);
    font-weight: 600;
    padding: 1px 8px;
    border-radius: var(--radius-pill);
  }
  .status.ok {
    color: var(--state-on-text);
    background: var(--state-on-soft);
  }
  .status.warn {
    color: var(--state-busy-text);
    background: var(--state-busy-soft);
  }
  .status.error {
    color: var(--state-fail-text);
    background: var(--state-fail-soft);
  }
  .status.muted {
    color: var(--secondary);
    background: var(--fill-pressed);
  }
  .chevron {
    flex: none;
    display: inline-flex;
    color: var(--tertiary);
  }
  .chevron :global(.icon) {
    width: 10px;
    height: 10px;
    stroke-width: 2;
  }
  p {
    margin: 0;
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .caption.error {
    color: var(--state-fail-text);
    overflow-wrap: anywhere;
  }
  .warning {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 8px 10px;
    border-radius: var(--radius-control);
    font-size: var(--text-md);
    background: var(--state-busy-soft);
    overflow-wrap: anywhere;
  }
  .warning :global(.icon) {
    flex: none;
    width: 15px;
    height: 15px;
    margin-top: 1px;
    color: var(--state-busy);
  }
</style>
