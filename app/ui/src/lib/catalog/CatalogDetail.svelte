<script lang="ts">
  // One subscription (spec 6, plan Task 16): its status and the last error, the source, the version, the full
  // publisher fingerprint, the refresh times, whether an access token is stored (never the token), the credential
  // slots ("Filled in" or "You will be asked when you connect", "Edit in Credentials"), and the actions: Refresh now
  // (its outcome under the button), Edit source…, Change team key…, Change access token…, Unsubscribe…. Only props
  // (the container calls the backend).
  import Icon from '../Icon.svelte';
  import { connectionsText } from '../counts';
  import { tr } from '../l10n.svelte';
  import type { SubscriptionView } from './catalogApi';
  import { statusOf, when, type StatusLine } from './status';

  let {
    sub,
    connections,
    language,
    refreshing = false,
    result = null,
    onback,
    onrefresh,
    onedit,
    onunsubscribe,
    oncredentials,
  }: {
    sub: SubscriptionView;
    /// The catalog's connections on this Mac.
    connections: number;
    language: 'en' | 'hu';
    refreshing?: boolean;
    /// The last "Refresh now" (or edit) of this subscription, in this window.
    result?: StatusLine | null;
    onback: () => void;
    onrefresh: () => void;
    onedit: (mode: 'source' | 'teamKey' | 'token') => void;
    onunsubscribe: () => void;
    oncredentials: () => void;
  } = $props();

  const status = $derived(statusOf(sub));
</script>

<div class="catalog-detail" data-catalog={sub.id}>
  <button class="back" onclick={onback}><span class="back-chevron" aria-hidden="true"><Icon name="chevron" /></span>{tr('Team catalogs')}</button>

  <header class="hero">
    <span class="hero-icon" aria-hidden="true"><Icon name="globe" /></span>
    <div class="hero-text">
      <h1>{sub.name}</h1>
      <p class="secondary">
        {connectionsText(connections)}<span class="dot" aria-hidden="true">·</span><span
          class="status {status.severity}">{status.text}</span
        >
      </p>
    </div>
  </header>

  {#if sub.error}
    <p class="problem" role="alert"><Icon name="warning" /><span>{sub.error}</span></p>
  {/if}

  <div class="card">
    <div class="refresh-row">
      <button class="refresh primary" disabled={refreshing} onclick={onrefresh}>
        <Icon name="refresh" />{refreshing ? tr('Refreshing…') : tr('Refresh now')}
      </button>
      {#if result}<span class="result {result.severity}" role="status">{result.text}</span>{/if}
    </div>
    <dl class="facts">
      <dt>{tr('Source')}</dt>
      <dd class="source">{sub.source}</dd>
      <dt>{tr('Version')}</dt>
      <dd>{sub.version === null ? '–' : `v${sub.version}`}</dd>
      <dt>{tr('Publisher fingerprint')}</dt>
      <dd class="mono fingerprint">{sub.fingerprint}</dd>
      <dt>{tr('Last refresh')}</dt>
      <dd>{when(sub.lastRefresh, language)}</dd>
      <dt>{tr('Last successful refresh')}</dt>
      <dd>{when(sub.lastSuccess, language)}</dd>
      <dt>{tr('Access token')}</dt>
      <dd class="token-state">{sub.hasToken ? tr('Stored in the vault') : tr('None')}</dd>
    </dl>
  </div>

  <div class="card">
    <h2>{tr('Credential slots')}</h2>
    {#each sub.slots as slot, i (i)}
      <div class="slot">
        <span class="slot-icon" aria-hidden="true"><Icon name="key" /></span>
        <div class="slot-text">
          <strong>{slot.name}</strong>
          <span class="caption" class:filled={slot.filled}>{slot.filled ? tr('Filled in') : tr('You will be asked when you connect')}</span>
        </div>
        {#if slot.credentialName}
          <button class="edit-credentials" onclick={oncredentials}>{tr('Edit in Credentials')}</button>
        {/if}
      </div>
    {:else}
      <p class="caption">{tr('This catalog uses no credential slots.')}</p>
    {/each}
  </div>

  <div class="card actions">
    <div class="buttons">
      <button class="edit-source" onclick={() => onedit('source')}>{tr('Edit source…')}</button>
      <button class="edit-team-key" onclick={() => onedit('teamKey')}>{tr('Change team key…')}</button>
      <button class="edit-token" onclick={() => onedit('token')}>{tr('Change access token…')}</button>
      <span class="spacer"></span>
      <button class="unsubscribe destructive" onclick={onunsubscribe}>{tr('Unsubscribe…')}</button>
    </div>
    <p class="caption">
      {tr('The connections of a team catalog are read-only. After a compromise of the admin key, your administrator publishes a new catalog and everyone subscribes again with its new fingerprint.')}
    </p>
  </div>
</div>

<style>
  .catalog-detail {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .back {
    align-self: flex-start;
    gap: 4px;
    padding: 2px 10px 2px 6px;
    border-radius: var(--radius-pill);
  }
  .back-chevron {
    display: inline-flex;
    transform: rotate(180deg);
    color: var(--accent);
  }
  .back-chevron :global(.icon) {
    width: 10px;
    height: 10px;
    stroke-width: 2;
  }
  .hero {
    display: flex;
    align-items: flex-start;
    gap: 14px;
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
    min-width: 0;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
    overflow-wrap: anywhere;
  }
  h2 {
    font-size: var(--text-md);
    font-weight: 600;
    margin: 0;
  }
  p {
    margin: 0;
  }
  .secondary {
    color: var(--secondary);
    font-size: var(--text-md);
  }
  .dot {
    margin: 0 6px;
  }
  .status.ok,
  .result.ok {
    color: var(--state-on-text);
  }
  .status.warn,
  .result.warn {
    color: var(--state-busy-text);
  }
  .status.error,
  .result.error {
    color: var(--state-fail-text);
  }
  .problem {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 8px 10px;
    border-radius: var(--radius-control);
    font-size: var(--text-md);
    background: var(--state-fail-soft);
    overflow-wrap: anywhere;
  }
  .problem :global(.icon) {
    flex: none;
    width: 15px;
    height: 15px;
    margin-top: 1px;
    color: var(--state-fail);
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
  .refresh-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-4);
  }
  .refresh :global(.icon) {
    width: 13px;
    height: 13px;
  }
  .result {
    font-size: var(--text-md);
    overflow-wrap: anywhere;
  }
  .facts {
    display: grid;
    grid-template-columns: minmax(120px, 34%) 1fr;
    gap: 6px var(--space-4);
    margin: 4px 0 0;
    font-size: var(--text-md);
  }
  dt {
    color: var(--secondary);
  }
  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  .mono {
    font-family: var(--mono);
    font-size: 12px;
  }
  .slot {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
  .slot-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: var(--radius-icon);
    color: var(--accent-text);
    background: var(--accent-soft);
  }
  .slot-icon :global(.icon) {
    width: 14px;
    height: 14px;
  }
  .slot-text {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .caption.filled {
    color: var(--state-on-text);
  }
  .buttons {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .spacer {
    flex: 1;
  }
</style>
