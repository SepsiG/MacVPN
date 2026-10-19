<script lang="ts">
  // The Credentials section's cards (spec 3a): one card per shared credential with its name, user name, whether a
  // password is stored and "used by N", and its actions; or, while the vault is locked, the reason. Only props:
  // the container (`Credentials.svelte`) does the calls, so this view renders the same on the server (tests).
  import type { CredentialItem, CredentialsView } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';

  let {
    view,
    pending = null,
    onadd,
    onfrom,
    onedit,
    onrename,
    ondelete,
  }: {
    view: CredentialsView;
    /// The credential with a change on its way (its buttons are disabled).
    pending?: string | null;
    onadd: () => void;
    onfrom: () => void;
    onedit: (c: CredentialItem) => void;
    onrename: (c: CredentialItem) => void;
    ondelete: (c: CredentialItem) => void;
  } = $props();
</script>

<div class="card actions-card">
  <div class="toolbar">
    <button class="add" disabled={!view.available} onclick={onadd}><Icon name="plus" />{tr('Add Credential…')}</button>
    <button class="from" disabled={!view.available} onclick={onfrom}>{tr('Create from Connection…')}</button>
  </div>
  {#if view.message}
    <p class="warning locked"><Icon name="warning" /><span>{view.message}</span></p>
  {/if}
</div>

{#each view.items as c (c.id)}
  <div class="card credential" data-credential={c.id}>
    <div class="head">
      <span class="badge" aria-hidden="true"><Icon name="key" /></span>
      <div class="text">
        <strong class="name">{c.name}</strong>
        <span class="user">{c.username === '' ? tr('No user name') : c.username}</span>
      </div>
      <span class="used" class:unused={c.usedBy === 0}>{c.usedBy === 1 ? tr('Used by 1 connection') : tr('Used by %lld connections', c.usedBy)}</span>
    </div>
    <p class="caption password">
      {c.hasPassword ? tr('Password saved') : tr('No password saved: asked when connecting')}
    </p>
    <div class="buttons">
      <button class="edit" disabled={pending === c.id} onclick={() => onedit(c)}>{tr('Edit…')}</button>
      <button class="rename" disabled={pending === c.id} onclick={() => onrename(c)}>{tr('Rename…')}</button>
      <span class="spacer"></span>
      <button class="delete destructive" disabled={pending === c.id} onclick={() => ondelete(c)}>{tr('Delete')}</button>
    </div>
  </div>
{:else}
  {#if view.available}
    <div class="card">
      <p class="caption none">{tr('No shared credentials yet. Add one, or create one from a connection that already has a user name and password.')}</p>
    </div>
  {/if}
{/each}

<style>
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
  .toolbar,
  .buttons {
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
  .user {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name {
    font-weight: 600;
  }
  .user {
    font-size: var(--text-md);
    color: var(--secondary);
    -webkit-user-select: text;
    user-select: text;
  }
  .used {
    flex: none;
    font-size: var(--text-xs);
    font-weight: 600;
    padding: 1px 8px;
    border-radius: var(--radius-pill);
    color: var(--state-on-text);
    background: var(--state-on-soft);
  }
  .used.unused {
    color: var(--secondary);
    background: var(--fill-pressed);
  }
  p {
    margin: 0;
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .spacer {
    flex: 1;
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
