<script lang="ts">
  // "Unsubscribe…" (spec 6): names the catalog and how many connections it removes, lists the ones that are up
  // (they are disconnected first), and says that filled-in credential slots stay in Credentials.
  import { tr } from '../l10n.svelte';
  import Sheet from './Sheet.svelte';

  let {
    name,
    connections,
    active,
    busy = false,
    error = null,
    onconfirm,
    oncancel,
  }: {
    name: string;
    /// The catalog's connections.
    connections: number;
    /// The names of those that are up now.
    active: string[];
    busy?: boolean;
    error?: string | null;
    onconfirm: () => void;
    oncancel: () => void;
  } = $props();
</script>

<Sheet title={tr('Unsubscribe from %@?', name)} {oncancel}>
  {#snippet children()}
    <p class="secondary removes">
      {connections === 1
        ? tr('Its connection and folders are removed from this Mac, and paired apps lose access to it.')
        : tr('Its %lld connections and folders are removed from this Mac, and paired apps lose access to them.', connections)}
    </p>
    {#if active.length > 0}
      <div class="active" role="note">
        <p>{tr('These connections are up and are disconnected first:')}</p>
        <ul>
          {#each active as connection, i (i)}
            <li>{connection}</li>
          {/each}
        </ul>
      </div>
    {/if}
    <p class="hint">
      {tr('Credential slots you filled in are kept as shared credentials in Credentials. To keep a connection, duplicate it as a personal connection first.')}
    </p>
    {#if error}
      <p class="form-error" role="alert">{error}</p>
    {/if}
  {/snippet}
  {#snippet buttons()}
    <button class="cancel" onclick={oncancel}>{tr('Cancel')}</button>
    <button class="destructive confirm" disabled={busy} onclick={onconfirm}>{tr('Unsubscribe')}</button>
  {/snippet}
</Sheet>

<style>
  .active {
    padding: 8px 12px;
    border-radius: var(--radius-control);
    background: var(--state-busy-soft);
    font-size: var(--text-md);
  }
  .active ul {
    margin: 4px 0 0;
    padding-left: 18px;
  }
</style>
