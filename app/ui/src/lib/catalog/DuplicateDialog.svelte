<script lang="ts">
  // "Duplicate as personal connection…" (spec 6): asks for the copy's name (default "<name> (personal)") and makes
  // an independent, editable copy at the top level. From the connection's detail and from its context menu.
  import { untrack } from 'svelte';
  import { tr } from '../l10n.svelte';
  import { catalogApi } from './catalogApi';
  import Sheet from './Sheet.svelte';

  let { itemId, name, ondone, oncancel }: { itemId: string; name: string; ondone: (copyId: string) => void; oncancel: () => void } = $props();

  let value = $state(untrack(() => tr('%@ (personal)', name)));
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function duplicate() {
    if (busy || value.trim() === '') return;
    busy = true;
    error = null;
    try {
      ondone(await catalogApi.duplicate(itemId, value.trim()));
    } catch (e) {
      error = typeof e === 'string' ? e : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Sheet title={tr('Duplicate as Personal Connection')} {oncancel}>
  {#snippet children()}
    <p class="secondary">
      {tr('The copy is yours: you can edit it, and later catalog versions do not change it. It keeps the config, the secrets and the shared credential; acknowledge its risky settings again.')}
    </p>
    <label class="form-row">
      <span>{tr('Name')}</span>
      <input class="duplicate-name" type="text" maxlength="128" autocomplete="off" bind:value />
    </label>
    {#if error}
      <p class="form-error" role="alert">{error}</p>
    {/if}
  {/snippet}
  {#snippet buttons()}
    <button class="cancel" onclick={oncancel}>{tr('Cancel')}</button>
    <button class="primary duplicate" disabled={busy || value.trim() === ''} onclick={() => duplicate().catch(console.error)}>{tr('Duplicate')}</button>
  {/snippet}
</Sheet>
