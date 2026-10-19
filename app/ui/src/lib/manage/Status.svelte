<script lang="ts">
  // The editor's footer state: "Unsaved changes", "Saved: <time>" or the native / system "saved" text.
  import { i18n, tr } from '../l10n.svelte';

  let { dirty, savedAt = null, savedText = null }: { dirty: boolean; savedAt?: number | null; savedText?: string | null } =
    $props();

  const time = $derived(
    savedAt === null ? '' : new Date(savedAt * 1000).toLocaleTimeString(i18n.language === 'hu' ? 'hu-HU' : 'en-US'),
  );
</script>

{#if dirty}
  <span class="unsaved">{tr('Unsaved changes')}</span>
{:else if savedAt !== null}
  <span class="secondary">{tr('Saved: %@', time)}</span>
{:else if savedText}
  <span class="ok">{savedText}</span>
{/if}

<style>
  .unsaved {
    color: var(--orange);
  }
  .secondary {
    color: var(--secondary);
  }
  .ok {
    color: var(--green);
  }
</style>
