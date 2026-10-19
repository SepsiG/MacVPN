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
  span {
    font-size: var(--text-md);
  }
  .unsaved {
    color: var(--state-busy-text);
    font-weight: 500;
  }
  .unsaved::before {
    content: '';
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 6px;
    border-radius: 50%;
    background: var(--state-busy);
    vertical-align: 1px;
  }
  .secondary {
    color: var(--secondary);
  }
  .ok {
    color: var(--state-on-text);
  }
</style>
