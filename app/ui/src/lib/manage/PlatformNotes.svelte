<script lang="ts">
  // The platform's notes on an editor's settings (WinVPN 2c): `reasons`, yellow, above the form (Windows cannot
  // connect these settings; the config stays valid and is saved, it still runs on macOS), or `summary`, grey, under
  // it (what Windows makes of the settings, and the ones it ignores while the connection still runs). Nothing
  // without `platform` (macOS).
  import type { EditorPlatformView } from '../api';
  import Icon from '../Icon.svelte';

  let { platform, part }: { platform: EditorPlatformView | undefined; part: 'reasons' | 'summary' } = $props();
</script>

{#if platform}
  {#if part === 'reasons'}
    {#each platform.reasons as reason, i (i)}
      <p class="platform-reason" role="note"><Icon name="warning" /><span>{reason}</span></p>
    {/each}
  {:else}
    {#if platform.summary}
      <p class="note">{platform.summary}</p>
    {/if}
    {#each platform.warnings as warning, i (i)}
      <p class="note">{warning}</p>
    {/each}
  {/if}
{/if}

<style>
  .platform-reason {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    margin: 0;
    padding: 8px 12px;
    border-radius: var(--radius-control);
    background: var(--state-busy-soft);
    color: var(--state-busy-text);
    font-size: var(--text-md);
    overflow-wrap: anywhere;
  }
  .platform-reason :global(.icon) {
    flex: none;
    margin-top: 1px;
    width: 14px;
    height: 14px;
  }
</style>
