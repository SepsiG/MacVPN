<script lang="ts">
  // The strength hint under the master password: three bars and a word. It advises; it never blocks (only the
  // 10-character minimum does).
  import { tr } from '../l10n.svelte';
  import type { Strength } from './strength';

  let { strength, short = false }: { strength: Strength | null; short?: boolean } = $props();
  const level = $derived(strength === 'strong' ? 3 : strength === 'fair' ? 2 : strength === 'weak' ? 1 : 0);
</script>

<div class="strength" data-strength={strength ?? 'none'}>
  <span class="bars" aria-hidden="true">
    {#each [1, 2, 3] as bar (bar)}<span class:on={bar <= level}></span>{/each}
  </span>
  <span class="caption">
    {#if short}
      {tr('Too short')}
    {:else if strength === 'weak'}
      {tr('Weak — easy to guess')}
    {:else if strength === 'fair'}
      {tr('Fair')}
    {:else if strength === 'strong'}
      {tr('Strong')}
    {/if}
  </span>
</div>

<style>
  .strength {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: 16px;
  }
  .bars {
    display: inline-flex;
    gap: 3px;
  }
  .bars span {
    width: 22px;
    height: 4px;
    border-radius: 2px;
    background: var(--surface-sunken);
  }
  [data-strength='weak'] .bars span.on {
    background: var(--state-fail);
  }
  [data-strength='fair'] .bars span.on {
    background: var(--state-busy);
  }
  [data-strength='strong'] .bars span.on {
    background: var(--state-on);
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
</style>
