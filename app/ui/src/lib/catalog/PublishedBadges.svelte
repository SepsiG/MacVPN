<script lang="ts">
  // A source connection's "Published in “Acme VPN” (v12)" line per publication, with "changed since the last
  // publish" once it was edited after that publish (spec 7, admin side). Nothing for a connection never published.
  import { tr } from '../l10n.svelte';
  import type { PublishedBadge } from './publishApi';

  let { published = [] }: { published?: PublishedBadge[] } = $props();
</script>

{#each published as badge (badge.catalogId)}
  <span class="published" class:changed={badge.changed} data-published={badge.catalogId}>
    {tr('Published in “%@” (v%d)', badge.name, badge.version)}{#if badge.changed}
      · {tr('changed since the last publish')}{/if}
  </span>
{/each}

<style>
  .published {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--accent-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .published.changed {
    color: var(--state-busy-text);
  }
</style>
