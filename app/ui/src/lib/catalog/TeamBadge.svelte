<script lang="ts">
  // The "Team" badge (spec 6): on a team catalog's root folder and on each of its connections, in the menu and in the
  // Connections window. The catalog's name is its tooltip.
  import { tr } from '../l10n.svelte';

  let { name = null }: { name?: string | null } = $props();
</script>

<span class="team-badge" title={name ? tr('Managed by the team catalog “%@”', name) : undefined}>{tr('Team')}</span>

<style>
  .team-badge {
    flex: none;
    display: inline-flex;
    align-items: center;
    padding: 0 6px;
    border-radius: var(--radius-pill);
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 16px;
    letter-spacing: 0.01em;
    white-space: nowrap;
  }
</style>
