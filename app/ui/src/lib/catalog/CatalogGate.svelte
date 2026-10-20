<script lang="ts">
  // The catalog sections (Team catalogs, Publishing) exist only while the vault is open. A lock unmounts them:
  // their dialogs close and their onDestroy wipes run (a team key on show, a pasted subscription string, a typed
  // team key, token or password), so nothing of it stays in the state or the page.
  import type { Snippet } from 'svelte';

  let { vaultState, children }: { vaultState: string; children: Snippet } = $props();
</script>

{#if vaultState === 'unlocked'}
  {@render children()}
{/if}
