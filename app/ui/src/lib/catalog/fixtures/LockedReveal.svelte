<script lang="ts">
  // View test fixture: a team key reveal inside the catalog gate, as the Publishing section shows it.
  import CatalogGate from '../CatalogGate.svelte';
  import TeamKeyReveal from '../TeamKeyReveal.svelte';

  let { vaultState, teamKey }: { vaultState: string; teamKey: string } = $props();
</script>

<CatalogGate {vaultState}>
  <TeamKeyReveal {teamKey} onclose={() => {}} />
</CatalogGate>
