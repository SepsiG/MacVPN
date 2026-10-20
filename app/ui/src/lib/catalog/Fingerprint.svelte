<script lang="ts">
  // A publisher fingerprint in its 8 groups, with Copy (a fingerprint is public: it is what members compare).
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';

  let { value }: { value: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch (e) {
      console.error(e);
    }
  }
</script>

<div class="fingerprint-row">
  <code class="fingerprint" data-fingerprint>{value}</code>
  <button class="copy-fingerprint" onclick={() => copy().catch(console.error)}><Icon name="copy" />{copied ? tr('Copied') : tr('Copy')}</button>
</div>

<style>
  .fingerprint-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .fingerprint-row :global(.icon) {
    width: 13px;
    height: 13px;
  }
</style>
