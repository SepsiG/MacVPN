<script lang="ts">
  // Deleting a shared credential that connections still use (spec 3a): the question names them and offers "Copy
  // into each connection" (they keep its user name and password as their own) or Cancel. A credential in use is
  // never deleted silently.
  import { tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';

  let {
    name,
    connections,
    oncopy,
    oncancel,
  }: { name: string; connections: string[]; oncopy: () => void; oncancel: () => void } = $props();
</script>

<Modal
  title={tr('Delete %@?', name)}
  message={tr('These connections use this shared credential. Copy its user name and password into each of them, then delete it?')}
  buttons={[
    { label: tr('Cancel'), kind: 'cancel', action: oncancel },
    { label: tr('Copy into Each Connection'), kind: 'destructive', action: oncopy },
  ]}
>
  <ul class="in-use">
    {#each connections as connection, i (i)}
      <li>{connection}</li>
    {/each}
  </ul>
</Modal>

<style>
  .in-use {
    margin: 0 0 16px;
    padding: 8px 12px 8px 28px;
    max-height: 180px;
    overflow: auto;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
    overflow-wrap: anywhere;
  }
  .in-use li + li {
    margin-top: 2px;
  }
</style>
