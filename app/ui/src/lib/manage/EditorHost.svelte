<script lang="ts">
  // The Settings tab of a managed connection: its editor (text, native or SSTP) over the backend draft.
  // Cmd+S saves while the tab is shown (text and SSTP editors, as the Swift app).
  import { onDestroy, onMount, untrack } from 'svelte';
  import type { Kind } from '../api';
  import { EditorSession } from './session.svelte';
  import NativeForm from './NativeForm.svelte';
  import SstpForm from './SstpForm.svelte';
  import TextEditor from './TextEditor.svelte';
  import { i18n } from '../l10n.svelte';
  import { isPrimaryShortcut } from '../keys';

  let { id, kind, active, epoch }: { id: string; kind: Kind; active: boolean; epoch: number } = $props();

  const session = untrack(() => new EditorSession(id));

  // The backend dropped the editors (changes discarded, e.g. for a quit that was then cancelled): load again.
  let loadedEpoch = untrack(() => epoch);
  $effect(() => {
    if (epoch !== loadedEpoch) {
      loadedEpoch = epoch;
      untrack(() => session.open());
    }
  });

  // Every change of a bound field goes to the backend draft.
  $effect(() => {
    if (session.fields) {
      JSON.stringify(session.fields);
      untrack(() => session.changed());
    }
  });

  onMount(() => {
    session.open();
  });
  onDestroy(() => session.dispose());

  function keydown(event: KeyboardEvent) {
    // Cmd+S (Ctrl+S on Windows and Linux).
    if (!active || !isPrimaryShortcut(event, 's', i18n.platform.os)) return;
    if (kind === 'l2tp' || kind === 'cisco') return;
    event.preventDefault();
    session.save().catch(console.error);
  }
</script>

<svelte:window onkeydown={keydown} />

{#if session.error}
  <p class="error pad">{session.error}</p>
{:else if session.fields}
  {#if session.fields.type === 'native'}
    <NativeForm {session} {kind} />
  {:else if session.fields.type === 'sstp'}
    <SstpForm {session} />
  {:else if session.fields.type === 'text'}
    <TextEditor {session} {kind} />
  {/if}
{/if}
