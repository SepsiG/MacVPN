<script lang="ts">
  // A pairing window of the control API (`pair-<id>`), like the MFA prompt windows: it does not take the focus when
  // it appears, nothing but Deny works in the first second after it became visible (the backend counts its own lock
  // from the page's ready signal and from ordering the window on screen), and there is no default button. Escape and
  // the close button deny; at the end of the two minutes the buttons are disabled and the backend times the pairing
  // out. The window closes when the pairing ends.
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { api, onViewModel, type ViewModel } from './api';
  import { setLanguage } from './l10n.svelte';
  import './manage/manage.css';
  import { allowedKeys, pairingIdOfLabel } from './pairing';
  import PairingView from './PairingView.svelte';

  const id = pairingIdOfLabel(getCurrentWindow().label);

  let vm = $state<ViewModel | null>(null);
  let ticked = $state<string[]>([]);
  let armed = $state(false);
  let finished = $state(false);
  let now = $state(Date.now());

  const pairing = $derived(vm?.pairings.find((p) => p.id === id) ?? null);
  const left = $derived(pairing ? pairing.deadline - now / 1000 : 0);

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    const timer = setInterval(() => (now = Date.now()), 1000);
    let arm: ReturnType<typeof setTimeout> | undefined;
    if (id !== null) {
      api.pairingReady(id).then(() => {
        arm = setTimeout(() => (armed = true), 1000);
      }, console.error);
    }
    return () => {
      clearInterval(timer);
      clearTimeout(arm);
      unlisten.then((f) => f());
    };
  });

  /// Two minutes are over: the buttons are disabled, and the backend's own time-out decides (the window then closes).
  const expired = $derived(pairing !== null && left <= 0);

  async function answer(allowed: string[] | null) {
    if (finished || id === null) return;
    finished = true;
    try {
      await api.pairingAnswer(id, allowed);
    } catch (e) {
      finished = false;
      console.error(e);
    }
  }

  function keydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && !expired) {
      event.preventDefault();
      answer(null).catch(console.error);
    }
  }
</script>

<svelte:window onkeydown={keydown} />

{#if pairing}
  <PairingView
    {pairing}
    bind:ticked
    {armed}
    {expired}
    {left}
    onallow={() => answer(allowedKeys(pairing.items, ticked)).catch(console.error)}
    ondeny={() => answer(null).catch(console.error)}
  />
{/if}
