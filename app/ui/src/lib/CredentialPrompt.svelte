<script lang="ts">
  // A credential prompt window (`cred-<id>`), like the MFA prompt windows: it does not take the focus when it
  // appears, nothing but Cancel works in the first second after it became visible (the backend counts its own lock
  // from the page's ready signal and from ordering the window on screen, and refuses an earlier answer too), and
  // there is no default button. Escape and the close button cancel. The typed values leave the page only in the
  // answer and are cleared from the fields and the page's state right after it is sent. The window closes when
  // the prompt ends (answered, cancelled, expired, disconnected).
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { api, onViewModel, type CredentialAction, type CredentialField, type ViewModel } from './api';
  import CredentialView from './CredentialView.svelte';
  import { answerValues, credentialIdOfLabel, orderedFields } from './credentials';
  import { setLanguage } from './l10n.svelte';
  import './manage/manage.css';

  const id = credentialIdOfLabel(getCurrentWindow().label);

  let vm = $state<ViewModel | null>(null);
  let values = $state<Partial<Record<CredentialField, string>>>({});
  let save = $state(true);
  let prefilled = false;
  let armed = $state(false);
  let finished = $state(false);
  /// The backend did not take the last answer (shown in the window, never silently ignored).
  let error = $state<'tooEarly' | 'rejected' | null>(null);
  let now = $state(Date.now());

  const prompt = $derived(vm?.credentialPrompts.find((p) => p.id === id) ?? null);
  const left = $derived(prompt ? prompt.deadline - now / 1000 : 0);

  // A new input clears the last refusal.
  $effect(() => {
    void values;
    error = null;
  });

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
    const p = next.credentialPrompts.find((c) => c.id === id);
    // The stored user name is pre-filled once (not on every view-model update).
    if (p && !prefilled) {
      prefilled = true;
      if (p.username && p.fields.includes('username')) values = { ...values, username: p.username };
    }
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    const timer = setInterval(() => (now = Date.now()), 1000);
    let arm: ReturnType<typeof setTimeout> | undefined;
    if (id !== null) {
      api.credentialsReady(id).then(() => {
        arm = setTimeout(() => {
          armed = true;
          // The first empty field gets the caret (the window itself is not made key: no focus steal).
          const inputs = [...document.querySelectorAll<HTMLInputElement>('input[data-field]')];
          inputs.find((input) => input.value === '')?.focus();
        }, 1000);
      }, console.error);
    }
    return () => {
      clearInterval(timer);
      clearTimeout(arm);
      unlisten.then((f) => f());
    };
  });

  /// Empties the fields: the page's state and the inputs in the DOM.
  function clear() {
    values = {};
    for (const input of document.querySelectorAll<HTMLInputElement>('input[data-field]')) input.value = '';
  }

  async function finish(action: CredentialAction) {
    if (finished || id === null || !prompt) return;
    finished = true;
    error = null;
    const sent = action === 'connect' ? answerValues(orderedFields(prompt.fields), values) : {};
    try {
      await api.answerCredentials(id, action, sent, save);
    } catch (e) {
      finished = false;
      // A click before the backend's own one-second lock passed (it counts from when the window was ordered on
      // screen, which can be later than this page's timer), or values it refused.
      error = String(e).includes('too early') ? 'tooEarly' : 'rejected';
      console.error(e);
    } finally {
      for (const key of Object.keys(sent)) delete sent[key as CredentialField];
      if (finished) clear();
    }
  }

  function keydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault();
      finish('cancel').catch(console.error);
    }
  }
</script>

<svelte:window onkeydown={keydown} />

{#if prompt}
  <CredentialView
    {prompt}
    bind:values
    bind:save
    {armed}
    {left}
    {error}
    onconnect={() => finish('connect').catch(console.error)}
    oncancel={() => finish('cancel').catch(console.error)}
  />
{/if}
