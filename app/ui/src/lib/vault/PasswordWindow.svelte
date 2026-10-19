<script lang="ts">
  // The master password window (`vault-password`), like the other vault windows (no focus steal, the one-second
  // input lock, no default button). Its mode comes from the view model (`vault.passwordMode`). The passwords leave
  // the page once and are cleared from the state and the DOM right after.
  import { onMount } from 'svelte';
  import { api, onViewModel, type UnlockReply, type ViewModel } from '../api';
  import { setLanguage, tr } from '../l10n.svelte';
  import '../manage/manage.css';
  import { fitToContent } from '../fit';
  import { clearInputs } from './inputs';
  import PasswordView from './PasswordView.svelte';
  import './vault.css';

  let vm = $state<ViewModel | null>(null);
  let armed = $state(false);
  let busy = $state(false);
  let done = $state(false);
  let current = $state('');
  let newPassword = $state('');
  let newAgain = $state('');
  let error = $state<string | null>(null);
  let notBefore = $state(0);
  let now = $state(Date.now());
  let root: HTMLDivElement | undefined = $state();

  const mode = $derived(vm?.vault.passwordMode ?? null);
  const wait = $derived(Math.max(0, Math.ceil((notBefore - now) / 1000)));

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    const timer = setInterval(() => (now = Date.now()), 250);
    let arm: ReturnType<typeof setTimeout> | undefined;
    api.vaultReady().then(() => {
      arm = setTimeout(() => {
        armed = true;
        document.querySelector<HTMLInputElement>('input[data-field]')?.focus();
      }, 1000);
    }, console.error);
    const stop = fitToContent(root ?? null, api.fitWindow);
    return () => {
      clearInterval(timer);
      clearTimeout(arm);
      stop();
      unlisten.then((f) => f());
    };
  });

  function forget() {
    current = '';
    newPassword = '';
    newAgain = '';
    clearInputs();
  }

  async function submit() {
    if (busy || !mode) return;
    busy = true;
    error = null;
    const sent = current;
    const next = newPassword;
    forget();
    try {
      const reply: UnlockReply =
        mode === 'change' ? await api.vaultChangePassword(sent, next) : await api.vaultEnableAutoUnlock(sent);
      if (reply.ok) {
        done = mode === 'change';
      } else {
        error = reply.message;
        if (reply.retryAfterMs) notBefore = Date.now() + reply.retryAfterMs;
      }
    } catch (e) {
      error = String(e).includes('too early') ? tr('Not ready yet. Wait a moment, then try again.') : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div bind:this={root}>
  {#if mode}
    <PasswordView
      {mode}
      {armed}
      {busy}
      {done}
      {wait}
      bind:current
      bind:newPassword
      bind:newAgain
      {error}
      onsubmit={submit}
      oncancel={() => api.vaultClose().catch(console.error)}
    />
  {/if}
</div>
