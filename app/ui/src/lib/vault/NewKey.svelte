<script lang="ts">
  // The new recovery key window (`vault-recovery`), like the other vault windows (no focus steal, the one-second
  // input lock, no default button). The master password leaves the page once; the new key arrives once in the
  // reply, lives only in this page's memory while it is shown, and is dropped (from the state and the DOM) at
  // "I saved it". The window cannot be closed by its buttons before the group check passed.
  import { onMount } from 'svelte';
  import { api, onViewModel, type ViewModel } from '../api';
  import { setLanguage, tr } from '../l10n.svelte';
  import '../manage/manage.css';
  import { copyRecoveryKey } from './copy';
  import { fitToContent } from '../fit';
  import { clearInputs } from './inputs';
  import NewKeyView from './NewKeyView.svelte';
  import './vault.css';

  let armed = $state(false);
  let busy = $state(false);
  let step = $state<'password' | 'key' | 'confirm' | 'done'>('password');
  let password = $state('');
  let recoveryKey = $state<string | null>(null);
  let group = $state(0);
  let typed = $state('');
  let error = $state<string | null>(null);
  let copied = $state(false);
  let notBefore = $state(0);
  let now = $state(Date.now());
  let root: HTMLDivElement | undefined = $state();

  const wait = $derived(Math.max(0, Math.ceil((notBefore - now) / 1000)));

  function apply(next: ViewModel) {
    setLanguage(next.language);
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

  const tooEarly = (e: unknown) =>
    String(e).includes('too early') ? tr('Not ready yet. Wait a moment, then try again.') : String(e);

  async function submit() {
    if (busy) return;
    busy = true;
    error = null;
    const sent = password;
    password = '';
    clearInputs();
    try {
      const { reply, key } = await api.vaultNewRecoveryKey(sent);
      if (reply.ok && key) {
        recoveryKey = key.recoveryKey;
        group = key.group;
        step = 'key';
      } else {
        error = reply.message;
        if (reply.retryAfterMs) notBefore = Date.now() + reply.retryAfterMs;
      }
    } catch (e) {
      error = tooEarly(e);
    } finally {
      busy = false;
    }
  }

  async function confirm() {
    if (busy) return;
    busy = true;
    error = null;
    try {
      await api.vaultConfirmNewKey(group, typed);
      typed = '';
      clearInputs();
      step = 'done';
    } catch (e) {
      error = tooEarly(e);
    } finally {
      busy = false;
    }
  }
</script>

<div bind:this={root}>
  <NewKeyView
    {step}
    {armed}
    {busy}
    {wait}
    bind:password
    {recoveryKey}
    {group}
    bind:typed
    {error}
    {copied}
    onsubmit={submit}
    oncopy={async () => (copied = await copyRecoveryKey(recoveryKey))}
    onsaved={() => {
      recoveryKey = null;
      copied = false;
      error = null;
      step = 'confirm';
    }}
    onconfirm={confirm}
    oncancel={() => api.vaultClose().catch(console.error)}
  />
</div>
