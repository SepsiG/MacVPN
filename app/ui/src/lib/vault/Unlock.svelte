<script lang="ts">
  // The unlock window (`vault-unlock`), like the prompt windows: no focus steal, the one-second input lock (the
  // backend refuses an earlier call too), no default button. The password or the recovery key and the new password
  // leave the page once, in `vault_unlock` / `vault_recover`, and are cleared from the state and the DOM right after.
  // A wrong attempt shows the backend's delay as a countdown. The window closes when the vault opens.
  import { onMount } from 'svelte';
  import { api, onViewModel, type UnlockReply, type ViewModel } from '../api';
  import { setLanguage, tr } from '../l10n.svelte';
  import '../manage/manage.css';
  import { fitToContent } from '../fit';
  import { clearInputs } from './inputs';
  import UnlockView from './UnlockView.svelte';
  import './vault.css';

  let armed = $state(false);
  let busy = $state(false);
  let mode = $state<'password' | 'recovery'>('password');
  let password = $state('');
  let recoveryKey = $state('');
  let newPassword = $state('');
  let newAgain = $state('');
  let error = $state<string | null>(null);
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

  function forget() {
    password = '';
    recoveryKey = '';
    newPassword = '';
    newAgain = '';
    clearInputs();
  }

  function show(reply: UnlockReply) {
    if (reply.ok) return;
    error = reply.message;
    if (reply.retryAfterMs) notBefore = Date.now() + reply.retryAfterMs;
  }

  async function run(call: () => Promise<UnlockReply>) {
    if (busy) return;
    busy = true;
    error = null;
    try {
      const reply = await call();
      show(reply);
    } catch (e) {
      error = String(e).includes('too early') ? tr('Not ready yet. Wait a moment, then try again.') : String(e);
    } finally {
      busy = false;
    }
  }

  function unlock() {
    const sent = password;
    forget();
    return run(() => api.vaultUnlock(sent));
  }

  function recover() {
    const key = recoveryKey;
    const sent = newPassword;
    forget();
    return run(() => api.vaultRecover(key, sent));
  }

  function switchMode(next: 'password' | 'recovery') {
    forget();
    error = null;
    mode = next;
  }
</script>

<div bind:this={root}>
  <UnlockView
    {mode}
    {armed}
    {busy}
    {wait}
    bind:password
    bind:recoveryKey
    bind:newPassword
    bind:newAgain
    {error}
    onunlock={unlock}
    onrecover={recover}
    onmode={switchMode}
  />
</div>
