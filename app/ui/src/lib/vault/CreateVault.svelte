<script lang="ts">
  // The create window (`vault-create`), like the prompt windows: it does not take the focus when it appears, nothing
  // works in the first second after it became visible (the backend counts its own lock from the page's ready signal
  // and from ordering the window on screen, and refuses an earlier call too), and there is no default button. The
  // backend owns the steps (`vaultSetup` in the view model). The master password leaves the page only in
  // `vault_create`; the recovery key arrives once in its reply, lives only in this page's memory while it is shown,
  // and is dropped (with every typed value, from the state and the DOM) once the step moves on.
  // "Restore from backup…" at the intro opens a backup here first (RestorePick, fresh); the window then goes through
  // the master password and the recovery key as for a new vault, restores the backup into it (instead of the
  // migration) and offers the preferences and the native profiles (RestoreAfter).
  import { onMount } from 'svelte';
  import { api, onViewModel, type VaultSetupAction, type ViewModel } from '../api';
  import { setLanguage, tr } from '../l10n.svelte';
  import '../manage/manage.css';
  import { copyRecoveryKey } from './copy';
  import CreateVaultView from './CreateVaultView.svelte';
  import { fitToContent } from '../fit';
  import { clearInputs } from './inputs';
  import Icon from '../Icon.svelte';
  import { backupApi, type RestoreOutcome } from './backupApi';
  import RestoreAfter from './RestoreAfter.svelte';
  import RestorePick from './RestorePick.svelte';
  import './backup.css';
  import './vault.css';

  let vm = $state<ViewModel | null>(null);
  let armed = $state(false);
  let busy = $state(false);
  let password = $state('');
  let again = $state('');
  let autoUnlock = $state(true);
  let recoveryKey = $state<string | null>(null);
  let typed = $state('');
  let error = $state<string | null>(null);
  let copied = $state(false);
  let root: HTMLDivElement | undefined = $state();

  const setup = $derived(vm?.vaultSetup ?? null);
  /// The intro's "Restore from backup…": the backup's file and password are asked here first.
  let picking = $state(false);
  /// The fresh restore's result, once the backup is in the new vault.
  let outcome = $state<RestoreOutcome | null>(null);
  let restoring = $state(false);
  let restoreError = $state<string | null>(null);
  /// After the recovery key check of a restore: the backup goes into the new vault (once; again with Try Again).
  const restoreDue = $derived(!!setup?.restoring && setup.step === 'done' && outcome === null);

  $effect(() => {
    if (restoreDue && !restoring && restoreError === null) applyRestore().catch(console.error);
  });

  async function applyRestore() {
    restoring = true;
    restoreError = null;
    try {
      outcome = await backupApi.freshApply();
    } catch (e) {
      restoreError = String(e);
    } finally {
      restoring = false;
    }
  }

  /// The backup is open: on to the master password (the backend checks the window opened one).
  async function opened() {
    error = null;
    try {
      await api.vaultOpenRestore();
      picking = false;
    } catch (e) {
      error = String(e);
      picking = false;
      backupApi.discard().catch(console.error);
    }
  }

  function cancelPick() {
    picking = false;
    backupApi.discard().catch(console.error);
  }

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
    // Past the key: it is forgotten here too.
    if (next.vaultSetup && next.vaultSetup.step !== 'recoveryKey' && recoveryKey !== null) recoveryKey = null;
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    let arm: ReturnType<typeof setTimeout> | undefined;
    api.vaultReady().then(() => {
      arm = setTimeout(() => {
        armed = true;
        document.querySelector<HTMLElement>('button.primary:not(:disabled), input[data-field]:not(:disabled)')?.focus();
      }, 1000);
    }, console.error);
    const stop = fitToContent(root ?? null, api.fitWindow);
    return () => {
      clearTimeout(arm);
      stop();
      unlisten.then((f) => f());
    };
  });

  function forgetPasswords() {
    password = '';
    again = '';
    clearInputs();
  }

  async function step(action: VaultSetupAction) {
    error = null;
    try {
      await api.vaultSetupStep(action);
      if (action === 'saved') {
        recoveryKey = null;
        copied = false;
      }
    } catch (e) {
      error = String(e);
    }
  }

  async function create() {
    if (busy) return;
    busy = true;
    error = null;
    const sent = password;
    forgetPasswords();
    try {
      const reply = await api.vaultCreate(sent, autoUnlock);
      recoveryKey = reply.recoveryKey;
    } catch (e) {
      error = String(e).includes('too early') ? tr('Not ready yet. Wait a moment, then try again.') : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy() {
    copied = await copyRecoveryKey(recoveryKey);
  }

  async function confirm() {
    if (busy || setup?.group == null) return;
    busy = true;
    error = null;
    const sent = typed;
    try {
      await api.vaultConfirmRecovery(setup.group, sent);
      typed = '';
      clearInputs();
    } catch (e) {
      error = String(e).includes('too early') ? tr('Not ready yet. Wait a moment, then try again.') : String(e);
    } finally {
      busy = false;
    }
  }

  function restore() {
    error = null;
    picking = true;
  }
</script>

<div bind:this={root}>
  {#if setup && picking && setup.step === 'intro'}
    <div class="manage vault-window fresh restore">
      <h1><span class="bubble" aria-hidden="true"><Icon name="refresh" /></span>{tr('Restore from Backup')}</h1>
      <RestorePick fresh onopened={() => opened().catch(console.error)} oncancel={cancelPick} />
    </div>
  {:else if setup && restoreDue}
    <div class="manage vault-window fresh restore">
      <h1><span class="bubble" aria-hidden="true"><Icon name="refresh" /></span>{tr('Restore from Backup')}</h1>
      {#if restoreError}
        <p class="banner error" role="alert"><Icon name="warning" /><span>{restoreError}</span></p>
        <div class="buttons">
          <button type="button" class="primary retry-restore" onclick={() => applyRestore().catch(console.error)}>{tr('Try Again')}</button>
        </div>
      {:else}
        <p class="progress"><span class="spinner" aria-hidden="true"></span>{tr('Restoring…')}</p>
      {/if}
    </div>
  {:else if setup && setup.restoring && setup.step === 'done' && outcome}
    <div class="manage vault-window fresh restore">
      <h1><span class="bubble ok" aria-hidden="true"><Icon name="check" /></span>{tr('Restore from Backup')}</h1>
      <RestoreAfter {outcome} ondone={() => step('close')} />
    </div>
  {:else if setup}
    <CreateVaultView
      {setup}
      {armed}
      {busy}
      bind:password
      bind:again
      bind:autoUnlock
      {recoveryKey}
      bind:typed
      {error}
      {copied}
      oncontinue={() => step('continue')}
      onback={() => {
        forgetPasswords();
        step('back');
      }}
      oncreate={create}
      oncopy={copy}
      onsaved={() => step('saved')}
      onconfirm={confirm}
      onretry={() => step('retry')}
      onfinish={() => step('finish')}
      onclose={() => step('close')}
      onrestore={restore}
      onbackup={() => backupApi.showWindow('backup').catch((e) => (error = String(e)))}
    />
  {/if}
</div>
