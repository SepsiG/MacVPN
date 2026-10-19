<script lang="ts">
  // The "Restore from backup" window (`restore`): the file and its password, the plan (Merge with one conflict
  // answer, or Replace everything after a confirmation that names the count and offers a backup first), the
  // progress, then the preferences and the native profiles. The backend refuses a replace whose count no longer
  // matches the vault, so a change made meanwhile cannot be lost unseen.
  import { onMount } from 'svelte';
  import { api, onViewModel, type ViewModel } from '../api';
  import { setLanguage, tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import '../manage/manage.css';
  import './backup.css';
  import { backupApi, type ConflictMode, type RestoreOutcome, type RestoreSummary } from './backupApi';
  import RestoreAfter from './RestoreAfter.svelte';
  import RestorePick from './RestorePick.svelte';
  import RestorePlanView from './RestorePlanView.svelte';

  let summary = $state<RestoreSummary | null>(null);
  let outcome = $state<RestoreOutcome | null>(null);
  let choice = $state<'merge' | 'replace'>('merge');
  let conflict = $state<ConflictMode>('overwrite');
  let confirming = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  /// A new pick starts with a fresh form.
  let attempt = $state(0);

  function apply(next: ViewModel) {
    setLanguage(next.language);
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    return () => {
      unlisten.then((f) => f());
    };
  });

  async function run(action: () => Promise<RestoreOutcome>) {
    confirming = false;
    busy = true;
    error = null;
    try {
      outcome = await action();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function restore() {
    if (!summary) return;
    if (choice === 'replace') {
      confirming = true;
      return;
    }
    run(() => backupApi.merge(conflict)).catch(console.error);
  }

  function back() {
    summary = null;
    error = null;
    attempt += 1;
    backupApi.discard().catch(console.error);
  }

  function close() {
    backupApi.closeWindow().catch(console.error);
  }
</script>

<div class="manage vault-window restore">
  <h1>
    <span class="bubble" aria-hidden="true"><Icon name="refresh" /></span>
    {tr('Restore from Backup')}
  </h1>
  {#if outcome}
    <RestoreAfter {outcome} ondone={close} />
  {:else if summary}
    <RestorePlanView
      {summary}
      bind:choice
      bind:conflict
      {confirming}
      {busy}
      {error}
      onrestore={restore}
      onconfirm={() => summary && run(() => backupApi.replace(summary!.lostOnReplace)).catch(console.error)}
      oncancelconfirm={() => (confirming = false)}
      onbackupfirst={() => backupApi.showWindow('backup').catch((e) => (error = String(e)))}
      onback={back}
    />
  {:else}
    {#key attempt}
      <RestorePick onopened={(s) => (summary = s)} oncancel={close} />
    {/key}
  {/if}
</div>
