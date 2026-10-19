<script lang="ts">
  // The "Back up everything" window (`backup`). The password goes to the backend once, with the save; it is cleared
  // from the fields (and this component) as soon as it is sent, whatever the result. Nothing is kept in storage.
  import { onMount } from 'svelte';
  import { api, onViewModel, type ViewModel } from '../api';
  import { setLanguage } from '../l10n.svelte';
  import '../manage/manage.css';
  import './backup.css';
  import type { BackupStep } from './backup';
  import { backupApi } from './backupApi';
  import BackupView from './BackupView.svelte';

  let step = $state<BackupStep>('form');
  let password = $state('');
  let repeat = $state('');
  /// The master password (always checked by the backend before a backup).
  let master = $state('');
  let useMaster = $state(false);
  let error = $state<string | null>(null);
  let savedName = $state<string | null>(null);

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

  function clear() {
    password = '';
    repeat = '';
    master = '';
  }

  async function save() {
    error = null;
    const name = await backupApi.chooseDestination();
    if (name === null) return;
    const secret = password;
    const current = useMaster ? password : master;
    const own = useMaster ? null : secret;
    clear();
    step = 'saving';
    try {
      await backupApi.save(current, own);
      savedName = name;
      step = 'done';
    } catch (e) {
      error = String(e);
      step = 'form';
    }
  }

  function confirmMaster(use: boolean) {
    step = 'form';
    if (use) {
      useMaster = true;
      clear();
    }
  }

  function close() {
    clear();
    backupApi.closeWindow().catch(console.error);
  }
</script>

<BackupView
  {step}
  bind:password
  bind:repeat
  bind:master
  bind:useMaster
  {error}
  {savedName}
  onsave={() => save().catch((e) => (error = String(e)))}
  onaskmaster={() => (step = 'confirmMaster')}
  onconfirmmaster={confirmMaster}
  oncancel={close}
  ondone={close}
/>
