<script lang="ts">
  // Choose and open a backup (the restore window, and the create-vault window's "Restore from backup…" branch of
  // plan B Task 14, with `fresh`). The password is sent once with "Open Backup" and cleared from the field at once,
  // whatever the result. `onopened` gets the plan's numbers; nothing has been written yet.
  import { backupApi, type RestoreSummary } from './backupApi';
  import RestorePickView from './RestorePickView.svelte';

  let {
    fresh = false,
    onopened,
    oncancel,
  }: {
    fresh?: boolean;
    onopened: (summary: RestoreSummary) => void;
    oncancel: () => void;
  } = $props();

  let fileName = $state<string | null>(null);
  let password = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function choose() {
    error = null;
    const name = await backupApi.chooseFile();
    if (name !== null) {
      fileName = name;
      password = '';
    }
  }

  async function open() {
    const secret = password;
    password = '';
    error = null;
    busy = true;
    try {
      onopened(await backupApi.open(secret));
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<RestorePickView
  {fileName}
  bind:password
  {busy}
  {error}
  {fresh}
  onchoose={() => choose().catch((e) => (error = String(e)))}
  onopen={() => open().catch(console.error)}
  {oncancel}
/>
