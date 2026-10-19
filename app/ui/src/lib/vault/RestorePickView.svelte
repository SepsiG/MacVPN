<script lang="ts">
  // The first restore step: the backup file (chosen in the native open panel; only its name is shown) and its
  // password. Nothing is written by "Open": the next step shows what the restore would do.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';

  let {
    fileName,
    password = $bindable(''),
    busy = false,
    error = null,
    fresh = false,
    onchoose,
    onopen,
    oncancel,
  }: {
    fileName: string | null;
    password?: string;
    busy?: boolean;
    error?: string | null;
    /// The first-run restore (the create-vault window): a new master password comes next.
    fresh?: boolean;
    onchoose: () => void;
    onopen: () => void;
    oncancel: () => void;
  } = $props();

  const ready = $derived(fileName !== null && password !== '' && !busy);
</script>

<div class="restore-pick">
  <p class="intro">
    {fresh
      ? tr('Choose a backup made with Back Up Everything. You set a new master password for this Mac next.')
      : tr('Choose a backup made with Back Up Everything. Nothing changes before you confirm what to restore.')}
  </p>
  <div class="card">
    <div class="file">
      <span class="name" class:caption={fileName === null}>{fileName ?? tr('No file chosen')}</span>
      <button type="button" class="choose" disabled={busy} onclick={onchoose}>{tr('Choose File…')}</button>
    </div>
    <label class="field">
      <span class="caption">{tr('Backup password')}</span>
      <input data-field="backup-password" type="password" autocomplete="off" spellcheck="false" disabled={busy || fileName === null} bind:value={password} />
    </label>
  </div>
  {#if error}
    <p class="banner error" role="alert"><Icon name="warning" /><span>{error}</span></p>
  {/if}
  <div class="buttons">
    {#if busy}
      <p class="progress left"><span class="spinner" aria-hidden="true"></span>{tr('Opening the backup…')}</p>
    {/if}
    <button type="button" class="cancel" disabled={busy} onclick={oncancel}>{tr('Cancel')}</button>
    <button type="button" class="primary open" disabled={!ready} onclick={() => ready && onopen()}>{tr('Open Backup')}</button>
  </div>
</div>

<style>
  .restore-pick {
    display: contents;
  }
</style>
