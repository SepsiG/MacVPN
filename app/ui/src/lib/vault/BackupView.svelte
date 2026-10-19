<script lang="ts">
  // "Back up everything" as its window shows it (the window's logic is in Backup.svelte): what the file holds, the
  // warning, the backup password twice with the strength hint (at least 10 characters), or – only after its own
  // confirmation step – the master password once. "Back Up…" opens the save panel; then the progress, the result.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { MIN_PASSWORD_CHARS, passwordProblem, passwordStrength, type BackupStep } from './backup';

  let {
    step,
    password = $bindable(''),
    repeat = $bindable(''),
    master = $bindable(''),
    useMaster = $bindable(false),
    error = null,
    savedName = null,
    onsave,
    onaskmaster,
    onconfirmmaster,
    oncancel,
    ondone,
  }: {
    step: BackupStep;
    password?: string;
    repeat?: string;
    /// The master password next to an own backup password (always checked before a backup).
    master?: string;
    useMaster?: boolean;
    error?: string | null;
    savedName?: string | null;
    onsave: () => void;
    /// "Use my master password…": its confirmation step.
    onaskmaster: () => void;
    /// The answer of the "Use my master password" step: true to use it.
    onconfirmmaster: (use: boolean) => void;
    oncancel: () => void;
    ondone: () => void;
  } = $props();

  const problem = $derived(passwordProblem(password, repeat, useMaster, master));
  const strength = $derived(passwordStrength(password));
  const busy = $derived(step === 'saving');
</script>

<div class="manage vault-window backup">
  <h1>
    <span class="bubble" aria-hidden="true"><Icon name="save" /></span>
    {tr('Back Up Everything')}
  </h1>
  {#if step === 'done'}
    <p class="banner ok" role="status"><Icon name="check" /><span>{tr('The backup was saved as %@.', savedName ?? '')}</span></p>
    <p class="intro">{tr('Keep the file and its password apart. To restore it, choose Restore from Backup… in the settings, or in the first-run window on a new Mac.')}</p>
    <div class="buttons">
      <button type="button" class="primary done" onclick={ondone}>{tr('Done')}</button>
    </div>
  {:else}
    <p class="intro">{tr('One encrypted file with every connection and its secrets, the folders, the shared credentials, the order and the app preferences. Paired apps are not included: they pair again after a restore.')}</p>
    <p class="banner warn warning" role="note"><Icon name="warning" /><span>{tr('Anyone with this file and its password can read all your VPN credentials.')}</span></p>
    <div class="card">
      {#if useMaster}
        <label class="field">
          <span class="caption">{tr('Master password')}</span>
          <input data-field="master" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={password} />
        </label>
        <p class="caption">{tr('The backup is protected with your master password. MacVPN checks it and does not keep a copy.')}</p>
        <button type="button" class="link separate" disabled={busy} onclick={() => { useMaster = false; password = ''; repeat = ''; master = ''; }}>{tr('Use a separate backup password')}</button>
      {:else}
        <label class="field">
          <span class="caption">{tr('Backup password')}</span>
          <input data-field="password" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={password} />
        </label>
        {#if password !== ''}
          <div class="meter {strength}" aria-live="polite">
            <span class="bar"><span></span></span>
            <span class="caption">
              {strength === 'strong' ? tr('Strong') : strength === 'fair' ? tr('Fair') : tr('Weak')}
            </span>
          </div>
        {/if}
        <label class="field">
          <span class="caption">{tr('Repeat the backup password')}</span>
          <input data-field="repeat" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={repeat} />
        </label>
        <p class="caption hint">
          {problem === 'mismatch' && repeat !== ''
            ? tr('The two passwords are not the same.')
            : tr('At least %d characters. MacVPN does not store it: without it the backup cannot be opened.', MIN_PASSWORD_CHARS)}
        </p>
        <label class="field">
          <span class="caption">{tr('Master password')}</span>
          <input data-field="current-master" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={master} />
        </label>
        <p class="caption">{tr('MacVPN checks your master password before every backup.')}</p>
        <button type="button" class="link use-master" disabled={busy} onclick={onaskmaster}>{tr('Use my master password…')}</button>
      {/if}
    </div>
    {#if error}
      <p class="banner error" role="alert"><Icon name="warning" /><span>{error}</span></p>
    {/if}
    <div class="buttons">
      {#if busy}
        <p class="progress left"><span class="spinner" aria-hidden="true"></span>{tr('Encrypting and saving the backup…')}</p>
      {/if}
      <button type="button" class="cancel" disabled={busy} onclick={oncancel}>{tr('Cancel')}</button>
      <button type="button" class="primary save" disabled={busy || problem !== null} onclick={() => problem === null && onsave()}>{tr('Back Up…')}</button>
    </div>
  {/if}
  {#if step === 'confirmMaster'}
    <div class="sheet" role="presentation">
      <div class="alert-card" role="alertdialog" aria-labelledby="use-master-title">
        <h2 id="use-master-title">{tr('Use your master password for this backup?')}</h2>
        <p class="caption">{tr('Then anyone who learns your master password can also open this file, wherever it is kept. A separate backup password keeps the two apart.')}</p>
        <div class="buttons">
          <button type="button" class="cancel-master" onclick={() => onconfirmmaster(false)}>{tr('Cancel')}</button>
          <button type="button" class="primary confirm-master" onclick={() => onconfirmmaster(true)}>{tr('Use Master Password')}</button>
        </div>
      </div>
    </div>
  {/if}
</div>
