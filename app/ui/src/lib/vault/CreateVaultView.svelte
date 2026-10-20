<script lang="ts">
  // The create window as it shows each step (the window's logic is in CreateVault.svelte; the steps are the
  // backend's `VaultSetup`): the intro (and, when there is 1.1 data, the Keychain note before the migration), the
  // master password twice with the strength hint and "Unlock automatically", the recovery key shown once with Copy and
  // "I saved it", the "retype group N" check, the migration and its result. There is no form and no default button:
  // Return in a field does nothing; the buttons work only once the input lock passed.
  import type { VaultSetupView } from '../api';
  import Icon from '../Icon.svelte';
  import { connectionsText, savedSecretsText } from '../counts';
  import { tr } from '../l10n.svelte';
  import { formatGroupInput } from './recovery';
  import { MIN_PASSWORD_CHARS, meetsMinimum, passwordsReady, strength } from './strength';
  import StrengthHint from './StrengthHint.svelte';

  let {
    setup,
    armed,
    busy = false,
    password = $bindable(''),
    again = $bindable(''),
    autoUnlock = $bindable(true),
    recoveryKey = null,
    typed = $bindable(''),
    error = null,
    copied = false,
    oncontinue,
    onback,
    oncreate,
    oncopy,
    onsaved,
    onconfirm,
    onretry,
    onfinish,
    onclose,
    onrestore,
    onbackup = () => {},
  }: {
    setup: VaultSetupView;
    armed: boolean;
    busy?: boolean;
    password?: string;
    again?: string;
    autoUnlock?: boolean;
    /// Only at `recoveryKey`, and only in the window's memory (from the create reply).
    recoveryKey?: string | null;
    typed?: string;
    /// The last refusal to show (localized).
    error?: string | null;
    copied?: boolean;
    oncontinue: () => void;
    onback: () => void;
    oncreate: () => void;
    oncopy: () => void;
    onsaved: () => void;
    onconfirm: () => void;
    onretry: () => void;
    onfinish: () => void;
    onclose: () => void;
    onrestore: () => void;
    /// The migration's reminder: "Back Up Everything…" (its own window).
    onbackup?: () => void;
  } = $props();

  const mismatch = $derived(again !== '' && password !== again);
  const canCreate = $derived(armed && !busy && passwordsReady(password, again));
  const groupNumber = $derived((setup.group ?? 0) + 1);
  const canConfirm = $derived(armed && !busy && typed.length === 4);
  /// "Restore from backup…" with 1.1 data: its import is replaced, which the window confirms first.
  let confirmRestore = $state(false);
</script>

<div class="vault manage create">
  {#if setup.step === 'intro'}
    <h1><span class="bubble" aria-hidden="true"><Icon name="lock" /></span>{tr('Set up the vault')}</h1>
    <p>
      {tr(
        'MacVPN keeps your connections and their passwords in an encrypted vault. A master password protects it; a recovery key gets you back in if you forget the password.',
      )}
    </p>
    {#if confirmRestore}
      <div class="note" role="alertdialog" aria-labelledby="restore-over-old">
        <Icon name="warning" />
        <span id="restore-over-old">{tr('Your MacVPN 1.1 data will not be imported. It will be deleted after the backup is restored.')}</span>
      </div>
      <div class="buttons">
        <button type="button" class="left cancel-restore" onclick={() => (confirmRestore = false)}>{tr('Cancel')}</button>
        <button type="button" class="primary confirm-restore" disabled={!armed} onclick={onrestore}>{tr('Restore from Backup…')}</button>
      </div>
    {:else if setup.migrating}
      <p>{tr('Your existing connections and saved passwords move into the vault, and the old copies are deleted after they were checked.')}</p>
      <p class="note" role="note">
        <Icon name="warning" />
        <span>
          {setup.keychainItems === 1
            ? tr('macOS may ask once for access to the Keychain — choose Always Allow. This happens only once.')
            : tr('macOS may ask up to %lld times for access to the Keychain — choose Always Allow each time. This happens only once.', setup.keychainItems)}
        </span>
      </p>
    {/if}
    {#if !confirmRestore}
      <div class="buttons">
        {#if setup.canRestore}
          <!-- With 1.1 data the restore replaces its import: the window says so first. -->
          <button
            type="button"
            class="left restore"
            disabled={!armed}
            onclick={() => (setup.migrating ? (confirmRestore = true) : onrestore())}>{tr('Restore from backup…')}</button
          >
        {/if}
        <button type="button" class="primary continue" disabled={!armed} onclick={oncontinue}>{tr('Continue')}</button>
      </div>
    {/if}
  {:else if setup.step === 'password'}
    <h1><span class="bubble" aria-hidden="true"><Icon name="lock" /></span>{tr('Choose a master password')}</h1>
    <p class="caption">{tr('At least %lld characters. A long phrase is easier to remember and harder to guess.', MIN_PASSWORD_CHARS)}</p>
    <div class="card">
      <label class="field">
        <span class="caption">{tr('Master password')}</span>
        <input data-field="password" type="password" autocomplete="new-password" spellcheck="false" disabled={!armed || busy} bind:value={password} />
      </label>
      <StrengthHint strength={strength(password)} short={password !== '' && !meetsMinimum(password)} />
      <label class="field">
        <span class="caption">{tr('Repeat the master password')}</span>
        <input data-field="again" type="password" autocomplete="new-password" spellcheck="false" disabled={!armed || busy} bind:value={again} />
      </label>
      {#if mismatch}<p class="refused" role="alert">{tr('The two passwords are not the same')}</p>{/if}
    </div>
    <label class="check">
      <input type="checkbox" bind:checked={autoUnlock} disabled={!armed || busy} />
      <span>
        {tr('Unlock automatically')}
        <span class="caption">{tr('The vault key is kept in the macOS Keychain, so MacVPN opens without asking. Turn it off to type the master password at every launch.')}</span>
      </span>
    </label>
    {#if error}<p class="refused" role="alert">{error}</p>{/if}
    <div class="buttons">
      <button type="button" class="left back" disabled={busy} onclick={onback}>{tr('Back')}</button>
      <button type="button" class="primary create-vault" disabled={!canCreate} onclick={() => canCreate && oncreate()}>
        {busy ? tr('Creating…') : tr('Create Vault')}
      </button>
    </div>
  {:else if setup.step === 'recoveryKey'}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="key" /></span>{tr('Your recovery key')}</h1>
    <p>{tr('If you forget the master password, this key is the only way back into the vault. Write it down or keep it in a password manager. It is shown only now.')}</p>
    <div class="card key-card">
      <code class="recovery-key" data-recovery-key>{recoveryKey ?? ''}</code>
      <button type="button" class="copy" disabled={!armed || !recoveryKey} onclick={oncopy}>
        <Icon name="copy" />{copied ? tr('Copied') : tr('Copy')}
      </button>
    </div>
    <div class="buttons">
      <button type="button" class="primary saved" disabled={!armed} onclick={onsaved}>{tr('I Saved It')}</button>
    </div>
  {:else if setup.step === 'confirm'}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="key" /></span>{tr('Check your recovery key')}</h1>
    <p>{tr('Type group %lld of your recovery key, counting from the left.', groupNumber)}</p>
    <div class="card">
      <label class="field">
        <span class="caption">{tr('Group %lld', groupNumber)}</span>
        <input
          data-field="group"
          type="text"
          class="group"
          maxlength="4"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          disabled={!armed || busy}
          value={typed}
          oninput={(e) => {
            typed = formatGroupInput(e.currentTarget.value);
            e.currentTarget.value = typed;
          }}
        />
      </label>
      {#if error ?? setup.message}<p class="refused" role="alert">{error ?? setup.message}</p>{/if}
    </div>
    <div class="buttons">
      <button type="button" class="primary confirm" disabled={!canConfirm} onclick={() => canConfirm && onconfirm()}>{tr('Confirm')}</button>
    </div>
  {:else if setup.step === 'migrating'}
    <h1><span class="bubble" aria-hidden="true"><Icon name="refresh" /></span>{tr('Moving your data into the vault…')}</h1>
    <p>{tr('Each connection and saved password is copied, checked, and only then deleted from the old place.')}</p>
    {#if setup.keychainItems > 0}
      <p class="note" role="note"><Icon name="warning" /><span>{tr('If macOS asks for access to the Keychain, choose Always Allow.')}</span></p>
    {/if}
    <div class="progress" aria-hidden="true"><span></span></div>
  {:else if setup.step === 'verified'}
    <h1><span class="bubble ok" aria-hidden="true"><Icon name="check" /></span>{tr('Your data is in the vault')}</h1>
    <p>
      {tr('%@ and %@ were moved and checked. The old copies are deleted when you continue.', connectionsText(setup.connections), savedSecretsText(setup.secrets))}
    </p>
    {#if setup.skipped > 0}
      <p class="note" role="note"><Icon name="warning" /><span>
          {setup.skipped === 1
            ? tr('1 item could not be read and was left where it was.')
            : tr('%lld items could not be read and were left where they were.', setup.skipped)}
        </span></p>
    {/if}
    <p class="caption">{tr('You can back up the whole vault into one encrypted file at any time from the menu’s settings.')}</p>
    {#if error}<p class="refused" role="alert">{error}</p>{/if}
    <div class="buttons">
      <button type="button" class="left backup" disabled={!armed} onclick={onbackup}>{tr('Back Up Everything…')}</button>
      <button type="button" class="primary finish" disabled={!armed} onclick={onfinish}>{tr('Continue')}</button>
    </div>
  {:else if setup.step === 'done'}
    <h1><span class="bubble ok" aria-hidden="true"><Icon name="check" /></span>{tr('The vault is ready')}</h1>
    <p>{tr('Keep your recovery key safe. You can change the master password and make a new recovery key in the menu’s settings.')}</p>
    <div class="buttons">
      <button type="button" class="primary close" onclick={onclose}>{tr('Done')}</button>
    </div>
  {:else if setup.step === 'failed'}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="warning" /></span>{tr('The migration did not finish')}</h1>
    {#if setup.message}<p class="note fail" role="alert"><Icon name="warning" /><span>{setup.message}</span></p>{/if}
    {#if setup.vaultRemoved}
      <p>{tr('Nothing was deleted. MacVPN keeps using your old data, read-only, until the migration succeeds. The new vault was removed: try again with a new master password.')}</p>
    {:else}
      <p>{tr('Your vault and its data were kept. MacVPN tries to finish the move of the old data again at the next launch, or now with Try Again.')}</p>
    {/if}
    <div class="buttons">
      <button type="button" class="left close" onclick={onclose}>{tr('Close')}</button>
      <button type="button" class="primary retry" disabled={!armed} onclick={onretry}>{tr('Try Again')}</button>
    </div>
  {/if}
</div>

<style>
  .recovery-key {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 15px;
    letter-spacing: 0.04em;
    -webkit-user-select: text;
    user-select: text;
  }
  .group {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    text-transform: uppercase;
    width: 9ch;
  }
  .progress {
    height: 4px;
    border-radius: 2px;
    background: var(--surface-sunken);
    overflow: hidden;
  }
  .progress span {
    display: block;
    width: 35%;
    height: 100%;
    border-radius: 2px;
    background: var(--accent);
    animation: slide 1.4s ease-in-out infinite;
  }
  @keyframes slide {
    from {
      transform: translateX(-100%);
    }
    to {
      transform: translateX(300%);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .progress span {
      animation: none;
      width: 100%;
      opacity: 0.4;
    }
  }
</style>
