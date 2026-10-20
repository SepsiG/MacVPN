<script lang="ts" module>
  /// The admin key page's dialogs: export the backup key, import a key file, switch to the backup key.
  export type KeyDialog = 'export' | 'import' | 'promote' | null;
</script>

<script lang="ts">
  // The admin key page (spec 7, user guide 16.7 and 16.10): the admin key (Generate, its fingerprint with Copy),
  // the backup admin key (Generate, Export to a password-protected file with "Remove the backup key from this Mac
  // after export", its offline state), Import admin key, Switch to the backup key; and what a successor is for: a
  // planned key change, not recovery from a compromise. Passwords are sent once and cleared at once.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import Modal from '../manage/Modal.svelte';
  import { MIN_PASSWORD_CHARS, passwordsReady } from '../vault/strength';
  import Fingerprint from './Fingerprint.svelte';
  import { dateText } from './labels';
  import { publishApi, type AdminKeyRole, type AdminKeyView } from './publishApi';

  let {
    keys,
    dialog = $bindable(null),
  }: {
    keys: AdminKeyView[];
    dialog?: KeyDialog;
  } = $props();

  const primary = $derived(keys.find((k) => k.role === 'primary') ?? null);
  const backup = $derived(keys.find((k) => k.role === 'backup') ?? null);

  let busy = $state(false);
  let failure = $state<string | null>(null);
  let notice = $state<string | null>(null);
  // The dialogs' fields (cleared when sent or closed).
  let password = $state('');
  let again = $state('');
  let removeAfter = $state(false);
  let keyFile = $state<string | null>(null);
  let dialogError = $state<string | null>(null);

  function open(next: KeyDialog) {
    password = '';
    again = '';
    removeAfter = false;
    keyFile = null;
    dialogError = null;
    dialog = next;
  }

  function close() {
    password = '';
    again = '';
    keyFile = null;
    dialog = null;
  }

  async function run(action: () => Promise<void>) {
    if (busy) return;
    busy = true;
    failure = null;
    notice = null;
    try {
      await action();
    } catch (e) {
      failure = String(e);
    } finally {
      busy = false;
    }
  }

  function generate(role: AdminKeyRole) {
    run(async () => {
      await publishApi.generateKey(role);
    }).catch(console.error);
  }

  async function exportKey() {
    if (!passwordsReady(password, again)) {
      dialogError = password !== again ? tr('The two passwords are not the same.') : tr('At least %d characters.', MIN_PASSWORD_CHARS);
      return;
    }
    const secret = password;
    const remove = removeAfter;
    password = '';
    again = '';
    busy = true;
    try {
      const name = await publishApi.exportKey(secret, remove);
      if (name === null) return;
      dialog = null;
      notice = remove
        ? tr('The backup key was saved as %@ and removed from this Mac. Keep the file offline and its password somewhere else.', name)
        : tr('The backup key was saved as %@. Keep the file offline and its password somewhere else.', name);
    } catch (e) {
      dialogError = String(e);
    } finally {
      busy = false;
    }
  }

  async function chooseFile() {
    dialogError = null;
    try {
      const name = await publishApi.chooseKeyFile();
      if (name !== null) keyFile = name;
    } catch (e) {
      dialogError = String(e);
    }
  }

  async function importKey() {
    if (keyFile === null) {
      dialogError = tr('Choose the admin key file first.');
      return;
    }
    const secret = password;
    password = '';
    busy = true;
    try {
      const fingerprint = await publishApi.importKey(secret);
      dialog = null;
      keyFile = null;
      notice = tr('The admin key %@ was imported.', fingerprint);
    } catch (e) {
      dialogError = String(e);
    } finally {
      busy = false;
    }
  }

  function promote() {
    dialog = null;
    run(async () => {
      await publishApi.promoteKey();
      notice = tr('The backup key is now the admin key. Publish a new version of each catalog, then generate and export a new backup key.');
    }).catch(console.error);
  }
</script>

<div class="card admin-key" data-role="primary">
  <div class="head">
    <span class="badge-icon" aria-hidden="true"><Icon name="key" /></span>
    <div class="text">
      <h2>{tr('Admin Key')}</h2>
      <span class="caption">{tr('An Ed25519 signing key in your vault. Its fingerprint is what your team compares when subscribing.')}</span>
    </div>
    {#if primary}<span class="pill on">{tr('On this Mac')}</span>{/if}
  </div>
  {#if primary}
    <Fingerprint value={primary.fingerprint} />
    <p class="caption">{tr('Created %@', dateText(primary.created))}</p>
  {:else}
    <p class="secondary">{tr('Publishing needs an admin key. Generate one, or import the key file of the Mac you published from.')}</p>
  {/if}
  <div class="buttons">
    {#if !primary}
      <button class="primary generate-primary" disabled={busy} onclick={() => generate('primary')}>{tr('Generate Admin Key')}</button>
    {/if}
    <button class="import-key" disabled={busy} onclick={() => open('import')}>{tr('Import Admin Key…')}</button>
  </div>
</div>

<div class="card admin-key" data-role="backup">
  <div class="head">
    <span class="badge-icon" aria-hidden="true"><Icon name="lock" /></span>
    <div class="text">
      <h2>{tr('Backup Admin Key')}</h2>
      <span class="caption">{tr('Every catalog you publish announces it as the successor of the admin key, so you can switch to it without every member subscribing again.')}</span>
    </div>
    {#if backup}
      <span class="pill {backup.offline ? 'on' : 'busy'} offline-state">{backup.offline ? tr('Offline: only in the exported file') : tr('On this Mac')}</span>
    {/if}
  </div>
  {#if backup}
    <Fingerprint value={backup.fingerprint} />
    <p class="caption">{tr('Created %@', dateText(backup.created))}</p>
    {#if backup.offline}
      <p class="caption backups-note">{tr('Full backups made before the export still contain the backup key: keep them as safe as the key file.')}</p>
    {:else}
      <p class="note">{tr('Export it to a password-protected file and remove it from this Mac: keep the file offline, for example on a USB stick in a safe, and its password somewhere else.')}</p>
    {/if}
  {:else}
    <p class="secondary">{tr('No backup admin key yet.')}</p>
  {/if}
  <div class="buttons">
    {#if !backup}
      <button class="generate-backup" disabled={busy || !primary} onclick={() => generate('backup')}>{tr('Generate Backup Admin Key')}</button>
    {:else}
      <button class="export-key" disabled={busy || backup.offline} onclick={() => open('export')}>{tr('Export Backup Key…')}</button>
      <span class="spacer"></span>
      <button class="promote-key" disabled={busy || backup.offline} onclick={() => open('promote')}>{tr('Switch to the Backup Key…')}</button>
    {/if}
  </div>
  {#if backup?.offline}
    <p class="caption">{tr('To switch to it, import the backup key file first (Import Admin Key…).')}</p>
  {/if}
</div>

<div class="card successor-note">
  <p class="banner info"><Icon name="help" /><span>{tr('Switching to the backup key is a planned key change, not recovery from a compromise: whoever holds a leaked admin key can announce their own successor and sign versions your members accept.')}</span></p>
  <p class="secondary">{tr('If the admin key may have leaked: generate a new admin key on a Mac you trust, publish the connections as a new catalog, remove the old catalog file from the server or share, and send every member the new subscription string and fingerprint through a trusted channel. Change the team secrets of the old catalog too.')}</p>
</div>

{#if failure}
  <p class="banner error" role="alert"><Icon name="warning" /><span>{failure}</span></p>
{/if}
{#if notice}
  <p class="banner ok" role="status"><Icon name="check" /><span>{notice}</span></p>
{/if}

{#if dialog === 'export'}
  <Modal
    title={tr('Export Backup Key')}
    message={tr('Anyone with this file and its password can sign your team catalogs.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: close },
      { label: tr('Export…'), kind: 'primary', action: () => exportKey().catch(console.error) },
    ]}
  >
    <div class="form export-form">
      <label class="form-row"><span>{tr('Password')}</span><input data-field="key-password" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={password} /></label>
      <label class="form-row"><span>{tr('Repeat the password')}</span><input data-field="key-repeat" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={again} /></label>
      <p class="caption">{password !== '' && again !== '' && password !== again ? tr('The two passwords are not the same.') : tr('At least %d characters. Without it the file cannot be opened.', MIN_PASSWORD_CHARS)}</p>
      <p class="caption">{tr('Full backups made before the export still contain the backup key: keep them as safe as the key file.')}</p>
      <label class="check"><input class="remove-after" type="checkbox" disabled={busy} bind:checked={removeAfter} /><span>{tr('Remove the backup key from this Mac after export')}<span class="detail">{tr('The backup key is then only in that file. Its public half stays, so every catalog still announces it.')}</span></span></label>
      {#if dialogError}<p class="form-error" role="alert">{dialogError}</p>{/if}
    </div>
  </Modal>
{:else if dialog === 'import'}
  <Modal
    title={tr('Import Admin Key')}
    message={tr('Choose a .macvpnadminkey file and enter its password. Your publications (each catalog’s id, version and team key) are in the vault, not in the key file: restore a full backup first on a new Mac.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: close },
      { label: tr('Import'), kind: 'primary', action: () => importKey().catch(console.error) },
    ]}
  >
    <div class="form import-form">
      <div class="form-row">
        <span>{tr('File')}</span>
        <span class="file-pick"><button class="choose-key-file" disabled={busy} onclick={() => chooseFile().catch(console.error)}>{tr('Choose File…')}</button>{#if keyFile}<span class="file-name">{keyFile}</span>{/if}</span>
      </div>
      <label class="form-row"><span>{tr('Password')}</span><input data-field="import-password" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={password} /></label>
      {#if dialogError}<p class="form-error" role="alert">{dialogError}</p>{/if}
    </div>
  </Modal>
{:else if dialog === 'promote'}
  <Modal
    title={tr('Switch to the Backup Key?')}
    message={tr('The backup key becomes the admin key, and the old admin key is deleted from this Mac. Then publish a new version of each catalog: members that refreshed since the backup key was created follow automatically, the others must subscribe again with the new fingerprint.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: close },
      { label: tr('Switch'), kind: 'primary', action: promote },
    ]}
  />
{/if}

<style>
  .file-pick {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-width: 0;
  }
  .file-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
