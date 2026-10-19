<script lang="ts">
  // What the opened backup holds and what the restore would do, before anything is written: the backup's date and
  // numbers; first, the connections whose acknowledged risky OpenVPN settings a replace keeps and a merge drops;
  // then Merge (one question for every item that already exists) or Replace everything, which asks again naming
  // how many items it deletes and offers to back up the current state first. A fresh restore (the create-vault
  // window) only shows the numbers and continues to the new master password.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { backupDate } from './backup';
  import type { ConflictMode, RestoreSummary } from './backupApi';

  let {
    summary,
    choice = $bindable('merge'),
    conflict = $bindable('overwrite'),
    confirming = false,
    busy = false,
    error = null,
    onrestore,
    onconfirm,
    oncancelconfirm,
    onbackupfirst,
    onback,
  }: {
    summary: RestoreSummary;
    choice?: 'merge' | 'replace';
    conflict?: ConflictMode;
    /// The "Replace everything?" question is shown.
    confirming?: boolean;
    busy?: boolean;
    error?: string | null;
    /// "Restore" (a merge runs at once; a replace asks first) or, for a fresh restore, "Continue".
    onrestore: () => void;
    /// "Replace Everything" in the question.
    onconfirm: () => void;
    oncancelconfirm: () => void;
    onbackupfirst: () => void;
    onback: () => void;
  } = $props();
</script>

<div class="restore-plan">
  <p class="caption made">{tr('Made on %@ by MacVPN %@', backupDate(summary.created), summary.appVersion)}</p>
  <div class="numbers">
    <p class="number"><strong>{summary.connections}</strong><span class="caption">{tr('Connections')}</span></p>
    <p class="number"><strong>{summary.folders}</strong><span class="caption">{tr('Folders')}</span></p>
    <p class="number"><strong>{summary.credentials}</strong><span class="caption">{tr('Shared credentials')}</span></p>
  </div>
  {#if summary.acknowledgedRisky.length > 0}
    <div class="banner warn risky" role="note">
      <Icon name="warning" />
      <div>
        <p>{tr('These connections have acknowledged risky OpenVPN settings, such as scripts that run as root:')}</p>
        <ul class="list">
          {#each summary.acknowledgedRisky as name, i (i)}
            <li>{name}</li>
          {/each}
        </ul>
        <p class="caption">
          {summary.fresh
            ? tr('The restore keeps these acknowledgements. Restore only a backup you made yourself.')
            : tr('Replace everything keeps these acknowledgements. A merge drops them unless the same connection with the same config is already here; its editor then asks again.')}
        </p>
      </div>
    </div>
  {/if}
  {#if !summary.fresh}
    <div class="card choices" role="radiogroup">
      <label class="check">
        <input type="radio" name="restore-mode" value="merge" disabled={busy} bind:group={choice} />
        <span>
          {tr('Merge')}
          <span class="caption">{tr('Adds what is missing here: %lld new items. Already here: %lld.', summary.added, summary.conflicts)}</span>
        </span>
      </label>
      {#if choice === 'merge' && summary.conflicts > 0}
        <div class="conflicts" role="radiogroup" aria-labelledby="conflict-question">
          <p class="caption" id="conflict-question">{tr('When an item already exists:')}</p>
          <label class="check">
            <input type="radio" name="conflict" value="overwrite" disabled={busy} bind:group={conflict} />
            <span>{tr('Overwrite it with the backup’s copy')}</span>
          </label>
          <label class="check">
            <input type="radio" name="conflict" value="keepExisting" disabled={busy} bind:group={conflict} />
            <span>{tr('Keep the item that is here')}</span>
          </label>
          <label class="check">
            <input type="radio" name="conflict" value="keepBoth" disabled={busy} bind:group={conflict} />
            <span>{tr('Keep both (the backup’s copy is named “(backup)”)')}</span>
          </label>
        </div>
      {/if}
      <label class="check">
        <input type="radio" name="restore-mode" value="replace" disabled={busy} bind:group={choice} />
        <span>
          {tr('Replace everything')}
          <span class="caption">{tr('Clears the vault first. Not in the backup, deleted: %lld items. Paired apps stay.', summary.lostOnReplace)}</span>
        </span>
      </label>
    </div>
  {/if}
  {#if error}
    <p class="banner error" role="alert"><Icon name="warning" /><span>{error}</span></p>
  {/if}
  <div class="buttons">
    {#if busy}
      <p class="progress left"><span class="spinner" aria-hidden="true"></span>{tr('Restoring…')}</p>
    {/if}
    <button type="button" class="back" disabled={busy} onclick={onback}>{tr('Back')}</button>
    <button type="button" class="primary restore" disabled={busy} onclick={onrestore}>
      {summary.fresh ? tr('Continue') : choice === 'replace' ? tr('Replace Everything…') : tr('Merge')}
    </button>
  </div>
  {#if confirming}
    <div class="sheet" role="presentation">
      <div class="alert-card" role="alertdialog" aria-labelledby="replace-title">
        <h2 id="replace-title">{tr('Replace everything?')}</h2>
        <p class="caption lost">
          {tr('Connections, folders and shared credentials here that are not in the backup are deleted: %lld items. This cannot be undone.', summary.lostOnReplace)}
        </p>
        <button type="button" class="link backup-first" onclick={onbackupfirst}>{tr('Back Up the Current State First…')}</button>
        <div class="buttons">
          <button type="button" class="cancel-replace" onclick={oncancelconfirm}>{tr('Cancel')}</button>
          <button type="button" class="destructive confirm-replace" onclick={onconfirm}>{tr('Replace Everything')}</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .restore-plan {
    display: contents;
  }
  .conflicts {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0 0 0 24px;
  }
  .risky > div {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .risky .caption {
    color: inherit;
    opacity: 0.85;
  }
</style>
