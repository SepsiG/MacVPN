<script lang="ts" module>
  export type EditMode = 'source' | 'teamKey' | 'token';
  export type EditValue =
    | { mode: 'source'; url: string | null; chosenFile: boolean }
    | { mode: 'teamKey'; teamKey: string }
    | { mode: 'token'; token: string | null };
</script>

<script lang="ts">
  // A subscription's edits (spec 5, review L3): "Edit source…" (an https:// address or a file), "Change team key…"
  // (after the publisher rotated it) and "Change access token…" (also asked right after a source change that dropped
  // the token: it is never sent to a new address). The typed key and token live only in this dialog's memory until
  // "Save" sends them; the dialog then closes and they go with it.
  import { tr } from '../l10n.svelte';
  import Sheet from './Sheet.svelte';
  import { EXAMPLES, formatTeamKey, teamKeyComplete } from './subscription';

  let {
    mode,
    name,
    hasToken = false,
    tokenDropped = false,
    fileName = null,
    busy = false,
    error = null,
    onchoosefile,
    onsave,
    oncancel,
  }: {
    mode: EditMode;
    /// The catalog's name (the title).
    name: string;
    hasToken?: boolean;
    /// The source change just dropped the stored token (another host, port or a file).
    tokenDropped?: boolean;
    /// The file chosen for a file source.
    fileName?: string | null;
    busy?: boolean;
    error?: string | null;
    onchoosefile: () => void;
    onsave: (value: EditValue) => void;
    oncancel: () => void;
  } = $props();

  let sourceKind = $state<'https' | 'file'>('https');
  let url = $state('');
  let teamKey = $state('');
  let token = $state('');
  let removeToken = $state(false);

  const title = $derived(
    mode === 'source' ? tr('Edit Source of %@', name) : mode === 'teamKey' ? tr('Change Team Key of %@', name) : tr('Change Access Token of %@', name),
  );
  const ready = $derived(
    mode === 'source'
      ? sourceKind === 'https'
        ? url.trim() !== ''
        : fileName !== null
      : mode === 'teamKey'
        ? teamKeyComplete(teamKey)
        : removeToken || token.trim() !== '',
  );

  function save() {
    if (!ready || busy) return;
    if (mode === 'source') onsave({ mode, url: sourceKind === 'https' ? url.trim() : null, chosenFile: sourceKind === 'file' });
    else if (mode === 'teamKey') onsave({ mode, teamKey });
    else onsave({ mode, token: removeToken ? null : token.trim() });
  }
</script>

<Sheet {title} {oncancel}>
  {#snippet children()}
    {#if mode === 'source'}
      <p class="secondary">
        {tr('If the new source is on another host or port, or is a file, the stored access token is dropped: it is never sent to a new address.')}
      </p>
      <div class="kind" role="radiogroup" aria-label={tr('Source')}>
        <label><input type="radio" name="kind" value="https" bind:group={sourceKind} />{tr('HTTPS address')}</label>
        <label><input type="radio" name="kind" value="file" bind:group={sourceKind} />{tr('File')}</label>
      </div>
      {#if sourceKind === 'https'}
        <label class="form-row">
          <span>{tr('Address')}</span>
          <input class="source-url" type="text" placeholder={EXAMPLES.url} autocomplete="off" spellcheck="false" bind:value={url} />
        </label>
      {:else}
        <div class="form-row">
          <span>{tr('File')}</span>
          <div class="file">
            <span class="file-name">{fileName ?? tr('No file chosen')}</span>
            <button class="choose-file" onclick={onchoosefile}>{tr('Choose File…')}</button>
          </div>
        </div>
      {/if}
    {:else if mode === 'teamKey'}
      <p class="secondary">{tr('Enter the new team key your administrator sent you through a secure channel.')}</p>
      <label class="form-row">
        <span>{tr('Team key')}</span>
        <input
          class="team-key mono"
          type="text"
          placeholder={EXAMPLES.teamKey}
          autocomplete="off"
          spellcheck="false"
          bind:value={teamKey}
          onblur={() => (teamKey = formatTeamKey(teamKey))}
        />
      </label>
    {:else}
      {#if tokenDropped}
        <p class="notice" role="note">{tr('The access token is not sent to a new address. Enter the token for it, if it needs one.')}</p>
      {:else}
        <p class="secondary">{tr('The bearer token the web server asks for. It is stored in the vault and sent only to the source’s own address.')}</p>
      {/if}
      <label class="form-row">
        <span>{tr('Access token')}</span>
        <input class="token" type="password" autocomplete="off" disabled={removeToken} bind:value={token} />
      </label>
      {#if hasToken}
        <label class="check"><input type="checkbox" bind:checked={removeToken} />{tr('Remove the stored access token')}</label>
      {/if}
    {/if}
    {#if error}
      <p class="form-error" role="alert">{error}</p>
    {/if}
  {/snippet}
  {#snippet buttons()}
    <button class="cancel" onclick={oncancel}>{tokenDropped ? tr('Not Now') : tr('Cancel')}</button>
    <button class="primary save" disabled={!ready || busy} onclick={save}>{tr('Save')}</button>
  {/snippet}
</Sheet>

<style>
  .kind {
    display: flex;
    gap: var(--space-5);
  }
  .kind label,
  .check {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .file {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-width: 0;
  }
  .file-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .notice {
    padding: 8px 10px;
    border-radius: var(--radius-control);
    background: var(--state-busy-soft);
    font-size: var(--text-md);
  }
</style>
