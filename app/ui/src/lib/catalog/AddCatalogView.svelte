<script lang="ts">
  // "Add team catalog…" (spec 5): the view only; `AddCatalog.svelte` holds the state and calls the backend, so this
  // renders the same on the server (tests).
  //   1. enter: paste a subscription string (the backend reads it: the source and the fingerprint are shown, the
  //      team key never), or fill in the source (an https:// address or "Choose File…"), the team key and the
  //      publisher fingerprint; an optional access token. "Check" needs a fingerprint: there is no trust on first use.
  //   2. preview: the verified catalog's name, version, fingerprint ("compare it…"), counts, credential slots, risky
  //      settings and team secrets; "Subscribe" only once the fingerprint comparison is ticked.
  // Once "Check" succeeded, the pasted string, the team key and the token are gone from the form (and the DOM).
  import { connectionsText, foldersText } from '../counts';
  import { tr } from '../l10n.svelte';
  import type { CatalogPreview } from './catalogApi';
  import Sheet from './Sheet.svelte';
  import { EXAMPLES, canCheck, formatFingerprint, formatTeamKey, type AddForm } from './subscription';

  let {
    step,
    form = $bindable(),
    preview = null,
    compared = false,
    busy = false,
    error = null,
    onpaste,
    onclearpaste,
    onchoosefile,
    oncheck,
    onback,
    oncompared,
    onsubscribe,
    oncancel,
  }: {
    step: 'enter' | 'preview';
    form: AddForm;
    preview?: CatalogPreview | null;
    /// The user ticked "I compared the fingerprint".
    compared?: boolean;
    busy?: boolean;
    error?: string | null;
    onpaste: (text: string) => void;
    onclearpaste: () => void;
    onchoosefile: () => void;
    oncheck: () => void;
    onback: () => void;
    oncompared: (on: boolean) => void;
    onsubscribe: () => void;
    oncancel: () => void;
  } = $props();

  const ready = $derived(canCheck(form));
</script>

<Sheet title={tr('Add Team Catalog')} wide {oncancel}>
  {#snippet children()}
    {#if step === 'enter'}
      <p class="secondary">
        {tr('Paste the subscription string your administrator sent you, or enter the source, the team key and the publisher fingerprint.')}
      </p>
      {#if form.parsed}
        <div class="parsed" data-parsed>
          <p class="parsed-title">{tr('Subscription string read')}</p>
          <div class="form-row"><span>{tr('Source')}</span><span class="value">{form.parsed.source}</span></div>
          <div class="form-row"><span>{tr('Publisher fingerprint')}</span><span class="value mono">{form.parsed.fingerprint}</span></div>
          <p class="hint">{tr('The team key was checked and stays hidden.')}</p>
          <button class="clear-paste" onclick={onclearpaste}>{tr('Enter the fields instead')}</button>
        </div>
      {:else}
        <label class="paste">
          <span class="label">{tr('Subscription string')}</span>
          <textarea
            class="paste-field mono"
            rows="2"
            spellcheck="false"
            autocomplete="off"
            placeholder={EXAMPLES.subscription}
            value=""
            oninput={(e) => {
              // The text leaves the field at once, whatever it is: a subscription string is kept in memory only,
              // anything else is refused (it may be a team key or a token pasted here by mistake).
              const text = e.currentTarget.value;
              e.currentTarget.value = '';
              onpaste(text);
            }}
          ></textarea>
        </label>
        <p class="or">{tr('or')}</p>
        <div class="form-row">
          <span>{tr('Source')}</span>
          <div class="segmented source-kind" role="radiogroup" aria-label={tr('Source')}>
            <button role="radio" aria-checked={form.sourceKind === 'https'} class:on={form.sourceKind === 'https'} onclick={() => (form.sourceKind = 'https')}
              >{tr('HTTPS address')}</button
            >
            <button role="radio" aria-checked={form.sourceKind === 'file'} class:on={form.sourceKind === 'file'} onclick={() => (form.sourceKind = 'file')}
              >{tr('File')}</button
            >
          </div>
        </div>
        {#if form.sourceKind === 'https'}
          <label class="form-row">
            <span>{tr('Address')}</span>
            <input class="source-url" type="text" placeholder={EXAMPLES.url} autocomplete="off" spellcheck="false" bind:value={form.url} />
          </label>
        {:else}
          <div class="form-row">
            <span>{tr('File')}</span>
            <div class="file">
              <span class="file-name" class:none={!form.fileName}>{form.fileName ?? tr('No file chosen')}</span>
              <button class="choose-file" onclick={onchoosefile}>{tr('Choose File…')}</button>
            </div>
          </div>
        {/if}
        <label class="form-row">
          <span>{tr('Team key')}</span>
          <input
            class="team-key mono"
            type="text"
            placeholder={EXAMPLES.teamKey}
            autocomplete="off"
            spellcheck="false"
            value={form.teamKey}
            oninput={(e) => (form.teamKey = e.currentTarget.value)}
            onblur={() => (form.teamKey = formatTeamKey(form.teamKey))}
          />
        </label>
        <label class="form-row">
          <span>{tr('Publisher fingerprint')}</span>
          <input
            class="fingerprint mono"
            type="text"
            placeholder={EXAMPLES.fingerprint}
            autocomplete="off"
            spellcheck="false"
            value={form.fingerprint}
            oninput={(e) => (form.fingerprint = formatFingerprint(e.currentTarget.value))}
          />
        </label>
        <p class="hint">{tr('The fingerprint is required: MacVPN never trusts a first download without it.')}</p>
      {/if}
      <label class="form-row">
        <span>{tr('Access token')}</span>
        <input class="token" type="password" placeholder={tr('Optional, HTTPS only')} autocomplete="off" bind:value={form.token} />
      </label>
    {:else if preview}
      <div class="preview" data-preview>
        <p class="name">{preview.name}</p>
        <p class="secondary">{tr('Version %lld', preview.version)}</p>
        <div class="fingerprint-box">
          <span class="label">{tr('Publisher fingerprint')}</span>
          <span class="mono big">{preview.fingerprint}</span>
          <span class="hint">{tr('Compare it with what your administrator sent you. If it differs, do not subscribe.')}</span>
        </div>
        <ul class="facts">
          <li>{connectionsText(preview.connections)}</li>
          <li>{foldersText(preview.folders)}</li>
          {#if preview.slots.length > 0}
            <li>{tr('Credential slots: %@', preview.slots.join(', '))}</li>
            <li class="hint">{tr('You enter your own user name and password for them when you first connect.')}</li>
          {/if}
          {#if preview.risky > 0}
            <li class="warn">{tr('Connections with risky settings: %lld. You acknowledge them yourself in each editor.', preview.risky)}</li>
          {/if}
          {#if preview.teamSecrets > 0}
            <li>{tr('Team secrets included: %lld', preview.teamSecrets)}</li>
          {/if}
        </ul>
        <label class="compared">
          <input type="checkbox" checked={compared} onchange={(e) => oncompared(e.currentTarget.checked)} />
          {tr('The fingerprint matches what my administrator sent me')}
        </label>
      </div>
    {/if}
    {#if error}
      <p class="form-error" role="alert">{error}</p>
    {/if}
  {/snippet}
  {#snippet buttons()}
    <button class="cancel" onclick={oncancel}>{tr('Cancel')}</button>
    {#if step === 'enter'}
      <button class="primary check" disabled={!ready || busy} onclick={oncheck}>{busy ? tr('Checking…') : tr('Check')}</button>
    {:else}
      <button class="back" disabled={busy} onclick={onback}>{tr('Back')}</button>
      <button class="primary subscribe" disabled={!compared || busy} onclick={onsubscribe}>{tr('Subscribe')}</button>
    {/if}
  {/snippet}
</Sheet>

<style>
  .paste {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .label {
    color: var(--secondary);
  }
  .paste-field {
    resize: none;
    width: 100%;
    box-sizing: border-box;
  }
  .or {
    align-self: center;
    font-size: var(--text-sm);
    color: var(--tertiary);
  }
  .segmented {
    display: inline-flex;
    gap: 2px;
    padding: 2px;
    border-radius: var(--radius-control);
    background: var(--fill-hover);
    justify-self: start;
  }
  .segmented button {
    min-height: 22px;
    padding: 2px 12px;
    border: none;
    border-radius: calc(var(--radius-control) - 2px);
    background: transparent;
    box-shadow: none;
    color: var(--secondary);
  }
  .segmented button.on {
    background: var(--segment-on);
    color: var(--text);
    box-shadow: var(--shadow-control);
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
  .file-name.none {
    color: var(--tertiary);
  }
  .parsed,
  .fingerprint-box {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: 12px 14px;
    border-radius: var(--radius-card);
    background: var(--surface-sunken);
  }
  .parsed-title {
    font-weight: 600;
  }
  .parsed .value {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .clear-paste {
    align-self: flex-start;
  }
  .preview {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .name {
    font-size: var(--text-lg);
    font-weight: 650;
  }
  .big {
    font-size: 14px;
    font-weight: 600;
    -webkit-user-select: text;
    user-select: text;
  }
  .facts {
    margin: 0;
    padding-left: 18px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .warn {
    color: var(--state-busy-text);
  }
  .compared {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    font-weight: 500;
  }
  .compared input {
    flex: none;
    margin: 2px 0 0;
  }
</style>
