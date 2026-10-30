<script lang="ts">
  // The credential prompt as its window shows it (the window's logic is in CredentialPrompt.svelte): the
  // connection's name, the shared credential the password belongs to ("Password for Office AD — used by 4
  // connections"; "Save in vault" then updates the credential; a team slot also shows the server and the catalog's
  // source), the re-prompt's "Sign-in failed" line, only the asked fields (the user name as text,
  // pre-filled when one is stored; the others as password fields), "Save in vault" (ticked by default) and Connect /
  // Cancel. There is no form and no default button: Return in a field does nothing, Connect needs a click (or Space
  // on the focused button), and it works only once the input lock passed and every field has a value.
  import type { CredentialField, CredentialPromptView } from './api';
  import { canConnect, isSecretField, orderedFields } from './credentials';
  import Icon from './Icon.svelte';
  import { tr } from './l10n.svelte';
  import { countdown } from './prompt';

  let {
    prompt,
    values = $bindable({}),
    save = $bindable(true),
    armed,
    left,
    error = null,
    onconnect,
    oncancel,
  }: {
    prompt: CredentialPromptView;
    values?: Partial<Record<CredentialField, string>>;
    save?: boolean;
    armed: boolean;
    left: number;
    /// Why the last answer was not taken (`tooEarly` or `rejected`); cleared by the window on the next input.
    error?: 'tooEarly' | 'rejected' | null;
    onconnect: () => void;
    oncancel: () => void;
  } = $props();

  const fields = $derived(orderedFields(prompt.fields));
  /// "Show" of a typed secret (only what the user typed here: a stored value never reaches this window).
  let shown = $state<Partial<Record<CredentialField, boolean>>>({});

  /// A field's label (the editors' texts).
  function label(field: CredentialField): string {
    switch (field) {
      case 'username':
        return tr('Username');
      case 'password':
        return tr('Password');
      case 'psk':
        return tr('Shared secret (PSK)');
      case 'keyPassword':
        return tr('Private key password');
    }
  }
  const ready = $derived(canConnect(fields, values, armed));
</script>

<div class="manage credentials">
  <h1>
    <span class="bubble" aria-hidden="true"><Icon name="key" /></span>
    {tr('Credentials needed')}
  </h1>
  <p class="name">{prompt.connectionName}</p>
  {#if prompt.credentialName && prompt.team}
    <!-- A team catalog's credential slot (its first use): "Save in vault" fills the slot for every connection. -->
    <p class="caption shared">
      {fields.includes('username')
        ? tr('%@ (team catalog “%@”) — enter your user name and password', prompt.credentialName, prompt.team)
        : tr('%@ (team catalog “%@”) — enter your password', prompt.credentialName, prompt.team)}
    </p>
    {#if prompt.server || prompt.teamSource}
      <!-- Where the password goes and where the catalog comes from: a catalog named like another cannot pass for it. -->
      <p class="caption origin">
        {[
          prompt.server ? tr('Server: %@', prompt.server) : null,
          prompt.teamSource ? tr('Catalog source: %@', prompt.teamSource) : null,
        ]
          .filter((part) => part !== null)
          .join(' · ')}
      </p>
    {/if}
  {:else if prompt.credentialName}
    <p class="caption shared">
      {prompt.usedBy === 1
        ? tr('Password for %@ — used by 1 connection', prompt.credentialName)
        : tr('Password for %@ — used by %lld connections', prompt.credentialName, prompt.usedBy ?? 0)}
    </p>
  {/if}
  {#if prompt.message}
    <p class="banner warn retry" role="alert"><Icon name="warning" /><span>{prompt.message}</span></p>
  {/if}
  <div class="card">
    {#each fields as field (field)}
      <label class="field">
        <span class="caption">{label(field)}</span>
        <span class="input">
          <input
            data-field={field}
            type={isSecretField(field) && !(shown[field] && values[field]) ? 'password' : 'text'}
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            disabled={!armed}
            value={values[field] ?? ''}
            oninput={(e) => (values = { ...values, [field]: e.currentTarget.value })}
          />
          {#if isSecretField(field) && values[field]}
            <button class="show" type="button" aria-pressed={shown[field] ?? false} onclick={() => (shown = { ...shown, [field]: !shown[field] })}
              >{shown[field] ? tr('Hide') : tr('Show')}</button
            >
          {/if}
        </span>
      </label>
    {/each}
  </div>
  {#if error}
    <p class="caption refused" role="alert">
      {error === 'tooEarly'
        ? tr('Not ready yet. Wait a moment, then click Connect again.')
        : tr('MacVPN did not accept these values. Check them and try again.')}
    </p>
  {/if}
  <label class="save">
    <input type="checkbox" bind:checked={save} disabled={!armed} />
    <span>
      {tr('Save in vault')}
      <span class="caption hint">{tr('Kept encrypted in the MacVPN vault, used from the next connect on')}</span>
    </span>
  </label>
  <div class="buttons">
    <p class="caption expires">{tr('Expires in %@', countdown(left))}</p>
    <button type="button" class="cancel" onclick={oncancel}>{tr('Cancel')}</button>
    <button type="button" class="connect" disabled={!ready} onclick={() => ready && onconnect()}>{tr('Connect')}</button>
  </div>
</div>

<style>
  .credentials {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: 18px var(--space-7) var(--space-7);
    box-sizing: border-box;
  }
  h1 {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0;
  }
  .bubble {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: var(--radius-icon);
    color: #fff;
    background: linear-gradient(180deg, var(--state-busy), color-mix(in srgb, var(--state-busy) 82%, #000));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .bubble :global(.icon) {
    width: 16px;
    height: 16px;
    stroke-width: 1.7;
  }
  p {
    margin: 0;
  }
  .name {
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
    font-variant-numeric: tabular-nums;
  }
  .banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 8px 12px;
    border-radius: var(--radius-control);
    overflow-wrap: anywhere;
  }
  .banner :global(.icon) {
    flex: none;
    margin-top: 1px;
    width: 14px;
    height: 14px;
  }
  .banner.warn {
    background: var(--state-fail-soft);
    color: var(--state-fail-text);
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .field input {
    flex: 1;
    min-width: 0;
    min-height: 28px;
  }
  .input {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .show {
    flex: none;
    min-height: 24px;
    padding: 2px 10px;
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
  }
  .origin {
    overflow-wrap: anywhere;
  }
  .refused {
    color: var(--state-fail-text);
  }
  .save {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 0 2px;
  }
  .save > span {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .buttons {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--space-3);
  }
  .expires {
    margin-right: auto;
    padding: 3px 9px;
    border-radius: var(--radius-pill);
    background: var(--surface-sunken);
  }
</style>
