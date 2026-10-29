<script lang="ts">
  // A WireGuard connection's keys, under its config text: the [Interface] private key (masked, Show / Hide, Copy
  // through the backend's secret clipboard), the public key derived from it by the backend (read-only, Copy: it is
  // what the other side's [Peer] needs) and "Generate Key Pair"; for a config with exactly one peer, its preshared
  // key the same way with "Generate Preshared Key". Everything follows the draft's config text live (generated,
  // pasted or typed). Generating asks first when it would replace a key. Keys are made in the backend (the OS
  // CSPRNG), never here; the private and preshared keys are copied by the backend from its draft.
  import type { WireGuardKeyLine, WireGuardKeysView } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';
  import { offersPresharedKey, publicKeyLine, replaceQuestion } from './wgkeys';

  let {
    keys,
    readOnly = false,
    ongenerate,
    oncopy,
  }: {
    keys: WireGuardKeysView;
    /// A team catalog's connection: the keys can be shown and copied, not generated.
    readOnly?: boolean;
    ongenerate: (which: WireGuardKeyLine) => Promise<void>;
    /// Copies the private / preshared key through the backend's secret clipboard.
    oncopy: (which: WireGuardKeyLine) => Promise<void>;
  } = $props();

  const pub = $derived(publicKeyLine(keys));
  const psk = $derived(offersPresharedKey(keys));
  let shown = $state<Record<WireGuardKeyLine, boolean>>({ privateKey: false, presharedKey: false });
  let copied = $state<WireGuardKeyLine | 'publicKey' | null>(null);
  let asking = $state<{ which: WireGuardKeyLine; title: string; message: string } | null>(null);
  let error = $state<string | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;

  function flash(which: WireGuardKeyLine | 'publicKey') {
    copied = which;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = null), 3000);
  }

  async function copySecret(which: WireGuardKeyLine) {
    error = null;
    try {
      await oncopy(which);
      flash(which);
    } catch (e) {
      error = String(e);
    }
  }

  // The public key is not a secret: the web view's clipboard, as a publisher fingerprint.
  async function copyPublic(key: string) {
    error = null;
    try {
      await navigator.clipboard.writeText(key);
      flash('publicKey');
    } catch (e) {
      error = String(e);
    }
  }

  async function generate(which: WireGuardKeyLine) {
    asking = null;
    error = null;
    try {
      await ongenerate(which);
      shown[which] = false;
    } catch (e) {
      error = String(e);
    }
  }

  function requestGenerate(which: WireGuardKeyLine) {
    const question = replaceQuestion(keys, which);
    if (question) asking = { which, ...question };
    else generate(which).catch(console.error);
  }
</script>

{#snippet secret(which: WireGuardKeyLine, label: string, value: string | null)}
  <div class="key-row">
    <span class="key-label">{label}</span>
    <input
      class="key {which}"
      type={shown[which] ? 'text' : 'password'}
      readonly
      spellcheck="false"
      autocomplete="off"
      aria-label={label}
      placeholder={tr('Not set')}
      value={value ?? ''}
    />
    <button class="show-key" type="button" disabled={!value} aria-pressed={shown[which]} onclick={() => (shown[which] = !shown[which])}
      >{shown[which] ? tr('Hide') : tr('Show')}</button
    >
    <button class="copy-key" type="button" disabled={!value} onclick={() => copySecret(which).catch(console.error)}
      ><Icon name="copy" />{copied === which ? tr('Copied') : tr('Copy')}</button
    >
  </div>
{/snippet}

<div class="wg-keys">
  <fieldset class="interface-keys">
    <legend>{tr('Interface keys')}</legend>
    {@render secret('privateKey', tr('Private key'), keys.privateKey)}
    <div class="key-row">
      <span class="key-label">{tr('Public key')}</span>
      {#if pub.state === 'key'}
        <code class="key public-key" data-public-key>{pub.key}</code>
        <button class="copy-public" type="button" onclick={() => copyPublic(pub.key).catch(console.error)}
          ><Icon name="copy" />{copied === 'publicKey' ? tr('Copied') : tr('Copy')}</button
        >
      {:else if pub.state === 'invalid'}
        <span class="key-state invalid-key" role="alert">{tr('Invalid private key')}</span>
      {:else}
        <span class="key-state no-key">{tr('Generate a key pair, or paste a private key into the config.')}</span>
      {/if}
    </div>
    <div class="key-actions">
      <button class="generate-key-pair" type="button" disabled={readOnly} onclick={() => requestGenerate('privateKey')}
        ><Icon name="key" />{tr('Generate Key Pair')}</button
      >
      <span class="note">{tr('Set the public key on the other side, in the [Peer] section for this device.')}</span>
    </div>
  </fieldset>
  {#if psk}
    <fieldset class="peer-keys">
      <legend>{tr('Peer')}</legend>
      {@render secret('presharedKey', tr('Preshared key'), keys.presharedKey)}
      <div class="key-actions">
        <button class="generate-psk" type="button" disabled={readOnly} onclick={() => requestGenerate('presharedKey')}
          ><Icon name="key" />{tr('Generate Preshared Key')}</button
        >
        <span class="note">{tr('Optional. The other side needs the same preshared key.')}</span>
      </div>
    </fieldset>
  {/if}
  {#if copied === 'privateKey' || copied === 'presharedKey'}
    <p class="copied-note" role="status"><Icon name="check" /><span>{tr('Copied. It is removed from the clipboard in a minute.')}</span></p>
  {:else if copied === 'publicKey'}
    <p class="copied-note" role="status"><Icon name="check" /><span>{tr('Public key copied.')}</span></p>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

{#if asking}
  {@const question = asking}
  <Modal
    title={question.title}
    message={question.message}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (asking = null) },
      { label: tr('Replace'), kind: 'destructive', action: () => generate(question.which).catch(console.error) },
    ]}
  />
{/if}

<style>
  .wg-keys,
  .wg-keys fieldset {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .wg-keys {
    gap: var(--space-4);
  }
  .key-row {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .key-label {
    flex: none;
    width: 9.5em;
    color: var(--secondary);
  }
  .key {
    flex: 1;
    min-width: 0;
    font-family: var(--mono);
    font-size: var(--text-sm);
  }
  code.key {
    padding: 4px 9px;
    overflow-wrap: anywhere;
    user-select: all;
  }
  .key-state {
    flex: 1;
    color: var(--secondary);
  }
  .invalid-key {
    color: var(--state-fail-text);
  }
  .key-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .key-actions .note {
    flex: 1;
    min-width: 12em;
  }
  .copied-note {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0;
    color: var(--secondary);
  }
</style>
