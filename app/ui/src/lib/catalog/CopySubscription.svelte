<script lang="ts">
  // "Copy Subscription String" (user guide 16.9): the master password (checked by the backend with its delay after
  // a wrong one) and the source the team will use – an https:// address, or the catalog file as the members' Macs
  // see it. The backend puts the string on the pasteboard and empties it a minute later; it never comes here, and
  // nothing shows it. The password field is not bound to any state: its text is read once when sent and cleared
  // at once.
  import { onDestroy } from 'svelte';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { publishApi } from './publishApi';

  let {
    catalogId,
    name,
    source = $bindable('url'),
    url = $bindable(''),
    fileName = $bindable(null),
    copied = $bindable(false),
    error = $bindable(null),
    onclose,
  }: {
    catalogId: string;
    name: string;
    source?: 'url' | 'file';
    url?: string;
    fileName?: string | null;
    copied?: boolean;
    error?: string | null;
    onclose: () => void;
  } = $props();

  /// An example source (not a text: the same in every language).
  const URL_PLACEHOLDER = 'https://vpn.example.com/team.macvpncatalog';
  /// After a refused password: the seconds before the next try.
  const RETRY_SECONDS = 3;

  let master: HTMLInputElement | undefined = $state();
  let hasMaster = $state(false);
  let busy = $state(false);
  let wait = $state(0);
  let timer: ReturnType<typeof setInterval> | null = null;

  const ready = $derived(hasMaster && wait === 0 && !busy && (source === 'url' ? url.trim() !== '' : fileName !== null));

  function clearMaster() {
    if (master) master.value = '';
    hasMaster = false;
  }

  function countdown() {
    wait = RETRY_SECONDS;
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      wait = Math.max(0, wait - 1);
      if (wait === 0 && timer) {
        clearInterval(timer);
        timer = null;
      }
    }, 1000);
  }

  async function chooseFile() {
    error = null;
    try {
      const chosen = await publishApi.chooseSourceFile();
      if (chosen !== null) fileName = chosen;
    } catch (e) {
      error = String(e);
    }
  }

  async function copy() {
    if (!ready || !master) return;
    const password = master.value;
    clearMaster();
    busy = true;
    error = null;
    try {
      await publishApi.copySubscription(catalogId, password, source === 'url' ? url.trim() : null, source === 'file');
      copied = true;
    } catch (e) {
      error = String(e);
      countdown();
    } finally {
      busy = false;
    }
  }

  function close() {
    clearMaster();
    onclose();
  }

  onDestroy(() => {
    if (timer) clearInterval(timer);
    if (master) master.value = '';
  });
</script>

<div class="backdrop">
  <div class="alert copy-subscription" role="alertdialog" aria-modal="true" aria-labelledby="copy-subscription-title">
    <h1 id="copy-subscription-title">{tr('Copy Subscription String of “%@”', name)}</h1>
    {#if copied}
      <p class="banner ok" role="status"><Icon name="check" /><span>{tr('The subscription string is on the clipboard. It is removed from the clipboard in a minute.')}</span></p>
      <p class="secondary">{tr('It contains the team key: send it only through a secure channel (a shared vault of your password manager, an end-to-end encrypted messenger), never by plain e-mail. Tell members the fingerprint separately, ideally by voice.')}</p>
      <div class="buttons">
        <button class="primary close-copy" onclick={close}>{tr('Done')}</button>
      </div>
    {:else}
      <p class="secondary">{tr('MacVPN asks for your master password, then puts the string on the clipboard without showing it. The access token is not in it.')}</p>
      <div class="form">
        <label class="form-row">
          <span>{tr('Master password')}</span>
          <input bind:this={master} data-field="master" type="password" autocomplete="off" spellcheck="false" disabled={busy} oninput={(e) => (hasMaster = e.currentTarget.value !== '')} />
        </label>
        <div class="form-row">
          <span>{tr('Source for the team')}</span>
          <div class="segmented" role="radiogroup">
            <button class:on={source === 'url'} role="radio" aria-checked={source === 'url'} onclick={() => (source = 'url')}>{tr('Web Address')}</button>
            <button class:on={source === 'file'} role="radio" aria-checked={source === 'file'} onclick={() => (source = 'file')}>{tr('File')}</button>
          </div>
        </div>
        {#if source === 'url'}
          <label class="form-row"><span>{tr('Address')}</span><input class="source-url" type="text" autocomplete="off" spellcheck="false" placeholder={URL_PLACEHOLDER} disabled={busy} bind:value={url} /></label>
        {:else}
          <div class="form-row">
            <span>{tr('Catalog file')}</span>
            <span class="file-pick"><button class="choose-source" disabled={busy} onclick={() => chooseFile().catch(console.error)}>{tr('Choose File…')}</button>{#if fileName}<span class="file-name">{fileName}</span>{/if}</span>
          </div>
          <p class="caption">{tr('Choose the file at the path the members’ Macs use, for example on the mounted share.')}</p>
        {/if}
        {#if error}<p class="form-error" role="alert">{error}</p>{/if}
        {#if wait > 0}<p class="caption wait">{tr('Try again in %lld s', wait)}</p>{/if}
      </div>
      <div class="buttons">
        <button class="cancel cancel-copy" onclick={close}>{tr('Cancel')}</button>
        <button class="primary copy-string" disabled={!ready} onclick={() => copy().catch(console.error)}>{tr('Copy to Clipboard')}</button>
      </div>
    {/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: 60px;
    background: var(--backdrop);
  }
  .alert {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    width: min(460px, calc(100vw - 40px));
    max-height: calc(100vh - 100px);
    overflow: auto;
    box-sizing: border-box;
    padding: 20px;
    border-radius: var(--radius-panel);
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  h1 {
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0;
    overflow-wrap: anywhere;
  }
  .buttons {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-3);
  }
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
