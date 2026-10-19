<script lang="ts">
  // An MFA prompt window (the Swift `AuthPromptView`): the code prompt ("The VPN server says:" for the server's
  // text; a secure or a plain field by the echo flag) or the web sign-in confirmation (the ASCII host and the full
  // URL). The window does not take the focus when it appears; nothing but Cancel works in the first second after it
  // became visible; there is no default button ("Open in Browser" neither: only a click opens the URL, which the
  // backend takes from its own validated copy). Return in the code field submits a valid code, Escape cancels. The
  // window closes when the prompt ends (answered, cancelled, expired).
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { api, onViewModel, type PromptAction, type ViewModel } from './api';
  import Icon from './Icon.svelte';
  import { setLanguage, tr } from './l10n.svelte';
  import './manage/manage.css';
  import { countdown, isValidCode, promptIdOfLabel } from './prompt';

  const id = promptIdOfLabel(getCurrentWindow().label);

  let vm = $state<ViewModel | null>(null);
  let code = $state('');
  let armed = $state(false);
  let finished = $state(false);
  let now = $state(Date.now());
  let field: HTMLInputElement | undefined = $state();

  const prompt = $derived(vm?.prompts.find((p) => p.id === id) ?? null);
  const left = $derived(prompt ? prompt.deadline - now / 1000 : 0);
  const valid = $derived(isValidCode(code));

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    const timer = setInterval(() => (now = Date.now()), 1000);
    // The first second after the window became visible takes no input (a keystroke meant for another app must not
    // answer). The page says it is ready; the backend counts its own lock from that (and from ordering the window on
    // screen), and refuses an earlier answer too.
    let arm: ReturnType<typeof setTimeout> | undefined;
    if (id !== null) {
      api.promptReady(id).then(() => {
        arm = setTimeout(() => {
          armed = true;
          field?.focus();
        }, 1000);
      }, console.error);
    }
    return () => {
      clearInterval(timer);
      clearTimeout(arm);
      unlisten.then((f) => f());
    };
  });

  async function finish(action: PromptAction, response: string | null = null) {
    if (finished || id === null) return;
    finished = true;
    try {
      await api.answerPrompt(id, action, response);
    } catch (e) {
      finished = false;
      console.error(e);
    } finally {
      code = '';
    }
  }

  function submit() {
    if (armed && valid) finish('code', code).catch(console.error);
  }

  function keydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault();
      finish('cancel').catch(console.error);
    }
  }
</script>

<svelte:window onkeydown={keydown} />

<div class="manage prompt">
  {#if prompt && prompt.kind === 'code'}
    <h1>
      <span class="bubble key" aria-hidden="true"><Icon name="key" /></span>
      {tr('One-time code')}
    </h1>
    <div class="message">
      {#if prompt.fromServer}
        <p class="caption">{tr('The VPN server says:')}</p>
      {/if}
      <p class="text">{prompt.text}</p>
    </div>
    <input
      class="code"
      bind:this={field}
      type={prompt.echo ? 'text' : 'password'}
      placeholder={tr('Code')}
      aria-label={tr('Code')}
      autocomplete="off"
      spellcheck="false"
      disabled={!armed}
      bind:value={code}
      onkeydown={(e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          submit();
        }
      }}
    />
    <div class="buttons">
      <p class="caption expires">{tr('Expires in %@', countdown(left))}</p>
      <button onclick={() => finish('cancel').catch(console.error)}>{tr('Cancel')}</button>
      <button class="continue primary" disabled={!valid || !armed} onclick={submit}>{tr('Continue')}</button>
    </div>
  {:else if prompt && prompt.kind === 'webAuth'}
    <h1>
      <span class="bubble web" aria-hidden="true"><Icon name="globe" /></span>
      {tr('Sign in in the browser')}
    </h1>
    <p class="intro">{tr('The VPN server asks you to sign in on a web page. Open it only if you started this connection and you trust this address:')}</p>
    <div class="message">
      <p class="host">{prompt.host}</p>
      <p class="url">{prompt.url}</p>
    </div>
    <div class="buttons">
      <p class="caption expires">{tr('Expires in %@', countdown(left))}</p>
      <button onclick={() => finish('cancel').catch(console.error)}>{tr('Cancel')}</button>
      <button class="open" disabled={!armed} onclick={() => armed && finish('openUrl').catch(console.error)}>{tr('Open in Browser')}</button>
    </div>
  {/if}
</div>

<style>
  .prompt {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: 18px var(--space-7) var(--space-7);
    height: 100vh;
    box-sizing: border-box;
    overflow: auto;
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
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .bubble :global(.icon) {
    width: 16px;
    height: 16px;
    stroke-width: 1.7;
  }
  .key {
    background: linear-gradient(180deg, var(--state-busy), color-mix(in srgb, var(--state-busy) 82%, #000));
  }
  .web {
    background: linear-gradient(180deg, var(--vpn-openvpn), var(--vpn-openvpn-2));
  }
  p {
    margin: 0;
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
    font-variant-numeric: tabular-nums;
  }
  .message {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 10px 12px;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
  }
  .intro {
    color: var(--secondary);
  }
  .text,
  .host,
  .url {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  .host {
    font: 700 14px var(--mono);
  }
  .url {
    font: 11px / 1.4 var(--mono);
    color: var(--secondary);
    word-break: break-all;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .code {
    min-height: 36px;
    font: 500 16px var(--mono);
    letter-spacing: 0.12em;
    text-align: center;
  }
  .code::placeholder {
    font-family: var(--font);
    letter-spacing: 0;
  }
  .buttons {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--space-3);
    margin-top: auto;
  }
  .expires {
    margin-right: auto;
    padding: 3px 9px;
    border-radius: var(--radius-pill);
    background: var(--surface-sunken);
  }
</style>
