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
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M10.5 1a4.5 4.5 0 00-4.3 5.8L1 12v3h3v-1.5h1.5V12H7l1.2-1.2A4.5 4.5 0 1010.5 1zm1 2.5a1.2 1.2 0 110 2.4 1.2 1.2 0 010-2.4z" fill="currentColor" /></svg>
      {tr('One-time code')}
    </h1>
    {#if prompt.fromServer}
      <p class="caption">{tr('The VPN server says:')}</p>
    {/if}
    <p class="text">{prompt.text}</p>
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
    <p class="caption">{tr('Expires in %@', countdown(left))}</p>
    <div class="buttons">
      <button onclick={() => finish('cancel').catch(console.error)}>{tr('Cancel')}</button>
      <button class="continue" disabled={!valid || !armed} onclick={submit}>{tr('Continue')}</button>
    </div>
  {:else if prompt && prompt.kind === 'webAuth'}
    <h1>
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm4.9 6.3h-2.1a11 11 0 00-.8-3.9 5.6 5.6 0 012.9 3.9zM8 2.5c.6.8 1.2 2.4 1.4 4.8H6.6C6.8 4.9 7.4 3.3 8 2.5zM6 3.4a11 11 0 00-.8 3.9H3.1A5.6 5.6 0 016 3.4zM3.1 8.7h2.1c.1 1.5.4 2.8.8 3.9a5.6 5.6 0 01-2.9-3.9zM8 13.5c-.6-.8-1.2-2.4-1.4-4.8h2.8c-.2 2.4-.8 4-1.4 4.8zm2 -.9c.4-1.1.7-2.4.8-3.9h2.1a5.6 5.6 0 01-2.9 3.9z" fill="currentColor" /></svg>
      {tr('Sign in in the browser')}
    </h1>
    <p>{tr('The VPN server asks you to sign in on a web page. Open it only if you started this connection and you trust this address:')}</p>
    <p class="host">{prompt.host}</p>
    <p class="url">{prompt.url}</p>
    <p class="caption">{tr('Expires in %@', countdown(left))}</p>
    <div class="buttons">
      <button onclick={() => finish('cancel').catch(console.error)}>{tr('Cancel')}</button>
      <button class="open" disabled={!armed} onclick={() => armed && finish('openUrl').catch(console.error)}>{tr('Open in Browser')}</button>
    </div>
  {/if}
</div>

<style>
  .prompt {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 18px 20px;
    height: 100vh;
    box-sizing: border-box;
    overflow: auto;
  }
  h1 {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 14px;
    margin: 0;
  }
  h1 svg {
    width: 15px;
    height: 15px;
  }
  p {
    margin: 0;
  }
  .caption {
    font-size: 11px;
    color: var(--secondary);
    font-variant-numeric: tabular-nums;
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
    font: 700 13px ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .url {
    font: 11px ui-monospace, SFMono-Regular, Menlo, monospace;
    color: var(--secondary);
    word-break: break-all;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .buttons {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: auto;
  }
</style>
