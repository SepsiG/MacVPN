<script lang="ts">
  // The Update window (the Swift `UpdateView`): the offered release with its notes as text with inline emphasis
  // only (never HTML), "Download and Install" with its stages and error, the active-connections question of the
  // install's quit step, and the previous update's notice at launch.
  import { onMount } from 'svelte';
  import { api, onViewModel, type QuitChoice, type ViewModel } from './api';
  import Icon from './Icon.svelte';
  import { setLanguage, tr } from './l10n.svelte';
  import Modal from './manage/Modal.svelte';
  import './manage/manage.css';
  import { inlineSegments } from './notes';

  let vm = $state<ViewModel | null>(null);
  let answering = $state(false);

  const update = $derived(vm?.update ?? null);
  const release = $derived(update?.release ?? null);
  const segments = $derived(release ? inlineSegments(release.notes) : []);
  const installing = $derived(update?.installStage !== null && update?.installStage !== undefined);
  const askingQuit = $derived(vm?.quit?.origin === 'update' && vm.quit.step === 'activeConnections');

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    return () => {
      unlisten.then((f) => f());
    };
  });

  function close() {
    api.closeWindow('update').catch(console.error);
  }

  async function dismissNotice() {
    await api.updateDismissNotice();
    if (!release) close();
  }

  async function answer(choice: QuitChoice) {
    answering = true;
    try {
      await api.quit(choice);
    } finally {
      answering = false;
    }
  }
</script>

<div class="manage update">
  {#if release && update}
    <header class="hero">
      <span class="hero-icon" aria-hidden="true"><Icon name="download" /></span>
      <div class="hero-text">
        <h1>{tr('Update available: %@', release.tag)}</h1>
        <p class="secondary">{tr('Installed version: %@', update.currentVersion)}</p>
      </div>
    </header>
    <div class="notes">
      {#each segments as s, i (i)}{#if s.code}<code>{s.text}</code>{:else}<span class:bold={s.bold} class:italic={s.italic} class:strike={s.strike}>{s.text}</span>{/if}{/each}
    </div>
    <p class="caption">
      {tr("The SHA-256 checksum of the downloaded disk image is checked against the release's .sha256 file. The app restarts after the installation.")}
    </p>
    {#if update.installError}
      <p class="error">{update.installError}</p>
    {/if}
    <div class="line">
      {#if installing}
        <span class="spinner" aria-hidden="true"></span>
        <span class="secondary stage">{update.installStage}</span>
      {:else if release.hasPage}
        <button class="link" onclick={() => api.updateOpenPage().catch(console.error)}>{tr('Open the Release on GitHub')}</button>
      {/if}
      <span class="spacer"></span>
      <button disabled={installing} onclick={close}>{tr('Later')}</button>
      <button class="primary install" disabled={installing} onclick={() => api.updateInstall().catch(console.error)}>
        {tr('Download and Install')}
      </button>
    </div>
  {:else if update}
    <header class="hero">
      <span class="hero-icon latest" aria-hidden="true"><Icon name="check" /></span>
      <div class="hero-text">
        <h1>{tr('No update available')}</h1>
        <p class="secondary">{tr('The installed version (%@) is the latest.', update.currentVersion)}</p>
      </div>
    </header>
    <div class="line">
      <span class="spacer"></span>
      <button onclick={close}>{tr('Close')}</button>
    </div>
  {/if}
</div>

{#if askingQuit}
  <Modal
    title={tr('There are active VPN connections')}
    message={vm?.quitNote ? `${tr('Disconnect them before quitting?')}\n\n${vm.quitNote}` : tr('Disconnect them before quitting?')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => answering || answer('cancel').catch(console.error) },
      { label: tr('Quit, Keep Them Running'), action: () => answering || answer('keepRunning').catch(console.error) },
      { label: tr('Disconnect and Quit'), kind: 'primary', action: () => answering || answer('disconnectAndQuit').catch(console.error) },
    ]}
  />
{:else if update?.notice}
  <Modal
    title={update.notice.title}
    message={update.notice.message}
    buttons={[{ label: tr('OK'), kind: 'primary', action: () => dismissNotice().catch(console.error) }]}
  />
{/if}

<style>
  .update {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-7);
    height: 100vh;
    box-sizing: border-box;
  }
  .hero {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .hero-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: 10px;
    color: #fff;
    background: linear-gradient(180deg, var(--vpn-openvpn), var(--vpn-openvpn-2));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .hero-icon.latest {
    background: linear-gradient(180deg, var(--state-on), color-mix(in srgb, var(--state-on) 80%, #000));
  }
  .hero-icon :global(.icon) {
    width: 22px;
    height: 22px;
    stroke-width: 1.8;
  }
  .hero-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
  }
  p {
    margin: 0;
  }
  .secondary,
  .caption {
    color: var(--secondary);
  }
  .caption {
    font-size: var(--text-sm);
  }
  .error {
    padding: 8px 12px;
    border-radius: var(--radius-control);
    background: var(--state-fail-soft);
    color: var(--state-fail-text);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .notes {
    flex: 1;
    min-height: 120px;
    overflow: auto;
    padding: 14px 16px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    line-height: 1.5;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  .bold {
    font-weight: 700;
  }
  .italic {
    font-style: italic;
  }
  .strike {
    text-decoration: line-through;
  }
  code {
    padding: 1px 5px;
    border-radius: var(--radius-xs);
    background: var(--surface-sunken);
    font: 11.5px var(--mono);
  }
  .line {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
  .spacer {
    flex: 1;
  }
  .stage {
    font-size: var(--text-md);
  }
  .link {
    min-height: 0;
    border: none;
    background: none;
    box-shadow: none;
    padding: 0;
    color: var(--accent-text);
    font-weight: 400;
  }
  .manage .link:hover:not(:disabled),
  .manage .link:active:not(:disabled) {
    background: none;
    text-decoration: underline;
  }
  .spinner {
    width: 12px;
    height: 12px;
    border: 2px solid var(--separator);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
