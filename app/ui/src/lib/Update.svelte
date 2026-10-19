<script lang="ts">
  // The Update window (the Swift `UpdateView`): the offered release with its notes as text with inline emphasis
  // only (never HTML), "Download and Install" with its stages and error, the active-connections question of the
  // install's quit step, and the previous update's notice at launch.
  import { onMount } from 'svelte';
  import { api, onViewModel, type QuitChoice, type ViewModel } from './api';
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
    <h1>{tr('Update available: %@', release.tag)}</h1>
    <p class="secondary">{tr('Installed version: %@', update.currentVersion)}</p>
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
    <h1>{tr('No update available')}</h1>
    <p class="secondary">{tr('The installed version (%@) is the latest.', update.currentVersion)}</p>
    <div class="line">
      <span class="spacer"></span>
      <button onclick={close}>{tr('Close')}</button>
    </div>
  {/if}
</div>

{#if askingQuit}
  <Modal
    title={tr('There are active VPN connections')}
    message={tr('Disconnect them before quitting?')}
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
    gap: 14px;
    padding: 20px;
    height: 100vh;
    box-sizing: border-box;
  }
  h1 {
    font-size: 17px;
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
    font-size: 11px;
  }
  .error {
    color: var(--red);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .notes {
    flex: 1;
    min-height: 120px;
    overflow: auto;
    padding: 8px;
    border-radius: 6px;
    background: var(--text-background);
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
    font: 12px ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .line {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .spacer {
    flex: 1;
  }
  .stage {
    font-size: 12px;
  }
  .link {
    border: none;
    background: none;
    padding: 0;
    color: var(--accent);
  }
  .spinner {
    width: 12px;
    height: 12px;
    border: 2px solid var(--separator);
    border-top-color: var(--secondary);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
