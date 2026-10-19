<script lang="ts">
  // The System Status window (the Swift `SetupView`): Homebrew, the VPN tools with the live `brew install`
  // output, the root layer (with the up-front notice that reinstalling disconnects active connections), launch at
  // login, and uninstall with its confirmation and final message. The texts of the rows come from the backend.
  import { onMount, tick } from 'svelte';
  import { api, onViewModel, type Notice, type UninstallResult, type ViewModel } from './api';
  import CheckRow from './CheckRow.svelte';
  import { setLanguage, tr } from './l10n.svelte';
  import Modal from './manage/Modal.svelte';
  import './manage/manage.css';

  let vm = $state<ViewModel | null>(null);
  let notice = $state<Notice | null>(null);
  let confirmUninstall = $state(false);
  let removeUserData = $state(false);
  let uninstalled = $state<UninstallResult | null>(null);
  let output: HTMLElement | undefined = $state();

  const setup = $derived(vm?.setup ?? null);

  function apply(next: ViewModel) {
    setLanguage(next.language);
    vm = next;
  }

  onMount(() => {
    const unlisten = onViewModel(apply);
    api.viewModel().then(apply, console.error);
    // The Swift `.task { loginItem.refresh(); checkSetup() }`.
    api.setupCheck().catch(console.error);
    return () => {
      unlisten.then((f) => f());
    };
  });

  // The live output follows its end.
  $effect(() => {
    if (setup?.brewOutput !== undefined) {
      tick().then(() => {
        if (output) output.scrollTop = output.scrollHeight;
      });
    }
  });

  async function installHomebrew() {
    const failure = await api.setupInstallHomebrew();
    if (failure) notice = failure;
  }

  async function setLaunchAtLogin(event: Event) {
    const failure = await api.setLaunchAtLogin((event.currentTarget as HTMLInputElement).checked);
    if (failure) notice = failure;
  }

  async function uninstall() {
    confirmUninstall = false;
    const result = await api.setupUninstall(removeUserData);
    if (result.done) uninstalled = result;
    else notice = { title: result.title, message: result.message };
  }
</script>

<div class="manage setup">
  <h1>{tr('System Status')}</h1>
  <p class="secondary">
    {tr('MacVPN uses the VPN tools from Homebrew (openvpn, wireguard-tools, strongswan, sstp-client, bash). You can install the missing ones here.')}
  </p>
  {#if vm?.statusError}
    <p class="warning"><span aria-hidden="true">⚠</span> {vm.statusError}</p>
  {/if}

  {#if setup?.homebrew && setup.tools && setup.root}
    <CheckRow row={setup.homebrew} title={tr('Homebrew')}>
      <button onclick={() => installHomebrew().catch(console.error)}>{tr('Install…')}</button>
    </CheckRow>
    <CheckRow row={setup.tools} title={tr('VPN tools')}>
      <button disabled={!setup.canInstallTools} onclick={() => api.setupInstallTools().catch(console.error)}>
        {setup.brewRunning ? tr('Installing…') : tr('Install')}
      </button>
    </CheckRow>
    {#if setup.brewOutput}
      <pre class="output" bind:this={output}>{setup.brewOutput}</pre>
    {/if}
    <CheckRow row={setup.root} title={tr('Permissions (root scripts + sudoers)')}>
      <button disabled={setup.installingRoot} onclick={() => api.setupInstallRoot().catch(console.error)}>
        {setup.installingRoot ? tr('Installing…') : tr('Authorize')}
      </button>
    </CheckRow>
    {#if setup.upgradeNotice}
      <p class="notice">{setup.upgradeNotice}</p>
    {/if}
    {#if setup.installError}
      <p class="error">{setup.installError}</p>
    {/if}
  {/if}

  <div class="line">
    <span class="caption">{tr('L2TP and Cisco IPsec work without these.')}</span>
    <span class="spacer"></span>
    <button onclick={() => api.setupCheck().catch(console.error)}>{tr('Check Again')}</button>
  </div>

  <hr />
  {#if vm?.loginItem}
    <label class="check">
      <input
        type="checkbox"
        checked={vm.loginItem.isOn}
        disabled={!vm.loginItem.canToggle}
        onchange={(e) => setLaunchAtLogin(e).catch(console.error)}
      />
      {tr('Launch at Login')}
    </label>
    {#if vm.loginItem.note}
      <p class="caption indent">{vm.loginItem.note}</p>
    {/if}
    {#if vm.loginItem.showsOpenSettings}
      <div class="indent">
        <button onclick={() => api.openLoginItemsSettings().catch(console.error)}>{tr('Open Login Items Settings…')}</button>
      </div>
    {/if}
  {/if}

  <hr />
  <div class="line">
    <span class="caption">{tr('Removes the root scripts, the sudoers rule and the logs; optionally your connections too.')}</span>
    <span class="spacer"></span>
    <button
      class="destructive uninstall"
      disabled={(setup?.uninstalling ?? false) || (setup?.installingRoot ?? false)}
      onclick={() => {
        removeUserData = false;
        confirmUninstall = true;
      }}>{tr('Uninstall MacVPN…')}</button
    >
  </div>
</div>

{#if confirmUninstall}
  <Modal
    title={tr('Uninstall MacVPN')}
    message={tr('After you enter an admin password, these are deleted:\n• /usr/local/libexec/macvpn (root scripts)\n• /etc/sudoers.d/macvpn (sudoers rule)\n• /var/run/macvpn, /var/run/macvpn-ui (runtime data)\n• /var/log/macvpn (connection logs)\n\nActive connections are disconnected first. Homebrew packages are kept.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (confirmUninstall = false) },
      { label: tr('Uninstall'), kind: 'destructive', action: () => uninstall().catch(console.error) },
    ]}
  >
    <label class="check accessory" title={tr('~/Library/Application Support/MacVPN and the MacVPN Keychain items')}>
      <input type="checkbox" bind:checked={removeUserData} />
      {tr('Also delete user data (connections and Keychain passwords)')}
    </label>
  </Modal>
{:else if uninstalled}
  {@const done = uninstalled}
  <Modal
    title={done.title}
    message={done.message}
    buttons={[{ label: tr('Quit MacVPN'), kind: 'primary', action: () => api.quitAfterUninstall().catch(console.error) }]}
  />
{:else if notice}
  <Modal title={notice.title} message={notice.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (notice = null) }]} />
{/if}

<style>
  .setup {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 20px;
    height: 100vh;
    box-sizing: border-box;
    overflow: auto;
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
  .warning {
    font-size: 12px;
  }
  .warning span {
    color: var(--orange);
  }
  .notice {
    color: var(--orange);
    font-size: 12px;
    margin-left: 28px;
  }
  .error {
    color: var(--red);
    white-space: pre-wrap;
  }
  .output {
    margin: 0 0 0 28px;
    height: 160px;
    overflow: auto;
    padding: 6px;
    border-radius: 6px;
    background: var(--text-background);
    font: 11px ui-monospace, SFMono-Regular, Menlo, monospace;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  .line {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .spacer {
    flex: 1;
  }
  .uninstall {
    flex: none;
  }
  hr {
    border: none;
    border-top: 1px solid var(--separator);
    margin: 0;
    width: 100%;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .indent {
    margin-left: 22px;
  }
  .accessory {
    margin: 0 0 14px;
  }
</style>
