<script lang="ts">
  // The System Status window (the Swift `SetupView`): Homebrew, the VPN tools with the live `brew install`
  // output, the root layer (with the up-front notice that reinstalling disconnects active connections), launch at
  // login, and uninstall with its confirmation and final message. The texts of the rows come from the backend.
  import { onMount, tick } from 'svelte';
  import { api, onViewModel, type Notice, type UninstallResult, type ViewModel } from './api';
  import CheckRow from './CheckRow.svelte';
  import Icon from './Icon.svelte';
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
  <header class="hero">
    <span class="hero-icon" aria-hidden="true"><Icon name="status" /></span>
    <div class="hero-text">
      <h1>{tr('System Status')}</h1>
      <p class="secondary">
        {tr('MacVPN uses the VPN tools from Homebrew (openvpn, wireguard-tools, strongswan, sstp-client, bash). You can install the missing ones here.')}
      </p>
    </div>
  </header>
  {#if vm?.statusError}
    <p class="warning"><Icon name="warning" /><span>{vm.statusError}</span></p>
  {/if}
  {#if vm?.control.error}
    <p class="warning control-error"><Icon name="warning" /><span>{vm.control.error}</span></p>
  {/if}

  <div class="card">
    {#if setup?.homebrew && setup.tools && setup.root}
      <CheckRow row={setup.homebrew} title={tr('Homebrew')}>
        <button onclick={() => installHomebrew().catch(console.error)}>{tr('Install…')}</button>
      </CheckRow>
      <hr />
      <CheckRow row={setup.tools} title={tr('VPN tools')}>
        <button disabled={!setup.canInstallTools} onclick={() => api.setupInstallTools().catch(console.error)}>
          {setup.brewRunning ? tr('Installing…') : tr('Install')}
        </button>
      </CheckRow>
      {#if setup.brewOutput}
        <pre class="output" bind:this={output}>{setup.brewOutput}</pre>
      {/if}
      <hr />
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
      <hr class="full" />
    {/if}
    <div class="line">
      <span class="caption">{tr('L2TP and Cisco IPsec work without these.')}</span>
      <span class="spacer"></span>
      <button onclick={() => api.setupCheck().catch(console.error)}><Icon name="refresh" />{tr('Check Again')}</button>
    </div>
  </div>

  {#if vm?.loginItem}
    <div class="card">
      <label class="check login">
        <span>{tr('Launch at Login')}</span>
        <input
          type="checkbox"
          class="switch"
          role="switch"
          checked={vm.loginItem.isOn}
          disabled={!vm.loginItem.canToggle}
          onchange={(e) => setLaunchAtLogin(e).catch(console.error)}
        />
      </label>
      {#if vm.loginItem.note}
        <p class="caption">{vm.loginItem.note}</p>
      {/if}
      {#if vm.loginItem.showsOpenSettings}
        <div>
          <button onclick={() => api.openLoginItemsSettings().catch(console.error)}>{tr('Open Login Items Settings…')}</button>
        </div>
      {/if}
    </div>
  {/if}

  <div class="card danger">
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
    gap: var(--space-5);
    padding: var(--space-7) var(--space-7) var(--space-8);
    height: 100vh;
    box-sizing: border-box;
    overflow: auto;
  }
  .hero {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 2px;
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
    background: linear-gradient(180deg, var(--vpn-ikev2), var(--vpn-ikev2-2));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .hero-icon :global(.icon) {
    width: 22px;
    height: 22px;
    stroke-width: 1.7;
  }
  .hero-text {
    display: flex;
    flex-direction: column;
    gap: 3px;
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
  .hero .secondary {
    font-size: var(--text-md);
  }
  .caption {
    font-size: var(--text-sm);
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: 14px 16px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .warning {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 10px 12px;
    border-radius: var(--radius-card);
    background: var(--state-busy-soft);
    font-size: var(--text-md);
  }
  .warning :global(.icon) {
    flex: none;
    width: 15px;
    height: 15px;
    color: var(--state-busy);
  }
  .notice {
    color: var(--state-busy-text);
    font-size: var(--text-md);
    margin-left: 36px;
  }
  .error {
    color: var(--state-fail-text);
    white-space: pre-wrap;
    margin-left: 36px;
  }
  .output {
    margin: 0 0 0 36px;
    height: 150px;
    overflow: auto;
    padding: 10px 12px;
    border-radius: var(--radius-control);
    background: var(--code-background);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    font: 11px / 1.5 var(--mono);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  hr {
    border: none;
    border-top: 1px solid var(--separator);
    margin: 0 0 0 36px;
  }
  hr.full {
    margin-left: 0;
  }
  .line {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
  .line button :global(.icon) {
    width: 13px;
    height: 13px;
    color: var(--secondary);
  }
  .spacer {
    flex: 1;
  }
  .uninstall {
    flex: none;
  }
  .check {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
  .login {
    justify-content: space-between;
    font-weight: 500;
  }
  .accessory {
    margin: 0 0 16px;
  }
</style>
