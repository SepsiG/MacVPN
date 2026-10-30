<script lang="ts">
  // The System Status window (the Swift `SetupView`): Homebrew, the VPN tools with the live `brew install`
  // output (and "Update" on the green row when a formula is outdated: `brew upgrade`), the root layer (with the
  // up-front notice that reinstalling disconnects active connections), launch at login, and uninstall with its
  // confirmation and final message. The texts of the rows come from the backend.
  // On WinVPN the WinVPN Service, OpenVPN Community and WireGuard rows replace the first three (with the OpenVPN
  // installer's output); the Windows VPN client row (WinVPN 2c) follows them, or the engine note when the service
  // is missing (the native Windows VPNs need no service). On LinVPN (L-b) the NetworkManager row and one row per
  // kind (its plugin, with "Install" when a package is missing: PackageKit's own prompt) replace them.
  import { onMount, tick } from 'svelte';
  import { api, onViewModel, type Notice, type UninstallResult, type ViewModel } from './api';
  import CheckRow from './CheckRow.svelte';
  import Icon from './Icon.svelte';
  import { i18n, setLanguage, tr } from './l10n.svelte';
  import Modal from './manage/Modal.svelte';
  import { engineRows, nmRows, opensInstalledApps, rasRow, uninstallTexts } from './setup';
  import './manage/manage.css';

  let vm = $state<ViewModel | null>(null);
  let notice = $state<Notice | null>(null);
  let confirmUninstall = $state(false);
  let removeUserData = $state(false);
  let uninstalled = $state<UninstallResult | null>(null);
  let output: HTMLElement | undefined = $state();
  // The engine row whose button ran last: the installer's output box is shown under it (WinVPN).
  let outputRow = $state<string>('openvpn');

  function runEngineAction(row: 'openvpn' | 'wireguard') {
    outputRow = row;
    api.setupInstallTools(row === 'wireguard' ? 'wireguard' : undefined).catch(console.error);
  }

  const setup = $derived(vm?.setup ?? null);
  // LinVPN: NetworkManager and the kinds' plugin rows (none on macOS and Windows).
  const nmItems = $derived(setup ? nmRows(setup, tr) : []);

  // LinVPN: installs the plugin of `kind` (its raw value) through PackageKit; the output box follows its row.
  function runNmInstall(kind: string) {
    outputRow = `nm-${kind}`;
    api.setupInstallTools(kind).catch(console.error);
  }
  // "Uninstall MacVPN…", or WinVPN's "Remove WinVPN from This Account…" (the clean-up before the MSI's uninstall).
  const uninstallText = $derived(uninstallTexts(setup ?? {}, tr));

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

{#snippet windowsVpnClient()}
  {@const ras = setup ? rasRow(setup, tr) : null}
  {#if ras}
    <hr />
    <CheckRow row={ras.row} title={ras.title} />
  {/if}
{/snippet}

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
    {#if setup?.engineNote}
      <p class="engine-note">{setup.engineNote}</p>
      {@render windowsVpnClient()}
      <hr class="full" />
    {:else if setup?.engine}
      {@const engine = setup.engine}
      {#each engineRows(setup, tr) as item, i (item.id)}
        {#if i > 0}
          <hr />
        {/if}
        <CheckRow
          row={item.row}
          title={item.title}
          showAction={(item.id === 'openvpn' && engine.openvpnAction !== undefined) ||
            (item.id === 'wireguard' && engine.wireguardAction !== undefined)}
        >
          {#if item.id === 'wireguard' && engine.wireguardAction}
            <button disabled={!setup.canInstallTools} onclick={() => runEngineAction('wireguard')}>
              {#if setup.brewRunning && outputRow === 'wireguard'}
                {tr('Installing…')}
              {:else}
                {tr('Update')}
              {/if}
            </button>
          {/if}
          {#if item.id === 'openvpn' && engine.openvpnAction}
            <button disabled={!setup.canInstallTools} onclick={() => runEngineAction('openvpn')}>
              {#if setup.brewRunning && outputRow === 'openvpn'}
                {tr('Installing…')}
              {:else if engine.openvpnAction === 'repair'}
                {tr('Repair')}
              {:else if engine.openvpnAction === 'update'}
                {tr('Update')}
              {:else}
                {tr('Install')}
              {/if}
            </button>
          {/if}
        </CheckRow>
        {#if item.id === outputRow && setup.brewOutput}
          <pre class="output" bind:this={output}>{setup.brewOutput}</pre>
        {/if}
      {/each}
      {@render windowsVpnClient()}
      {#if engine.laterNote}
        <p class="caption later-note">{engine.laterNote}</p>
      {/if}
      <hr class="full" />
    {:else if setup && nmItems.length > 0}
      {#each nmItems as item, i (item.id)}
        {#if i > 0}
          <hr />
        {/if}
        <CheckRow row={item.row} title={item.title} showAction={item.install !== undefined}>
          {#if item.install}
            {@const install = item.install}
            <button id={item.install.buttonId} disabled={!setup.canInstallTools} onclick={() => runNmInstall(install.kind)}>
              {#if setup.brewRunning && outputRow === item.id}
                {tr('Installing…')}
              {:else}
                {tr('Install')}
              {/if}
            </button>
          {/if}
        </CheckRow>
        {#if item.id === outputRow && setup.brewOutput}
          <pre class="output" bind:this={output}>{setup.brewOutput}</pre>
        {/if}
      {/each}
      <hr class="full" />
    {:else if setup?.homebrew && setup.tools && setup.root}
      <CheckRow row={setup.homebrew} title={tr('Homebrew')}>
        <button onclick={() => installHomebrew().catch(console.error)}>{tr('Install…')}</button>
      </CheckRow>
      <hr />
      <CheckRow row={setup.tools} title={tr('VPN tools')} showAction={setup.toolsAction === 'update'}>
        <button disabled={!setup.canInstallTools} onclick={() => api.setupInstallTools().catch(console.error)}>
          {#if setup.brewRunning}
            {tr('Installing…')}
          {:else if setup.toolsAction === 'update'}
            {tr('Update')}
          {:else}
            {tr('Install')}
          {/if}
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
      {#if !setup?.engine && nmItems.length === 0}
        <span class="caption">{tr('L2TP and Cisco IPsec work without these.')}</span>
      {/if}
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

  <!-- WinVPN: the MSI's uninstall in Settings → Apps; LinVPN: the package's removal command (no page to open). -->
  {#if setup?.systemUninstall}
    <div class="card system-uninstall">
      <div class="line">
        <span class="caption">{setup.systemUninstall}</span>
        {#if opensInstalledApps(i18n.platform.os)}
          <span class="spacer"></span>
          <button onclick={() => api.setupOpenSystemUninstall().catch(console.error)}>{tr('Open Installed Apps…')}</button>
        {/if}
      </div>
    </div>
  {/if}
  <!-- Without an engine (LinVPN's sandbox) the app installed nothing of its own to remove, and with the system's
       uninstall note (LinVPN, WinVPN without its account clean-up) the system removes it: no uninstall area. -->
  {#if !setup?.engineNote && (!setup?.systemUninstall || setup.accountCleanup)}
    <div class="card danger">
      <div class="line">
        <span class="caption">{uninstallText.caption}</span>
        <span class="spacer"></span>
        <button
          class="destructive uninstall"
          disabled={(setup?.uninstalling ?? false) || (setup?.installingRoot ?? false)}
          onclick={() => {
            removeUserData = false;
            confirmUninstall = true;
          }}>{uninstallText.button}</button
        >
      </div>
    </div>
  {/if}
</div>

{#if confirmUninstall}
  <Modal
    title={uninstallText.title}
    message={uninstallText.message}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (confirmUninstall = false) },
      { label: uninstallText.confirm, kind: 'destructive', action: () => uninstall().catch(console.error) },
    ]}
  >
    <label class="check accessory" title={tr('~/Library/Application Support/MacVPN with the vault, and in the Keychain the vault key and the old MacVPN 1.1 items')}>
      <input type="checkbox" bind:checked={removeUserData} />
      {tr('Also delete user data (connections, the vault and its key)')}
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
  .engine-note {
    font-size: var(--text-md);
  }
  .later-note {
    margin-left: 36px;
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
