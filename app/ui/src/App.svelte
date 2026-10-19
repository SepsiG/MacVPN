<script lang="ts">
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import CredentialPrompt from './lib/CredentialPrompt.svelte';
  import Menu from './lib/Menu.svelte';
  import Pairing from './lib/Pairing.svelte';
  import Manage from './lib/manage/Manage.svelte';
  import Prompt from './lib/Prompt.svelte';
  import Setup from './lib/Setup.svelte';
  import Update from './lib/Update.svelte';
  import CreateVault from './lib/vault/CreateVault.svelte';
  import NewKey from './lib/vault/NewKey.svelte';
  import PasswordWindow from './lib/vault/PasswordWindow.svelte';
  import Unlock from './lib/vault/Unlock.svelte';
  import Backup from './lib/vault/Backup.svelte';
  import Restore from './lib/vault/Restore.svelte';

  // The window's label (set by the backend) selects the view; no IPC needed to read it.
  const label = getCurrentWindow().label;
</script>

{#if label === 'menu'}
  <Menu />
{:else if label === 'manage'}
  <Manage />
{:else if label === 'setup'}
  <Setup />
{:else if label === 'update'}
  <Update />
{:else if label === 'backup'}
  <Backup />
{:else if label === 'restore'}
  <Restore />
{:else if label.startsWith('prompt-')}
  <Prompt />
{:else if label.startsWith('cred-')}
  <CredentialPrompt />
{:else if label.startsWith('pair-')}
  <Pairing />
{:else if label === 'vault-create'}
  <CreateVault />
{:else if label === 'vault-unlock'}
  <Unlock />
{:else if label === 'vault-password'}
  <PasswordWindow />
{:else if label === 'vault-recovery'}
  <NewKey />
{/if}
