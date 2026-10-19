<script lang="ts">
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import CredentialPrompt from './lib/CredentialPrompt.svelte';
  import Menu from './lib/Menu.svelte';
  import Pairing from './lib/Pairing.svelte';
  import Manage from './lib/manage/Manage.svelte';
  import Prompt from './lib/Prompt.svelte';
  import Setup from './lib/Setup.svelte';
  import Update from './lib/Update.svelte';

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
{:else if label.startsWith('prompt-')}
  <Prompt />
{:else if label.startsWith('cred-')}
  <CredentialPrompt />
{:else if label.startsWith('pair-')}
  <Pairing />
{/if}
