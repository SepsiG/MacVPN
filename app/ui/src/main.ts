import { mount } from 'svelte';
import App from './App.svelte';
import { api } from './lib/api';
import { platformOf } from './lib/l10n-core.ts';
import { setPlatform } from './lib/l10n.svelte';
import './app.css';

const target = document.getElementById('app');
if (target === null) throw new Error('no #app element');

// The texts' OS and product before the first render; on an error the macOS default stays.
try {
  setPlatform(platformOf(await api.platform()));
} catch {
  // keeps the macOS default
}

export default mount(App, { target });
