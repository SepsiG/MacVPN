import { getCurrentWindow } from '@tauri-apps/api/window';
import { mount } from 'svelte';
import App from './App.svelte';
import { api } from './lib/api';
import { platformOf } from './lib/l10n-core.ts';
import { i18n, setLanguage, setPlatform } from './lib/l10n.svelte';
import { languageOf } from './lib/language.ts';
import { OVERLAY_CLASS, usesOverlay } from './lib/overlay.ts';
import './app.css';

const target = document.getElementById('app');
if (target === null) throw new Error('no #app element');

// The texts' OS, product and language before the first render; on an error the macOS default (and the web view's
// languages) stay.
try {
  const reply = await api.platform();
  setPlatform(platformOf(reply));
  const language = languageOf(reply);
  if (language !== null) setLanguage(language);
} catch {
  // keeps the macOS default
}

// Linux: the menu window is the card panel's transparent overlay (only the card is drawn, at the top-right).
if (usesOverlay(i18n.platform.os, getCurrentWindow().label)) document.documentElement.classList.add(OVERLAY_CLASS);

export default mount(App, { target });
