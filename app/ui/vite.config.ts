import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';

// The UI loads the single EN/HU table of the core (crates/core/l10n/strings.json), outside this folder.
const l10nDir = fileURLToPath(new URL('../../crates/core/l10n', import.meta.url));
const uiDir = fileURLToPath(new URL('.', import.meta.url));

/// Only the `app` scope of the table is bundled (the core / root messages arrive translated from the backend).
function l10nAppScope(): Plugin {
  return {
    name: 'macvpn-l10n-app-scope',
    enforce: 'pre',
    transform(code, id) {
      if (!id.split('?')[0].endsWith('/crates/core/l10n/strings.json')) return null;
      const table = JSON.parse(code) as { strings: Record<string, { hu: string; scope: string }> };
      const strings = Object.fromEntries(Object.entries(table.strings).filter(([, e]) => e.scope === 'app'));
      return { code: JSON.stringify({ strings }), map: null };
    },
  };
}

export default defineConfig({
  plugins: [l10nAppScope(), svelte()],
  clearScreen: false,
  // Relative asset URLs: the bundle is served by Tauri's custom protocol.
  base: './',
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    fs: { strict: true, allow: [uiDir, l10nDir] },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'safari16',
    sourcemap: false,
    // No data: URIs and no inline scripts: everything is a file under the strict CSP (default-src 'self').
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
});
