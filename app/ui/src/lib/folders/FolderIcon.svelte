<script lang="ts">
  // A folder glyph in the folder's effective colour (a back panel with its tab, a front panel); without a colour,
  // the system grey. Decorative: the row names the folder.
  import type { FolderColor } from '../api';
  import { colorToken } from './tree';

  let { color, open = false, size = 18 }: { color: FolderColor | null; open?: boolean; size?: number } = $props();
</script>

<span class="folder-icon" class:open style:--fc={colorToken(color) ?? 'var(--vpn-system)'} style:width="{size}px" style:height="{Math.round(size * 0.78)}px">
  <svg viewBox="0 0 18 14" aria-hidden="true">
    <path class="back" d="M1 2.4A1.4 1.4 0 0 1 2.4 1h3.9c.4 0 .7.1 1 .4l1.2 1.2h7.1A1.4 1.4 0 0 1 17 4v7.6a1.4 1.4 0 0 1-1.4 1.4H2.4A1.4 1.4 0 0 1 1 11.6z" />
    <path class="front" d="M1 5.3A1.3 1.3 0 0 1 2.3 4h13.4A1.3 1.3 0 0 1 17 5.3v6.3a1.4 1.4 0 0 1-1.4 1.4H2.4A1.4 1.4 0 0 1 1 11.6z" />
  </svg>
</span>

<style>
  .folder-icon {
    flex: none;
    display: inline-flex;
  }
  svg {
    width: 100%;
    height: 100%;
    overflow: visible;
  }
  .back {
    fill: color-mix(in srgb, var(--fc) 55%, var(--surface));
  }
  .front {
    fill: var(--fc);
    transition: transform var(--duration) var(--ease);
    transform-origin: 50% 100%;
  }
  .open .front {
    transform: skewX(-8deg) scaleY(0.92);
  }
</style>
