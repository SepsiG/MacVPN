<script lang="ts" module>
  /// What the picker chose: a palette colour, `null` (no colour; on a folder), or `inherit` ("Use folder colour" on
  /// an item with its own colour).
  export type ColorChoice = import('../api').FolderColor | null | 'inherit';
</script>

<script lang="ts">
  // The colour popover: the 12 palette swatches, then "None" for a folder, or "Use folder colour" for an item
  // that has its own colour (an item without one already follows its folder).
  import type { FolderColor } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import { colorToken } from './tree';
  import { pointAnchor, popover } from '../popover';

  let {
    palette,
    value,
    target,
    inherited = null,
    x = 0,
    y = 0,
    onpick,
    onclose,
  }: {
    palette: FolderColor[];
    /// The own colour (null: none).
    value: FolderColor | null;
    target: 'folder' | 'item';
    /// An item's folder colour (shown on "Use folder colour").
    inherited?: FolderColor | null;
    x?: number;
    y?: number;
    onpick: (choice: ColorChoice) => void;
    onclose: () => void;
  } = $props();

  function colorName(color: FolderColor): string {
    switch (color) {
      case 'red':
        return tr('Red');
      case 'orange':
        return tr('Orange');
      case 'amber':
        return tr('Amber');
      case 'yellow':
        return tr('Yellow');
      case 'lime':
        return tr('Lime');
      case 'green':
        return tr('Green');
      case 'teal':
        return tr('Teal');
      case 'cyan':
        return tr('Cyan');
      case 'blue':
        return tr('Blue');
      case 'indigo':
        return tr('Indigo');
      case 'purple':
        return tr('Purple');
      case 'pink':
        return tr('Pink');
    }
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div class="dismiss" role="presentation" onpointerdown={onclose}></div>
<div class="picker" role="dialog" aria-label={tr('Colour')} use:popover={{ anchor: pointAnchor(x, y) }}>
  <p class="title">{tr('Colour')}</p>
  <div class="swatches" role="group" aria-label={tr('Colour')}>
    {#each palette as color (color)}
      <button
        class="swatch"
        data-color={color}
        class:selected={value === color}
        style:--sw={colorToken(color)}
        title={colorName(color)}
        aria-label={colorName(color)}
        aria-pressed={value === color}
        onclick={() => onpick(color)}
      >
        {#if value === color}<Icon name="check" />{/if}
      </button>
    {/each}
  </div>
  {#if target === 'folder'}
    <button class="option" class:selected={value === null} aria-pressed={value === null} onclick={() => onpick(null)}>
      <span class="none" aria-hidden="true"></span>
      <span class="option-label">{tr('None')}</span>
      {#if value === null}<Icon name="check" />{/if}
    </button>
  {:else if value !== null}
    <button class="option" onclick={() => onpick('inherit')}>
      <span class="inherit" style:--sw={colorToken(inherited) ?? 'transparent'} class:empty={!inherited} aria-hidden="true"></span>
      {tr('Use folder colour')}
    </button>
  {/if}
</div>

<style>
  .dismiss {
    position: fixed;
    inset: 0;
    z-index: 30;
  }
  .picker {
    position: fixed;
    z-index: 41;
    width: 188px;
    padding: 10px;
    box-sizing: border-box;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    animation: pop 0.14s var(--ease);
  }
  .title {
    margin: 0 2px 8px;
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--secondary);
  }
  .swatches {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 6px;
  }
  .swatch {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    justify-self: center;
    width: 22px;
    height: 22px;
    min-width: 0;
    min-height: 0;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: var(--sw);
    color: #fff;
    box-shadow: inset 0 0 0 0.5px rgba(0, 0, 0, 0.15);
    transition: transform var(--duration) var(--ease);
  }
  .swatch:hover {
    transform: scale(1.12);
  }
  .swatch.selected {
    box-shadow:
      0 0 0 2px var(--surface),
      0 0 0 3.5px var(--sw);
  }
  .swatch :global(.icon) {
    width: 12px;
    height: 12px;
    stroke-width: 2.4;
  }
  .option {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 8px;
    width: 100%;
    margin-top: 8px;
    padding: 5px 6px;
    border: none;
    border-top: 1px solid var(--separator);
    border-radius: 0;
    background: transparent;
    box-shadow: none;
    color: var(--text);
    font: inherit;
    font-size: var(--text-md);
    text-align: left;
  }
  .option-label {
    flex: 1;
  }
  .option :global(.icon) {
    width: 13px;
    height: 13px;
    color: var(--accent);
    stroke-width: 2;
  }
  .option:hover {
    border-radius: var(--radius-sm);
    background: var(--fill-hover);
  }
  .none,
  .inherit {
    flex: none;
    position: relative;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    box-sizing: border-box;
    border: 1.5px solid var(--border-strong);
  }
  .none::after {
    content: '';
    position: absolute;
    left: 50%;
    top: -1px;
    bottom: -1px;
    width: 1.5px;
    background: var(--state-fail);
    transform: translateX(-50%) rotate(45deg);
  }
  .inherit {
    border: 3px solid var(--sw);
    background: transparent;
  }
  .inherit.empty {
    border: 1.5px dashed var(--border-strong);
  }
  @keyframes pop {
    from {
      opacity: 0;
      transform: translateY(-4px) scale(0.98);
    }
  }
</style>
