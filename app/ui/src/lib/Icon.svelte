<script lang="ts" module>
  export type IconName =
    | 'plus'
    | 'list'
    | 'status'
    | 'gear'
    | 'chevron'
    | 'help'
    | 'power'
    | 'download'
    | 'warning'
    | 'refresh'
    | 'export'
    | 'trash'
    | 'bug'
    | 'key'
    | 'globe'
    | 'check'
    | 'cross'
    | 'search'
    | 'copy'
    | 'save'
    | 'play'
    | 'stop'
    | 'link'
    | 'lock'
    | 'folder'
    | 'folder-plus'
    | 'palette'
    | 'pencil'
    | 'arrow-up';
</script>

<script lang="ts">
  // The app's small line icons (16 × 16, drawn for MacVPN; decorative: the button or text next to it names it).
  let { name, class: className = '' }: { name: IconName; class?: string } = $props();
</script>

<svg class="icon {className}" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  {#if name === 'plus'}
    <path d="M8 3v10M3 8h10" />
  {:else if name === 'list'}
    <path d="M6 4.5h7M6 8h7M6 11.5h7" />
    <circle cx="3.2" cy="4.5" r="0.4" fill="currentColor" />
    <circle cx="3.2" cy="8" r="0.4" fill="currentColor" />
    <circle cx="3.2" cy="11.5" r="0.4" fill="currentColor" />
  {:else if name === 'status'}
    <path d="M1.8 8.4h2.6l1.6-4 2.6 8 1.8-5.2.9 1.2h2.9" />
  {:else if name === 'gear'}
    <circle cx="8" cy="8" r="2.1" />
    <path d="M8 1.8v1.7M8 12.5v1.7M14.2 8h-1.7M3.5 8H1.8M12.4 3.6l-1.2 1.2M4.8 11.2l-1.2 1.2M12.4 12.4l-1.2-1.2M4.8 4.8L3.6 3.6" />
  {:else if name === 'chevron'}
    <path d="M6 3.8L10.2 8 6 12.2" />
  {:else if name === 'help'}
    <circle cx="8" cy="8" r="6.2" />
    <path d="M6.2 6.3a1.9 1.9 0 0 1 3.7.5c0 1.3-1.9 1.6-1.9 2.8" />
    <circle cx="8" cy="11.6" r="0.3" fill="currentColor" />
  {:else if name === 'power'}
    <path d="M8 2v5.5" />
    <path d="M4.6 4.2a5.2 5.2 0 1 0 6.8 0" />
  {:else if name === 'download'}
    <path d="M8 2.5v8M4.8 7.5L8 10.7l3.2-3.2M3 13.5h10" />
  {:else if name === 'warning'}
    <path d="M8 2.2l6.2 11H1.8z" />
    <path d="M8 6.5v3" />
    <circle cx="8" cy="11.3" r="0.3" fill="currentColor" />
  {:else if name === 'refresh'}
    <path d="M13 3.5v3h-3" />
    <path d="M12.6 6.4A5 5 0 1 0 13 9.5" />
  {:else if name === 'export'}
    <path d="M8 1.8v8M5 4.6L8 1.8l3 2.8" />
    <path d="M5.5 7H4v6.5h8V7h-1.5" />
  {:else if name === 'trash'}
    <path d="M2.8 4.2h10.4M6.3 4.2V2.6h3.4v1.6M4.2 4.2l.6 9.2h6.4l.6-9.2M6.8 6.6v4.6M9.2 6.6v4.6" />
  {:else if name === 'bug'}
    <rect x="5" y="4.8" width="6" height="8.4" rx="3" />
    <path d="M6.2 4.6a1.8 1.8 0 0 1 3.6 0M8 7.4v5.8M2.6 8.6H5M11 8.6h2.4M3.2 5.4L5.2 6.4M12.8 5.4l-2 1M3.2 12.4l2-1.2M12.8 12.4l-2-1.2" />
  {:else if name === 'key'}
    <circle cx="5.2" cy="10.8" r="2.8" />
    <path d="M7.2 8.8L13 3M10.8 5.2l1.6 1.6M12.2 3.8l1.2 1.2" />
  {:else if name === 'globe'}
    <circle cx="8" cy="8" r="6" />
    <path d="M2 8h12M8 2c1.7 1.7 2.5 3.7 2.5 6S9.7 12.3 8 14C6.3 12.3 5.5 10.3 5.5 8S6.3 3.7 8 2z" />
  {:else if name === 'check'}
    <path d="M3.5 8.4l3 3 6-6.4" />
  {:else if name === 'cross'}
    <path d="M4.2 4.2l7.6 7.6M11.8 4.2l-7.6 7.6" />
  {:else if name === 'search'}
    <circle cx="7" cy="7" r="4.2" />
    <path d="M10.2 10.2L13.5 13.5" />
  {:else if name === 'copy'}
    <rect x="5.2" y="5.2" width="8" height="8.6" rx="1.6" />
    <path d="M10.8 5.2V3.8a1.6 1.6 0 0 0-1.6-1.6H4.4a1.6 1.6 0 0 0-1.6 1.6v5.6a1.6 1.6 0 0 0 1.6 1.6h.8" />
  {:else if name === 'save'}
    <path d="M8 2.5v7.5M5 7l3 3 3-3" />
    <path d="M2.8 10.5v1.7a1.3 1.3 0 0 0 1.3 1.3h7.8a1.3 1.3 0 0 0 1.3-1.3v-1.7" />
  {:else if name === 'play'}
    <path d="M5 3.2v9.6L12.6 8z" fill="currentColor" />
  {:else if name === 'stop'}
    <rect x="4" y="4" width="8" height="8" rx="1.6" fill="currentColor" />
  {:else if name === 'folder'}
    <path d="M1.8 4.2a1.4 1.4 0 0 1 1.4-1.4h3l1.4 1.5h5.2a1.4 1.4 0 0 1 1.4 1.4v6.1a1.4 1.4 0 0 1-1.4 1.4H3.2a1.4 1.4 0 0 1-1.4-1.4z" />
  {:else if name === 'folder-plus'}
    <path d="M14.2 7.2V5.7a1.4 1.4 0 0 0-1.4-1.4H7.6L6.2 2.8h-3a1.4 1.4 0 0 0-1.4 1.4v7.6a1.4 1.4 0 0 0 1.4 1.4h4.6" />
    <path d="M12 9.6v4.4M9.8 11.8h4.4" />
  {:else if name === 'palette'}
    <path d="M8 1.9a6.1 6.1 0 0 0 0 12.2c.9 0 1.4-.6 1.4-1.3 0-.8-.6-1-.6-1.7 0-.6.5-1 1.1-1h1.6a2.6 2.6 0 0 0 2.6-2.6C14.1 4.4 11.4 1.9 8 1.9z" />
    <circle cx="4.9" cy="7.4" r="0.5" fill="currentColor" />
    <circle cx="6.6" cy="4.8" r="0.5" fill="currentColor" />
    <circle cx="9.6" cy="4.6" r="0.5" fill="currentColor" />
  {:else if name === 'pencil'}
    <path d="M10.6 2.6l2.8 2.8-7.6 7.6H3v-2.8z" />
    <path d="M9.2 4l2.8 2.8" />
  {:else if name === 'arrow-up'}
    <path d="M8 13V3.2M4 7.2l4-4 4 4" />
  {:else if name === 'link'}
    <path d="M6.6 9.4l2.8-2.8" />
    <path d="M7.4 4.6l1.3-1.3a2.6 2.6 0 0 1 3.7 3.7l-1.3 1.3" />
    <path d="M8.6 11.4l-1.3 1.3a2.6 2.6 0 0 1-3.7-3.7l1.3-1.3" />
  {:else if name === 'lock'}
    <rect x="3.2" y="7" width="9.6" height="7" rx="1.6" />
    <path d="M5.2 7V5a2.8 2.8 0 0 1 5.6 0v2" />
    <circle cx="8" cy="10.5" r="0.4" fill="currentColor" />
  {/if}
</svg>

<style>
  .icon {
    flex: none;
    width: 16px;
    height: 16px;
  }
</style>
