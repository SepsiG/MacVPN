<script lang="ts">
  // "Delete folder" (spec 3): first what happens to its contents – moved to the parent folder (the default) or
  // the connections deleted too –, then, for the second, one more confirmation that names how many connections
  // go. An empty folder is only confirmed.
  import type { FolderTreeRow } from '../api';
  import { tr } from '../l10n.svelte';
  import Modal, { type ModalButton } from '../manage/Modal.svelte';
  import { deleteStep, isEmptyFolder, type DeleteMode } from './tree';

  let {
    folder,
    step = $bindable('choose'),
    mode = $bindable('moveUp'),
    ondelete,
    oncancel,
  }: {
    folder: FolderTreeRow;
    step?: 'choose' | 'confirm';
    mode?: DeleteMode;
    ondelete: (mode: DeleteMode) => void;
    oncancel: () => void;
  } = $props();

  const empty = $derived(isEmptyFolder(folder));
  const systemCount = $derived(folder.itemCount - folder.connectionCount);

  function next() {
    const chosen = empty ? 'moveUp' : mode;
    if (deleteStep(chosen, folder.connectionCount) === 'confirm') step = 'confirm';
    else ondelete(chosen);
  }

  const buttons = $derived<ModalButton[]>(
    step === 'confirm'
      ? [
          { label: tr('Cancel'), kind: 'cancel', action: oncancel },
          { label: tr('Delete Connections'), kind: 'destructive', action: () => ondelete('deleteContents') },
        ]
      : [
          { label: tr('Cancel'), kind: 'cancel', action: oncancel },
          { label: tr('Delete'), kind: mode === 'deleteContents' ? 'destructive' : 'primary', action: next },
        ],
  );
</script>

{#if step === 'confirm'}
  <Modal
    title={folder.connectionCount === 1 ? tr('Delete 1 connection?') : tr('Delete %lld connections?', folder.connectionCount)}
    message={tr('The connections in %@ and its subfolders are deleted with their saved passwords. This cannot be undone.', folder.name)}
    {buttons}
  />
{:else if empty}
  <Modal title={tr('Delete %@?', folder.name)} {buttons} />
{:else}
  <Modal title={tr('Delete %@?', folder.name)} message={tr('What should happen to its contents?')} {buttons}>
    <div class="choices" role="radiogroup">
      <label class="choice">
        <input type="radio" name="delete-mode" value="moveUp" bind:group={mode} />
        <span>{folder.parent === null ? tr('Move its contents to the top level') : tr('Move its contents to the parent folder')}</span>
      </label>
      <label class="choice">
        <input type="radio" name="delete-mode" value="deleteContents" bind:group={mode} />
        <span>
          {tr('Delete the connections too')}
          {#if systemCount > 0}<small>{tr('System VPNs are moved to the top level.')}</small>{/if}
        </span>
      </label>
    </div>
  </Modal>
{/if}

<style>
  .choices {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: -4px 0 16px;
  }
  .choice {
    display: flex;
    align-items: flex-start;
    gap: 9px;
    padding: 9px 11px;
    line-height: 18px;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
    color: var(--text);
  }
  /* A radio drawn like the app's checkboxes: a ring, filled with the accent and a white dot when chosen. */
  .choice input {
    -webkit-appearance: none;
    appearance: none;
    flex: none;
    box-sizing: border-box;
    width: 16px;
    height: 16px;
    min-height: 0;
    margin: 1px 0 0;
    padding: 0;
    border-radius: 50%;
    border: 1px solid var(--field-border);
    background: var(--field);
    box-shadow: inset 0 0.5px 1px rgba(0, 0, 0, 0.06);
    transition:
      background-color var(--duration) var(--ease),
      border-color var(--duration) var(--ease);
  }
  .choice input:checked {
    border-color: var(--accent);
    background: radial-gradient(circle, #fff 0 3px, var(--accent) 3.5px);
  }
  .choice:has(input:checked) {
    box-shadow: inset 0 0 0 1.5px color-mix(in srgb, var(--accent) 55%, transparent);
  }
  .choice span {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  small {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
</style>
