<script lang="ts">
  // "Add team catalog…" (spec 5): the dialog's state and calls (the view is `AddCatalogView.svelte`). The pasted
  // string, the team key and the token live only in this component's memory: they are sent with "Check" and wiped
  // right after it succeeded, and everything goes when the dialog closes. Closing after "Check" drops the verified
  // download in the backend too (`catalog_discard`).
  import { onDestroy } from 'svelte';
  import AddCatalogView from './AddCatalogView.svelte';
  import { tr } from '../l10n.svelte';
  import { catalogApi, type ApplyView, type CatalogPreview } from './catalogApi';
  import { afterCheck, emptyForm, pastedKind, previewInput, withoutSecrets, type AddForm } from './subscription';

  let { onclose, onsubscribed }: { onclose: () => void; onsubscribed: (catalogId: string, applied: ApplyView) => void } = $props();

  let form = $state<AddForm>(emptyForm());
  let step = $state<'enter' | 'preview'>('enter');
  let preview = $state<CatalogPreview | null>(null);
  let compared = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  /// Closed (Cancel, or unmounted): a "Check" still running drops its result.
  let closed = false;

  function message(e: unknown): string {
    return typeof e === 'string' ? e : String(e);
  }

  async function paste(text: string) {
    error = null;
    const kind = pastedKind(text);
    if (kind === 'other') error = tr('This is not a subscription string.');
    if (kind !== 'subscription') return;
    try {
      const parsed = await catalogApi.parseSubscription(text);
      form = { ...form, subscription: text, parsed: { ...parsed } };
    } catch (e) {
      error = message(e);
    }
  }

  async function chooseFile() {
    try {
      const name = await catalogApi.chooseFileSource();
      if (name !== null) form = { ...form, fileName: name };
    } catch (e) {
      error = message(e);
    }
  }

  async function check() {
    if (busy) return;
    busy = true;
    error = null;
    try {
      const sent = await catalogApi.preview(previewInput(form));
      const result = await afterCheck(sent, () => closed, catalogApi.discard);
      if (!result) return;
      // Sent: the string, the key and the token are not kept.
      form = withoutSecrets(form);
      preview = result;
      compared = false;
      step = 'preview';
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  /// The verified download is dropped in the backend (it holds the team key) whenever it is not confirmed.
  function discard() {
    const pending = preview?.pendingId;
    preview = null;
    if (pending) catalogApi.discard(pending).catch(console.error);
  }

  function back() {
    discard();
    error = null;
    step = 'enter';
  }

  async function subscribe() {
    const current = preview;
    if (busy || !current || !compared) return;
    busy = true;
    error = null;
    try {
      const applied = await catalogApi.confirm(current.pendingId);
      preview = null;
      form = emptyForm();
      onsubscribed(current.catalogId, applied);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  function cancel() {
    closed = true;
    discard();
    form = emptyForm();
    onclose();
  }

  onDestroy(() => {
    closed = true;
    discard();
    form = emptyForm();
  });
</script>

<AddCatalogView
  {step}
  bind:form
  {preview}
  {compared}
  {busy}
  {error}
  onpaste={(text) => paste(text).catch(console.error)}
  onclearpaste={() => (form = withoutSecrets(form))}
  onchoosefile={() => chooseFile().catch(console.error)}
  oncheck={() => check().catch(console.error)}
  onback={back}
  oncompared={(on) => (compared = on)}
  onsubscribe={() => subscribe().catch(console.error)}
  oncancel={cancel}
/>
