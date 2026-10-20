<script lang="ts">
  // The Connections window's "Team catalogs" section (spec 5–6, plan Task 16): the list of subscriptions, one
  // subscription's detail, and the dialogs (add, edit source / team key / access token, unsubscribe). The views are
  // `CatalogList`, `CatalogDetail`, `AddCatalog`, `EditDialog` and `UnsubscribeDialog`; this container calls the
  // backend and keeps the outcome of the last refresh per catalog. A typed key or token never stays here: the
  // dialogs send it and close.
  import type { Row } from '../api';
  import Icon from '../Icon.svelte';
  import { i18n, tr } from '../l10n.svelte';
  import AddCatalog from './AddCatalog.svelte';
  import CatalogDetail from './CatalogDetail.svelte';
  import CatalogList from './CatalogList.svelte';
  import { catalogApi, type ApplyView, type SubscriptionView } from './catalogApi';
  import EditDialog, { type EditMode, type EditValue } from './EditDialog.svelte';
  import { activeRows, catalogRows, changesText, refreshLine, type StatusLine } from './status';
  import UnsubscribeDialog from './UnsubscribeDialog.svelte';

  let {
    catalogs,
    rows,
    message = null,
    oncredentials,
    opened = null,
    onopenedhandled = () => {},
  }: {
    catalogs: SubscriptionView[];
    rows: Row[];
    /// Why the section cannot be used now (the vault is locked).
    message?: string | null;
    oncredentials: () => void;
    /// A team catalog file opened from Finder (its name; `seq` tells two opens apart): the add dialog opens with it.
    opened?: { fileName: string; seq: number } | null;
    /// The opened file was taken into the add dialog.
    onopenedhandled?: () => void;
  } = $props();

  let selected = $state<string | null>(null);
  let adding = $state(false);
  /// The add dialog's opened file (from Finder), and its remount key.
  let addFile = $state<string | null>(null);
  let addKey = $state(0);
  let refreshing = $state<Set<string>>(new Set());
  let refreshingAll = $state(false);
  let results = $state<Record<string, StatusLine>>({});
  let editing = $state<{ id: string; mode: EditMode; tokenDropped: boolean; fileName: string | null; busy: boolean; error: string | null } | null>(
    null,
  );
  let unsubscribing = $state<{ id: string; busy: boolean; error: string | null } | null>(null);
  let notice = $state<string | null>(null);

  const current = $derived(catalogs.find((c) => c.id === selected) ?? null);
  /// The selection was seen in the view model (a new subscription is selected before its view model arrives).
  let seen: string | null = null;
  // The selected catalog is gone (unsubscribed, or the vault locked): back to the list.
  $effect(() => {
    if (current) seen = current.id;
    else if (selected !== null && seen === selected) selected = null;
  });

  // A catalog file opened from Finder: the add dialog with that file as the source, in place of whatever was open.
  $effect(() => {
    const o = opened;
    if (!o) return;
    selected = null;
    editing = null;
    unsubscribing = null;
    addFile = o.fileName;
    addKey = o.seq;
    adding = true;
    onopenedhandled();
  });

  function closeAdd() {
    adding = false;
    addFile = null;
  }

  function errorText(e: unknown): string {
    return typeof e === 'string' ? e : String(e);
  }

  async function refresh(id: string) {
    if (refreshing.has(id)) return;
    refreshing = new Set([...refreshing, id]);
    try {
      results = { ...results, [id]: refreshLine(await catalogApi.refresh(id)) };
    } catch (e) {
      results = { ...results, [id]: { text: errorText(e), severity: 'error' } };
    } finally {
      const next = new Set(refreshing);
      next.delete(id);
      refreshing = next;
    }
  }

  async function refreshAll() {
    if (refreshingAll) return;
    refreshingAll = true;
    try {
      const all = await catalogApi.refreshAll();
      const next = { ...results };
      for (const r of all) next[r.id] = refreshLine(r);
      results = next;
    } catch (e) {
      notice = errorText(e);
    } finally {
      refreshingAll = false;
    }
  }

  function subscribed(id: string, applied: ApplyView) {
    closeAdd();
    selected = id;
    const changes = changesText(applied);
    results = { ...results, [id]: { text: changes === '' ? tr('Subscribed.') : tr('Subscribed: %@', changes), severity: 'ok' } };
  }

  async function chooseFile() {
    const e = editing;
    if (!e) return;
    try {
      const name = await catalogApi.chooseFileSource();
      if (name !== null && editing) editing = { ...editing, fileName: name };
    } catch (err) {
      if (editing) editing = { ...editing, error: errorText(err) };
    }
  }

  async function saveEdit(value: EditValue) {
    const e = editing;
    if (!e || e.busy) return;
    editing = { ...e, busy: true, error: null };
    try {
      if (value.mode === 'source') {
        const dropped = await catalogApi.updateSource(e.id, value.url, value.chosenFile);
        results = { ...results, [e.id]: { text: tr('The source was changed.'), severity: 'ok' } };
        // The token was not carried to the new address: ask for the one it needs, if any.
        editing = dropped ? { id: e.id, mode: 'token', tokenDropped: true, fileName: null, busy: false, error: null } : null;
        return;
      }
      if (value.mode === 'teamKey') {
        await catalogApi.updateTeamKey(e.id, value.teamKey);
        results = { ...results, [e.id]: { text: tr('The team key was changed. Refresh now to apply the catalog.'), severity: 'ok' } };
      } else {
        await catalogApi.updateBearer(e.id, value.token);
        results = { ...results, [e.id]: { text: value.token === null ? tr('The access token was removed.') : tr('The access token was saved.'), severity: 'ok' } };
      }
      editing = null;
    } catch (err) {
      if (editing) editing = { ...editing, busy: false, error: errorText(err) };
    }
  }

  async function unsubscribe() {
    const u = unsubscribing;
    if (!u || u.busy) return;
    unsubscribing = { ...u, busy: true, error: null };
    try {
      const report = await catalogApi.unsubscribe(u.id);
      unsubscribing = null;
      selected = null;
      notice =
        report.keptCredentials.length > 0
          ? tr('Unsubscribed. These filled-in credentials are kept in Credentials: %@', report.keptCredentials.join(', '))
          : tr('Unsubscribed.');
    } catch (err) {
      if (unsubscribing) unsubscribing = { ...unsubscribing, busy: false, error: errorText(err) };
    }
  }
</script>

<div class="team-catalogs-section">
  {#if current}
    <CatalogDetail
      sub={current}
      connections={catalogRows(rows, current.id).length}
      language={i18n.language}
      refreshing={refreshing.has(current.id)}
      result={results[current.id] ?? null}
      onback={() => (selected = null)}
      onrefresh={() => refresh(current.id).catch(console.error)}
      onedit={(mode) => (editing = { id: current.id, mode, tokenDropped: false, fileName: null, busy: false, error: null })}
      onunsubscribe={() => (unsubscribing = { id: current.id, busy: false, error: null })}
      {oncredentials}
    />
  {:else}
    <header class="hero">
      <span class="hero-icon" aria-hidden="true"><Icon name="globe" /></span>
      <div class="hero-text">
        <h1>{tr('Team catalogs')}</h1>
        <p class="secondary">
          {tr('VPN connections your administrator shares with the team. They update by themselves and are read-only here; you sign in with your own user name and password.')}
        </p>
      </div>
    </header>
    {#if notice}
      <p class="notice" role="status"><span>{notice}</span><button class="dismiss-notice" onclick={() => (notice = null)}>{tr('OK')}</button></p>
    {/if}
    <CatalogList
      {catalogs}
      language={i18n.language}
      {message}
      refreshing={refreshingAll}
      onadd={() => {
        addFile = null;
        addKey += 1;
        adding = true;
      }}
      onrefreshall={() => refreshAll().catch(console.error)}
      onselect={(id) => (selected = id)}
    />
  {/if}
</div>

{#if adding}
  {#key addKey}
    <AddCatalog openedFile={addFile} onclose={closeAdd} onsubscribed={subscribed} />
  {/key}
{:else if editing}
  {@const e = editing}
  {@const sub = catalogs.find((c) => c.id === e.id)}
  <EditDialog
    mode={e.mode}
    name={sub?.name ?? ''}
    hasToken={sub?.hasToken ?? false}
    tokenDropped={e.tokenDropped}
    fileName={e.fileName}
    busy={e.busy}
    error={e.error}
    onchoosefile={() => chooseFile().catch(console.error)}
    onsave={(value) => saveEdit(value).catch(console.error)}
    oncancel={() => (editing = null)}
  />
{:else if unsubscribing}
  {@const u = unsubscribing}
  {@const sub = catalogs.find((c) => c.id === u.id)}
  <UnsubscribeDialog
    name={sub?.name ?? ''}
    connections={catalogRows(rows, u.id).length}
    active={activeRows(rows, u.id).map((r) => r.name)}
    busy={u.busy}
    error={u.error}
    onconfirm={() => unsubscribe().catch(console.error)}
    oncancel={() => (unsubscribing = null)}
  />
{/if}

<style>
  .team-catalogs-section {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-7) var(--space-7) var(--space-8);
    height: 100%;
    box-sizing: border-box;
    overflow: auto;
  }
  .hero {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 2px;
  }
  .hero-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: 10px;
    color: #fff;
    background: linear-gradient(180deg, var(--accent), var(--accent-pressed));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .hero-icon :global(.icon) {
    width: 22px;
    height: 22px;
    stroke-width: 1.7;
  }
  .hero-text {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
  }
  p {
    margin: 0;
  }
  .secondary {
    color: var(--secondary);
    font-size: var(--text-md);
  }
  .notice {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 8px 8px 8px 12px;
    border-radius: var(--radius-control);
    background: var(--state-on-soft);
    font-size: var(--text-md);
  }
  .notice span {
    flex: 1;
    overflow-wrap: anywhere;
  }
</style>
