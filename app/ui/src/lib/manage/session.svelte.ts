// An editor's link to its draft in the backend (app-core `editor`): the fields live here while typing, every
// change is sent (at most one request in flight; the latest fields follow), and the backend answers with the
// derived state (dirty, risky panel, issues, …). The backend's draft is what "Save" of the unsaved-changes
// question and the quit save, so pending changes are flushed before any of those.
import { api, type EditorFields, type EditorView } from '../api';

let active: EditorSession | null = null;

/// Sends the shown editor's last change (before a selection change, the unsaved question's answer, …).
export async function flushActive(): Promise<void> {
  await active?.flush();
}

export class EditorSession {
  readonly id: string;
  fields = $state<EditorFields | null>(null);
  view = $state<EditorView | null>(null);
  error = $state<string | null>(null);
  #inFlight: Promise<void> | null = null;
  #queued = false;
  #lastSent = '';

  constructor(id: string) {
    this.id = id;
    active = this;
  }

  dispose(): void {
    if (active === this) active = null;
  }

  async open(): Promise<void> {
    try {
      this.#adopt(await api.editorOpen(this.id));
    } catch (e) {
      this.error = String(e);
    }
  }

  #adopt(view: EditorView): void {
    this.view = view;
    this.fields = structuredClone(view.fields);
    this.#lastSent = JSON.stringify(view.fields);
  }

  /// Call after the fields changed (an effect does it for every bound input).
  changed(): void {
    if (this.fields === null) return;
    if (JSON.stringify($state.snapshot(this.fields)) === this.#lastSent) return;
    if (this.#inFlight) {
      this.#queued = true;
      return;
    }
    this.#inFlight = this.#send().finally(() => {
      this.#inFlight = null;
      if (this.#queued) {
        this.#queued = false;
        this.changed();
      }
    });
  }

  async #send(): Promise<void> {
    const fields = $state.snapshot(this.fields) as EditorFields;
    const sent = JSON.stringify(fields);
    try {
      const view = await api.editorUpdate(this.id, fields);
      this.#lastSent = sent;
      // A newer change is on its way: its answer will follow.
      if (!this.#queued) this.view = view;
    } catch (e) {
      console.error(e);
    }
  }

  async flush(): Promise<void> {
    while (this.#inFlight) await this.#inFlight;
  }

  /// "Save" with the current fields. The backend may adjust them (the stored risky acknowledgement).
  async save(): Promise<void> {
    if (this.fields === null) return;
    await this.flush();
    const fields = $state.snapshot(this.fields) as EditorFields;
    const sent = JSON.stringify(fields);
    const view = await api.editorSave(this.id, fields);
    if (JSON.stringify($state.snapshot(this.fields)) === sent) this.#adopt(view);
    else this.view = view;
  }

  /// "Forget saved secrets" (system VPN).
  async forget(): Promise<void> {
    await this.flush();
    this.#adopt(await api.editorForget(this.id));
  }

  /// "Choose PEM File…" (SSTP): the panel, then the certificates into the form.
  async chooseCa(): Promise<void> {
    await this.flush();
    this.#adopt(await api.editorChooseCa(this.id));
  }
}
