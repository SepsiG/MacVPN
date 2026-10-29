// The live traffic of the connected rows (the backend's `get_traffic`; its texts come in the UI language): read
// about once a second while this window is visible and shows a connected row, never while it is hidden.

/// One connected row's traffic.
export interface TrafficView {
  /// "↓ 12.4 MB  ↑ 1.2 MB".
  totals: string;
  /// "↓ 350 kB/s  ↑ 20.0 kB/s"; null until a rate is known.
  rates: string | null;
  /// The whole in words (tooltip, accessible label).
  tooltip: string;
}

export type TrafficMap = Record<string, TrafficView>;

/// How often a visible window asks (ms).
export const TRAFFIC_INTERVAL = 1000;

export interface TrafficDeps {
  fetch: () => Promise<TrafficMap>;
  /// The window is shown (`document.visibilityState`).
  visible: () => boolean;
  setInterval: (f: () => void, ms: number) => unknown;
  clearInterval: (handle: unknown) => void;
  /// Calls `f` when the visibility changes; returns the removal.
  onVisibility: (f: () => void) => () => void;
}

/// Starts the reads: `wanted` says whether a row is connected; `apply` gets each answer (an empty map when nothing
/// is wanted, so a line never outlives its connection). Returns the stop.
export function pollTraffic(wanted: () => boolean, apply: (t: TrafficMap) => void, deps: TrafficDeps): () => void {
  let busy = false;
  let stopped = false;
  const tick = () => {
    if (stopped || busy || !deps.visible()) return;
    if (!wanted()) {
      apply({});
      return;
    }
    busy = true;
    deps
      .fetch()
      .then((t) => {
        if (!stopped) apply(t);
      }, console.error)
      .finally(() => (busy = false));
  };
  const handle = deps.setInterval(tick, TRAFFIC_INTERVAL);
  const off = deps.onVisibility(tick);
  tick();
  return () => {
    stopped = true;
    deps.clearInterval(handle);
    off();
  };
}

/// The browser's timers and visibility.
export function browserDeps(fetch: () => Promise<TrafficMap>): TrafficDeps {
  return {
    fetch,
    visible: () => document.visibilityState === 'visible',
    setInterval: (f, ms) => setInterval(f, ms),
    clearInterval: (h) => clearInterval(h as ReturnType<typeof setInterval>),
    onVisibility: (f) => {
      document.addEventListener('visibilitychange', f);
      return () => document.removeEventListener('visibilitychange', f);
    },
  };
}
