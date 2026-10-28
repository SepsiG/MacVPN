// The Log tab's display rules (the same as app-core `logs`: the 5000-line cap, the All / Commands / Errors
// filter by line kind, the case-insensitive search, the time range over each line's time). Pure functions, so
// `node --test` can check them.
import type { LogFilter, LogLineView } from './api';

export const MAX_LINES = 5000;

/// The lines after an update from the backend (`reset`: replace), keeping the last 5000.
export function applyChunk(lines: LogLineView[], reset: boolean, incoming: LogLineView[]): LogLineView[] {
  const next = reset ? incoming.slice() : lines.concat(incoming);
  return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
}

export function matchesFilter(line: LogLineView, filter: LogFilter): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'commands':
      return line.kind === 'command' || line.kind === 'step' || line.kind === 'header';
    case 'errors':
      return line.kind === 'error';
  }
}

/// Inclusive bounds as local wall-clock seconds (app-core `logs::civil_seconds`, the unit of a line's `time`);
/// `null`: open. Both open: every line; otherwise a line without a known time is outside.
export interface TimeRange {
  from: number | null;
  to: number | null;
}

export const ANY_TIME: TimeRange = { from: null, to: null };

export function inRange(time: number | null, range: TimeRange): boolean {
  if (range.from === null && range.to === null) return true;
  return time !== null && (range.from === null || time >= range.from) && (range.to === null || time <= range.to);
}

/// The visible lines: the filter, the time range, then the search (`localizedCaseInsensitiveContains`; empty:
/// everything).
export function visibleLines(lines: readonly LogLineView[], filter: LogFilter, search: string, range: TimeRange = ANY_TIME): LogLineView[] {
  const needle = search.toLocaleLowerCase();
  return lines.filter((l) => matchesFilter(l, filter) && inRange(l.time, range) && (needle === '' || l.text.toLocaleLowerCase().includes(needle)));
}

/// A local date and time as wall-clock seconds (the logs write local time; no time zone on either side).
export function civilSeconds(d: Date): number {
  return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()) / 1000;
}

/// A `datetime-local` field's value (`YYYY-MM-DDTHH:MM[:SS]`) as wall-clock seconds; `null`: empty or invalid.
export function inputSeconds(value: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map((v) => (v === undefined ? 0 : Number(v)));
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  return Date.UTC(y, mo - 1, d, h, mi, s) / 1000;
}

export type TimePreset = 'any' | '5m' | '15m' | '1h' | 'today' | 'custom';

const PRESET_SECONDS: Partial<Record<TimePreset, number>> = { '5m': 300, '15m': 900, '1h': 3600 };

/// A quick preset's range at `now` (`custom`: see [`customRange`]; here every line).
export function presetRange(preset: TimePreset, now: Date): TimeRange {
  const seconds = PRESET_SECONDS[preset];
  if (seconds !== undefined) return { from: civilSeconds(now) - seconds, to: null };
  if (preset === 'today') return { from: civilSeconds(new Date(now.getFullYear(), now.getMonth(), now.getDate())), to: null };
  return ANY_TIME;
}

/// The custom "From" / "To" fields (minutes: "To" includes its whole minute, unless it gives seconds).
export function customRange(from: string, to: string): TimeRange {
  const end = inputSeconds(to);
  return { from: inputSeconds(from), to: end === null ? null : /:\d{2}:\d{2}$/.test(to) ? end : end + 59 };
}
