// The Log tab's display rules (the same as app-core `logs`: the 5000-line cap, the All / Commands / Errors
// filter by line kind, the case-insensitive search). Pure functions, so `node --test` can check them.
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

/// The visible lines: the filter, then the search (`localizedCaseInsensitiveContains`; empty: everything).
export function visibleLines(lines: readonly LogLineView[], filter: LogFilter, search: string): LogLineView[] {
  const needle = search.toLocaleLowerCase();
  return lines.filter((l) => matchesFilter(l, filter) && (needle === '' || l.text.toLocaleLowerCase().includes(needle)));
}
