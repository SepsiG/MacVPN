// A connection's state as shown next to its type: the text and its colour (the menu cards, the list, the detail).
import type { Row } from './api';
import { idleLine, uptime } from './format';
import { tr } from './l10n.svelte';

export type Tone = 'on' | 'busy' | 'fail' | 'off';

export interface StatusLine {
  /// The VPN type ("OpenVPN").
  type: string;
  /// The state's text (IP and uptime, the failure, …), if any.
  status: string | null;
  tone: Tone;
}

export function statusLine(row: Row, now: number): StatusLine {
  switch (row.state) {
    case 'connected': {
      const parts = [row.ip].filter((p): p is string => !!p);
      if (row.since !== null) parts.push(uptime(row.since, now));
      return { type: row.typeLabel, status: parts.length > 0 ? parts.join(' · ') : null, tone: 'on' };
    }
    case 'connecting':
      return { type: row.typeLabel, status: tr('Connecting…'), tone: 'busy' };
    case 'disconnecting':
      return { type: row.typeLabel, status: tr('Disconnecting…'), tone: 'busy' };
    case 'failed':
      return { type: row.typeLabel, status: row.reason, tone: 'fail' };
    case 'awaitingAuth':
      return { type: row.typeLabel, status: tr('Waiting for authentication'), tone: 'busy' };
    case 'waitingForNetwork':
      return { type: row.typeLabel, status: tr('Waiting for network…'), tone: 'busy' };
    case 'reconnecting':
      return { type: row.typeLabel, status: tr('Reconnecting…'), tone: 'busy' };
    case 'notResponding':
      return { type: row.typeLabel, status: tr('Not responding'), tone: 'fail' };
    case 'retrying':
      return { type: row.typeLabel, status: tr('Retrying in %@ min', Math.max(1, Math.ceil((row.at * 1000 - now) / 60000))), tone: 'busy' };
    default:
      return { ...idleLine(row), tone: 'off' };
  }
}

/// The whole line as one text (a tooltip).
export function statusText(line: StatusLine): string {
  return line.status ? `${line.type} · ${line.status}` : line.type;
}
