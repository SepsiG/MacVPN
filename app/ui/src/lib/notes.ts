// Release notes as the Swift `AttributedString(markdown:, interpretedSyntax: .inlineOnlyPreservingWhitespace)`
// showed them: plain text with inline emphasis (bold, italic, strikethrough, code) and link texts, whitespace and
// line breaks kept. The result is text segments: the view renders them as text nodes, so nothing in the notes is
// ever interpreted as HTML. Links are shown as their text only (the app opens no URL from the notes).

export interface Segment {
  text: string;
  bold: boolean;
  italic: boolean;
  strike: boolean;
  code: boolean;
}

interface Style {
  bold: boolean;
  italic: boolean;
  strike: boolean;
}

const PUNCTUATION = /[!-/:-@[-`{-~]/;
const WORD = /[\p{L}\p{N}]/u;

function push(out: Segment[], text: string, style: Style, code = false): void {
  if (text === '') return;
  const last = out[out.length - 1];
  if (last && !code && !last.code && last.bold === style.bold && last.italic === style.italic && last.strike === style.strike) {
    last.text += text;
  } else {
    out.push({ text, ...style, code });
  }
}

/// The closing delimiter of an emphasis opened at `from` (not right after whitespace; for `_`, not inside a word).
function closing(src: string, delimiter: string, from: number): number {
  let i = from;
  while (true) {
    const at = src.indexOf(delimiter, i);
    if (at < 0) return -1;
    const before = src[at - 1];
    const after = src[at + delimiter.length];
    const escaped = before === '\\';
    const flanking = at > from && before !== undefined && !/\s/.test(before);
    const wordy = delimiter[0] === '_' && after !== undefined && WORD.test(after);
    if (!escaped && flanking && !wordy) return at;
    i = at + 1;
  }
}

function parse(src: string, style: Style, out: Segment[]): void {
  let i = 0;
  let plain = '';
  const flush = () => {
    push(out, plain, style);
    plain = '';
  };
  while (i < src.length) {
    const c = src[i];
    if (c === '\\' && i + 1 < src.length && PUNCTUATION.test(src[i + 1])) {
      plain += src[i + 1];
      i += 2;
      continue;
    }
    if (c === '`') {
      let run = 1;
      while (src[i + run] === '`') run += 1;
      const fence = '`'.repeat(run);
      const end = src.indexOf(fence, i + run);
      if (end > i) {
        flush();
        push(out, src.slice(i + run, end), style, true);
        i = end + run;
        continue;
      }
      plain += fence;
      i += run;
      continue;
    }
    if (c === '[') {
      const close = src.indexOf(']', i + 1);
      if (close > i && src[close + 1] === '(') {
        const end = src.indexOf(')', close + 2);
        if (end > close) {
          flush();
          parse(src.slice(i + 1, close), style, out);
          i = end + 1;
          continue;
        }
      }
    }
    const two = src.slice(i, i + 2);
    if ((two === '**' || two === '__' || two === '~~') && src[i + 2] !== undefined && !/\s/.test(src[i + 2])) {
      const opensWord = two === '__' && i > 0 && WORD.test(src[i - 1]);
      const end = opensWord ? -1 : closing(src, two, i + 2);
      if (end > 0) {
        flush();
        const inner = two === '~~' ? { ...style, strike: true } : { ...style, bold: true };
        parse(src.slice(i + 2, end), inner, out);
        i = end + 2;
        continue;
      }
    }
    if ((c === '*' || c === '_') && src[i + 1] !== undefined && !/\s/.test(src[i + 1]) && src[i + 1] !== c) {
      const opensWord = c === '_' && i > 0 && WORD.test(src[i - 1]);
      const end = opensWord ? -1 : closing(src, c, i + 1);
      if (end > 0) {
        flush();
        parse(src.slice(i + 1, end), { ...style, italic: true }, out);
        i = end + 1;
        continue;
      }
    }
    plain += c;
    i += 1;
  }
  flush();
}

export function inlineSegments(notes: string): Segment[] {
  const out: Segment[] = [];
  parse(notes, { bold: false, italic: false, strike: false }, out);
  return out;
}
