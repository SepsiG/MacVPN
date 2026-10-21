//! Masking of secrets in everything that reaches a user-readable log (the bash `MASK_AWK`).
//!
//! Byte-oriented (the bash ran it under `LC_ALL=C`): every non-empty secret is replaced by `***`, literally (no
//! pattern). Secrets shorter than 3 bytes are replaced only as whole tokens (neither neighbour is an ASCII letter
//! or digit), otherwise a 1–2 character password would tear every word of the log apart.

use std::io::{BufRead, Read, Write};

/// The secrets one masker replaces, in order (password, PSK, key password, one-time code).
#[derive(Default, Clone)]
pub struct Masker {
    secrets: Vec<zeroize::Zeroizing<Vec<u8>>>,
}

impl Masker {
    pub fn new<'a>(secrets: impl IntoIterator<Item = &'a [u8]>) -> Masker {
        let mut m = Masker::default();
        for s in secrets {
            m.add(s);
        }
        m
    }

    /// Adds a secret; an empty one is ignored.
    pub fn add(&mut self, s: &[u8]) {
        if !s.is_empty() {
            self.secrets.push(zeroize::Zeroizing::new(s.to_vec()));
        }
    }

    /// One line (without its line end), every secret replaced in turn.
    pub fn line(&self, line: &[u8]) -> Vec<u8> {
        let mut out = line.to_vec();
        for s in &self.secrets {
            out = mask_one(&out, s);
        }
        out
    }

    #[cfg(test)]
    /// Masks a whole text line by line; every output line ends with `\n` (as awk prints it).
    pub fn text(&self, text: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len());
        for l in lines(text) {
            out.extend_from_slice(&self.line(l));
            out.push(b'\n');
        }
        out
    }

    /// The longest secret (bytes).
    fn max_len(&self) -> usize {
        self.secrets.iter().map(|s| s.len()).max().unwrap_or(0)
    }

    /// Streams `input` to `output` line by line, flushing after every line (the long-running masker).
    pub fn stream(&self, input: impl Read, mut output: impl Write) {
        self.stream_lines(input, MAX_LINE, |l| output.write_all(l).and_then(|_| output.flush()).is_ok());
    }

    /// Reads `input` until EOF and hands every masked line (with its `\n`) to `sink` as soon as it is complete;
    /// `sink` returns `false` to stop. A line longer than `cap` bytes is cut: the first `cap` bytes plus enough
    /// to cover any secret that starts inside them (and its neighbour for the token rule) are masked and emitted,
    /// the rest up to the line end is dropped. So memory stays bounded and no secret is split unmasked.
    pub fn stream_lines(&self, input: impl Read, cap: usize, mut sink: impl FnMut(&[u8]) -> bool) {
        let window = cap + self.max_len() + 1;
        let mut reader = std::io::BufReader::new(input);
        let mut line: Vec<u8> = Vec::new();
        let mut overflow = false;
        let mut emit = |line: &[u8]| {
            let mut l = self.line(line);
            l.push(b'\n');
            sink(&l)
        };
        loop {
            let chunk = match reader.fill_buf() {
                Ok([]) => break,
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let n = chunk.len();
            for &b in chunk {
                if b == b'\n' {
                    if !overflow && !emit(&line) {
                        return;
                    }
                    line.clear();
                    overflow = false;
                } else if !overflow {
                    line.push(b);
                    if line.len() >= window {
                        if !emit(&line) {
                            return;
                        }
                        line.clear();
                        overflow = true;
                    }
                }
            }
            reader.consume(n);
        }
        if !overflow && !line.is_empty() {
            emit(&line);
        }
    }
}

/// The longest line kept whole in a streamed log (longer lines are cut).
pub const MAX_LINE: usize = 64 * 1024;

/// The lines of a text as awk sees them: split at `\n`, a final line without `\n` included, no empty tail.
pub fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    let empty = text.is_empty();
    body.split(|&b| b == b'\n').filter(move |_| !empty)
}

fn is_alnum(b: Option<u8>) -> bool {
    b.is_some_and(|b| b.is_ascii_alphanumeric())
}

/// The awk `maskone`.
fn mask_one(line: &[u8], v: &[u8]) -> Vec<u8> {
    let n = v.len();
    let mut out = Vec::with_capacity(line.len());
    let mut rest = line;
    while let Some(p) = find(rest, v) {
        if n >= 3 {
            out.extend_from_slice(&rest[..p]);
            out.extend_from_slice(b"***");
        } else {
            let pre = if p > 0 { Some(rest[p - 1]) } else { out.last().copied() };
            let next = rest.get(p + n).copied();
            if !is_alnum(pre) && !is_alnum(next) {
                out.extend_from_slice(&rest[..p]);
                out.extend_from_slice(b"***");
            } else {
                out.extend_from_slice(&rest[..p + n]);
            }
        }
        rest = &rest[p + n..];
    }
    out.extend_from_slice(rest);
    out
}

/// First occurrence of `needle` (non-empty) in `hay`.
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The masker of a mask file's content: one secret per line (the backend reads the file).
pub fn from_mask_file(data: &[u8]) -> Masker {
    let mut m = Masker::default();
    for l in lines(data) {
        m.add(l);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(secret: &str, line: &str) -> String {
        String::from_utf8(Masker::new([secret.as_bytes()]).line(line.as_bytes())).unwrap()
    }

    #[test]
    fn long_secrets_anywhere_literally() {
        assert_eq!(m("Sup3rTitok", "a Sup3rTitok b"), "a *** b");
        assert_eq!(m("x.*y", "x.*y [a] x.*y"), "*** [a] ***");
        assert_eq!(m("%s!", "pw=%s! end"), "pw=*** end");
        assert_eq!(m("K3yP4ss", "k K3yP4ss"), "k ***");
    }

    #[test]
    fn short_secrets_only_as_tokens() {
        assert_eq!(m("ab", "ab cab ab. abc (ab)"), "*** cab ***. abc (***)");
        assert_eq!(m("x", "x y xx x"), "*** y xx ***");
        assert_eq!(m("x", "xx"), "xx");
    }

    #[test]
    fn byte_oriented() {
        assert_eq!(m("ŰR", "Szép ÁRVÍZTŰRŐ"), "Szép ÁRVÍZT***Ő");
    }

    #[test]
    fn empty_secret_ignored_and_order_kept() {
        let mk = Masker::new([b"".as_slice(), b"abc".as_slice(), b"bcd".as_slice()]);
        assert_eq!(mk.line(b"abcd"), b"***d".to_vec());
    }

    #[test]
    fn text_lines_end_with_newline() {
        let mk = Masker::new([b"pw1".as_slice()]);
        assert_eq!(mk.text(b"a pw1\nb"), b"a ***\nb\n".to_vec());
        assert_eq!(mk.text(b""), b"".to_vec());
        assert_eq!(mk.text(b"\n"), b"\n".to_vec());
    }

    #[test]
    fn stream_masks_each_line() {
        let mk = Masker::new([b"secret".as_slice()]);
        let mut out = Vec::new();
        mk.stream(&b"PASSWORD: \"secret\"\nok"[..], &mut out);
        assert_eq!(out, b"PASSWORD: \"***\"\nok\n".to_vec());
    }

    #[test]
    fn long_lines_are_cut_without_splitting_a_secret() {
        let mk = Masker::new([b"secret".as_slice()]);
        let mut input = b"ab".repeat(4);
        input.extend_from_slice(b"secret tail that is dropped\nnext\n");
        let mut out = Vec::new();
        mk.stream_lines(&input[..], 9, |l| {
            out.extend_from_slice(l);
            true
        });
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("secr"), "{text}");
        assert!(text.starts_with("abababab***"), "{text}");
        assert!(text.ends_with("\nnext\n"), "{text}");
        assert!(!text.contains("dropped"));
    }
}
