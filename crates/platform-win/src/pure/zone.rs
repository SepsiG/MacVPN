//! The Mark of the Web: the `Zone.Identifier` alternate data stream a browser writes next to a download.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// The largest stream read (real ones are a few hundred bytes).
const MAX_STREAM: u64 = 4096;

/// Whether a `Zone.Identifier` stream's content marks a download: `ZoneId` 3 (Internet) or 4 (Restricted) in the
/// `[ZoneTransfer]` section. 0–2 (this computer, intranet, trusted) are not. Anything unreadable is marked.
pub fn marks_download(content: &[u8]) -> bool {
    let text = if let Some(rest) = content.strip_prefix(&[0xff, 0xfe]) {
        let (pairs, odd) = rest.as_chunks::<2>();
        if !odd.is_empty() {
            return true;
        }
        let units: Vec<u16> = pairs.iter().map(|&c| u16::from_le_bytes(c)).collect();
        match String::from_utf16(&units) {
            Ok(t) => t,
            Err(_) => return true,
        }
    } else {
        match std::str::from_utf8(content) {
            Ok(t) => t.trim_start_matches('\u{feff}').to_string(),
            Err(_) => return true,
        }
    };
    let (mut in_section, mut zone) = (false, None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_section = line.trim_start_matches('\u{feff}').eq_ignore_ascii_case("[ZoneTransfer]");
        } else if in_section
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("ZoneId")
        {
            zone = Some(value.trim().parse::<u32>().unwrap_or(u32::MAX));
        }
    }
    zone.is_none_or(|z| z >= 3)
}

/// The `DownloadMark` of WinVPN: marked when the file's stream says so or cannot be read; a missing file and a file
/// without the stream are not marked.
pub fn is_marked(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
        Ok(_) => {}
    }
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    match File::open(&stream) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
        Ok(file) => {
            let mut data = Vec::new();
            match file.take(MAX_STREAM + 1).read_to_end(&mut data) {
                Ok(_) if data.len() as u64 <= MAX_STREAM => marks_download(&data),
                _ => true,
            }
        }
    }
}
