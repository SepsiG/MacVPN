//! The local date formats of the UI, the same as MacVPN's (`platform-mac::system::local_date_time`).

use macvpn_core::l10n::AppLanguage;

/// `2026-10-18`.
pub fn date((y, mo, d): (i32, u32, u32)) -> String {
    format!("{y:04}-{mo:02}-{d:02}")
}

/// `10/18/2026, 2:03:05 PM` (English, a narrow no-break space before AM/PM) and `2026. 10. 18. 14:03:05` (Hungarian).
pub fn date_time((y, mo, d, h, mi, s): (i32, u32, u32, u32, u32, u32), language: AppLanguage) -> String {
    match language {
        AppLanguage::Hu => format!("{y}. {mo:02}. {d:02}. {h:02}:{mi:02}:{s:02}"),
        AppLanguage::En => {
            let (h12, suffix) = match h {
                0 => (12, "AM"),
                1..=11 => (h, "AM"),
                12 => (12, "PM"),
                _ => (h - 12, "PM"),
            };
            format!("{mo}/{d}/{y}, {h12}:{mi:02}:{s:02}\u{202f}{suffix}")
        }
    }
}
