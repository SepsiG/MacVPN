//! The toast's XML and tag (pure; the WinRT calls are in `win/toast.rs`).

/// The five XML entities.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A generic toast with a title and a body.
pub fn xml(title: &str, body: &str) -> String {
    format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>",
        escape(title),
        escape(body)
    )
}

/// The toast's tag (at most 64 characters): the identifier, or the first 32 hex digits of its SHA-256.
pub fn tag(identifier: &str) -> String {
    if identifier.len() <= 64 {
        identifier.to_string()
    } else {
        macvpn_core::update::sha256_hex(identifier.as_bytes())[..32].to_string()
    }
}
