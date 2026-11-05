//! The command line and the framed stdin of the helper's `up` (root layer 8), shared by MacVPN's `sudo mvpn` client
//! and WinVPN's service client: the config goes in the frame, never in an argument; the secrets follow it.

use crate::dns_settings::DnsRequest;
use crate::models::{Secrets, VPNKind, uuid_string};
use std::collections::BTreeSet;
use uuid::Uuid;
use zeroize::Zeroizing;

/// `up <kind> <ID> [--debug] [--accept-risky a,b]` (the acknowledged names sorted, `^[a-z0-9-]+$` only, OpenVPN only).
pub fn up_arguments(kind: VPNKind, id: &Uuid, debug: bool, accept_risky: &[String]) -> Vec<String> {
    let mut args = vec!["up".to_string(), kind.raw_value().to_string(), uuid_string(id)];
    if debug {
        args.push("--debug".into());
    }
    let names: BTreeSet<&str> = accept_risky
        .iter()
        .map(String::as_str)
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        .collect();
    if kind == VPNKind::Openvpn && !names.is_empty() {
        args.push("--accept-risky".into());
        args.push(names.into_iter().collect::<Vec<_>>().join(","));
    }
    args
}

/// `config <len>\n<config><secret lines>`, in one zeroized buffer allocated at its final size.
pub fn up_stdin(config: &[u8], secrets: &Secrets) -> Zeroizing<Vec<u8>> {
    up_stdin_with_dns(config, secrets, None)
}

/// [`up_stdin`] followed by the connection's DNS lines (root layer 15, macOS only: an older root layer refuses
/// them, so the caller sends a request only to root layer 15 or newer). `None`: byte-identical to [`up_stdin`].
pub fn up_stdin_with_dns(config: &[u8], secrets: &Secrets, dns: Option<&DnsRequest>) -> Zeroizing<Vec<u8>> {
    let lines = secrets.stdin_payload();
    let dns = dns.map(DnsRequest::frame_lines).unwrap_or_default();
    let header = format!("config {}\n", config.len());
    let mut payload = Zeroizing::new(Vec::with_capacity(header.len() + config.len() + lines.len() + dns.len()));
    payload.extend_from_slice(header.as_bytes());
    payload.extend_from_slice(config);
    payload.extend_from_slice(lines.as_bytes());
    payload.extend_from_slice(dns.as_bytes());
    payload
}
