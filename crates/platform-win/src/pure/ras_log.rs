//! The masked log of a RAS connection (`%LOCALAPPDATA%\WinVPN\logs\ras\<UUID>.log`, written by the `RasEngine`):
//! every line goes through a [`LogMasker`] of the connection's secrets, and the debug dump of an entry names its
//! effective settings, never a secret.

use macvpn_core::l10n;
use macvpn_core::models::Secrets;
use macvpn_core::ras::{Auth, DefaultRoute, RasEntryPlan, Strategy};
use zeroize::Zeroizing;

/// Replaces the connection's secrets (password, PSK, key password, one-time code; not the user name) by `***` in a
/// log line: the rule of the root layer's masker (`helper::shared::mask`): a secret of 3 bytes or more anywhere,
/// literally; a shorter one only as a whole token (neither neighbour is an ASCII letter or digit). A password
/// with the OTP code appended is covered by masking both.
#[derive(Default)]
pub struct LogMasker {
    secrets: Vec<Zeroizing<String>>,
}

impl LogMasker {
    pub fn new(secrets: &Secrets) -> LogMasker {
        let mut m = LogMasker::default();
        for s in [&secrets.password, &secrets.psk, &secrets.key_password, &secrets.one_time_code].into_iter().flatten()
        {
            if !s.is_empty() {
                m.secrets.push(Zeroizing::new(s.clone()));
            }
        }
        m
    }

    /// One line, every secret replaced in turn.
    pub fn line(&self, line: &str) -> String {
        let mut out = line.to_string();
        for s in &self.secrets {
            out = mask_one(&out, s);
        }
        out
    }

    pub fn lines(&self, lines: &[String]) -> Vec<String> {
        lines.iter().map(|l| self.line(l)).collect()
    }
}

fn is_alnum(b: Option<u8>) -> bool {
    b.is_some_and(|b| b.is_ascii_alphanumeric())
}

/// The helper's `mask_one` over `&str`: a UTF-8 secret only matches on character boundaries, so the result stays
/// UTF-8.
fn mask_one(line: &str, secret: &str) -> String {
    let n = secret.len();
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(p) = rest.find(secret) {
        let whole_token = n >= 3 || {
            let pre = if p > 0 { Some(rest.as_bytes()[p - 1]) } else { out.as_bytes().last().copied() };
            !is_alnum(pre) && !is_alnum(rest.as_bytes().get(p + n).copied())
        };
        out.push_str(&rest[..p]);
        out.push_str(if whole_token { "***" } else { &rest[p..p + n] });
        rest = &rest[p + n..];
    }
    out.push_str(rest);
    out
}

/// The debug-mode dump of an entry's effective settings (the plan holds no secret; which secrets the dial takes
/// is not listed either).
pub fn entry_dump(plan: &RasEntryPlan) -> Vec<String> {
    let strategy = match plan.strategy {
        Strategy::L2tp => "L2TP/IPsec",
        Strategy::Sstp => "SSTP",
        Strategy::Ikev2 => "IKEv2",
    };
    let auth = match plan.auth {
        Auth::MsChapV2 { .. } => "MS-CHAP v2",
        Auth::EapMsChapV2 => "EAP-MSCHAPv2",
        Auth::Ikev2Psk => "IKEv2 shared secret",
        Auth::MachineCertificate => "computer certificate",
    };
    let route = match plan.default_route {
        DefaultRoute::None => "split tunnel",
        DefaultRoute::Ipv4 => "all IPv4 traffic",
        DefaultRoute::Both => "all IPv4 and IPv6 traffic",
    };
    let mut lines = vec![
        format!("entry: {strategy}, server {}, {auth}", plan.server),
        format!("routing: {route}{}", if plan.ts_as_routes { ", traffic selectors as routes" } else { "" }),
    ];
    if !plan.user.is_empty() {
        lines.push(format!("user name: {}", plan.user));
    }
    if plan.strategy == Strategy::Ikev2 {
        lines.push(format!("IKE fragmentation: {}", if plan.ike_fragmentation { "on" } else { "off" }));
    }
    if let Some(metric) = plan.interface_metric {
        lines.push(format!("interface metric: {metric}"));
    }
    if let Some(policy) = &plan.policy {
        lines.push(format!("IPsec policy: {}", policy.describe()));
    }
    // The heading is translated; the settings are technical words, as an engine's log has them.
    lines.insert(0, l10n::tr("Windows VPN entry (debug mode):", &[]));
    lines
}
