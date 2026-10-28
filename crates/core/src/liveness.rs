//! A running tunnel's liveness facts (dead-tunnel detection, maintainer decision 2026-10-28): what the root layer
//! (`mvpn liveness <id>`, macOS root layer 10) and the WinVPN Service (`liveness <id>` on its pipe) report about a
//! connection the caller owns. Only times and counters: never a key, an address, an interface name or a path.
//!
//! ```text
//! wireguard <n>\n                                         n = 0 … MAX_PEERS peers, then n lines:
//! peer <handshake> <rx> <tx> <keepalive> <endpoint>\n    handshake: Unix seconds of the latest handshake (0: none
//!                                                         yet); rx / tx: bytes; keepalive: PersistentKeepalive
//!                                                         seconds (0: off); endpoint: 1 when the peer has one
//! openvpn up\n                                            OpenVPN connected (or not known to be reconnecting)
//! openvpn reconnecting <since>\n                          OpenVPN's own restart (`RECONNECTING` after it was
//!                                                         connected) since this Unix time
//! ```
//!
//! Numbers are ASCII decimal without sign or leading zero (but `0`), at most 20 digits, fitting a `u64`. Anything
//! else, also a longer answer than [`MAX_BYTES`], is refused (`None`): the app then detects nothing. The decision
//! what a dead tunnel is lives in the app (`macvpn_app_core::liveness`).

/// The command (both the macOS root layer and the WinVPN Service). An older root layer or service answers its usage
/// error: the app detects nothing then.
pub const LIVENESS: &str = "liveness";
/// The most peers reported (more are left out).
pub const MAX_PEERS: usize = 64;
/// The longest answer accepted.
pub const MAX_BYTES: usize = 8 * 1024;

/// One WireGuard peer's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WgPeer {
    /// The latest handshake, Unix seconds; `None`: none yet.
    pub last_handshake: Option<u64>,
    pub rx: u64,
    pub tx: u64,
    /// `PersistentKeepalive` in seconds; 0: off.
    pub keepalive: u16,
    /// The peer has an endpoint (only such a peer can start a handshake from this side).
    pub endpoint: bool,
}

/// What a tunnel reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    WireGuard(Vec<WgPeer>),
    /// `reconnecting_since`: OpenVPN restarts the tunnel itself (`ping-restart`, `SIGUSR1`) since this Unix time;
    /// `None`: up, or nothing known yet.
    OpenVpn {
        reconnecting_since: Option<u64>,
    },
}

fn number(s: &str) -> Option<u64> {
    let ok = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

impl Liveness {
    pub fn encode(&self) -> String {
        match self {
            Liveness::WireGuard(peers) => {
                let peers = &peers[..peers.len().min(MAX_PEERS)];
                let mut out = format!("wireguard {}\n", peers.len());
                for p in peers {
                    out.push_str(&format!(
                        "peer {} {} {} {} {}\n",
                        p.last_handshake.unwrap_or(0),
                        p.rx,
                        p.tx,
                        p.keepalive,
                        u8::from(p.endpoint)
                    ));
                }
                out
            }
            Liveness::OpenVpn { reconnecting_since: None } => "openvpn up\n".into(),
            Liveness::OpenVpn { reconnecting_since: Some(t) } => format!("openvpn reconnecting {t}\n"),
        }
    }

    /// Exactly the format above (every line ends in `\n`, nothing after the last one).
    pub fn parse(data: &[u8]) -> Option<Liveness> {
        if data.len() > MAX_BYTES {
            return None;
        }
        let text = std::str::from_utf8(data).ok()?;
        let body = text.strip_suffix('\n')?;
        let mut lines = body.split('\n');
        let head: Vec<&str> = lines.next()?.split(' ').collect();
        match head.as_slice() {
            ["openvpn", "up"] if lines.next().is_none() => Some(Liveness::OpenVpn { reconnecting_since: None }),
            ["openvpn", "reconnecting", t] if lines.next().is_none() => {
                Some(Liveness::OpenVpn { reconnecting_since: Some(number(t)?) })
            }
            ["wireguard", n] => {
                let n = usize::try_from(number(n)?).ok().filter(|n| *n <= MAX_PEERS)?;
                let mut peers = Vec::with_capacity(n);
                for line in lines.by_ref() {
                    let f: Vec<&str> = line.split(' ').collect();
                    let ["peer", h, rx, tx, k, e] = f.as_slice() else { return None };
                    let h = number(h)?;
                    let endpoint = match *e {
                        "0" => false,
                        "1" => true,
                        _ => return None,
                    };
                    peers.push(WgPeer {
                        last_handshake: (h != 0).then_some(h),
                        rx: number(rx)?,
                        tx: number(tx)?,
                        keepalive: u16::try_from(number(k)?).ok()?,
                        endpoint,
                    });
                }
                (peers.len() == n).then_some(Liveness::WireGuard(peers))
            }
            _ => None,
        }
    }
}
