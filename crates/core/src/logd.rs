//! linvpn-logd's protocol and journal filter (LinVPN L-b, Task 10).
//!
//! The pure half of `linvpn-logd` (resolved points 3, 9, 10 of the L-b plan): the server (helper crate) and the
//! client (platform-linux) only move bytes. One request and one response per connection, ASCII lines:
//!
//! ```text
//! request:  linvpn-logd-v1 <connection UUID> <since µs> <cursor or ->\n            (≤ MAX_REQUEST bytes)
//! response: L <µs> <nm|openvpn|plugin:<ident>> <escaped text>\n   × ≤ MAX_LINES
//!           W\n                                                    (optional: plugin lines withheld)
//!           C <cursor or ->\n
//!           E\n                                                    (≤ MAX_RESPONSE bytes in all)
//! ```
//!
//! **Ownership** needs no state: the server derives the NetworkManager UUID from the caller's `SO_PEERCRED` uid and
//! the LinVPN connection id the caller names ([`crate::nm_plan::names::nm_uuid`]), so a caller can only reach UUIDs
//! derived from its own uid. **Attribution** ([`select`]): NetworkManager's lines of that UUID, OpenVPN's lines
//! under `linvpn-ovpn-<UUID>`, and a VPN plugin's line only when NetworkManager's VPN history says it can be nobody
//! else's: at that moment the caller's connection was active (after its own `starting <plugin>` line, before its
//! end) and no other VPN connection may have been, counting every connection activated since NetworkManager's last
//! start (a second, fixed query: [`history_args`]). Another user's tunnel that was up before the caller's window
//! and stays up after it writes no line inside the window, yet its activation is in the history, so its plugin
//! lines are withheld (security review M1). Without NM's start line in the history nothing is known and no plugin
//! line passes.
//!
//! **Ends** (lab run 2): NetworkManager 1.54.3 at its default level logs no end of a VPN connection that finishes
//! normally (its state lines are debug), and for a failure only a warning ([`vpn_change`]: `dbus: failure: …`,
//! `failed to connect: '…'`, …). So logd also reads NetworkManager's active VPN connections over the system bus at
//! every request ([`Observation`]) and records a reading that says something new in its own journal (a third
//! query: [`observation_args`]): a connection active since before a reading began that the reading did not see
//! ended by the reading's end. The engine asks once right before each activation, so earlier connections that are
//! gone no longer count. A connection without any end line or reading after it stays active (fail closed). A plugin's `_PID` cannot carry the attribution:
//! charon-nm (and nm-l2tp) serve every connection from one D-Bus activated process, and the per-connection services'
//! children (openvpn, pppd, sstpc, vpnc) have pids NM never logs. Anything that cannot be attributed is refused
//! (fail closed).
//!
//! **Senders** (L-b Task 18): `SYSLOG_IDENTIFIER`, `MESSAGE` and `NM_CONNECTION` are written by the sender, so any
//! local user could forge them (`logger -t linvpn-ovpn-<UUID> …`). A line counts only when the journal's *trusted*
//! fields (set by journald from the kernel's credentials, never by the sender) name the expected process:
//! NetworkManager's lines `_SYSTEMD_UNIT=NetworkManager.service` and `_UID=0`; OpenVPN's lines `_COMM=openvpn` and
//! `_UID` root or the `nm-openvpn` user ([`Senders`], resolved by the server at runtime); each plugin's lines its own
//! process names ([`plugin_senders`]) and `_UID` root (the OpenVPN plugin's also `nm-openvpn`). A missing trusted
//! field drops the line. NetworkManager 1.54.3 writes `NM_CONNECTION=<connection UUID>` (`nm-logging.c`,
//! `_nm_log_impl`, the journal backend: `NM_LOG_LEVEL`, `NM_LOG_DOMAINS`, `NM_DEVICE`, `NM_CONNECTION`), so the
//! `MESSAGE` fallback only matters for other versions.

use serde_json::Value;
use uuid::Uuid;

pub const MAGIC: &str = "linvpn-logd-v1";
/// The longest request, newline included.
pub const MAX_REQUEST: usize = 512;
/// The most `L` lines in one response.
pub const MAX_LINES: usize = 2000;
/// The longest response, `E\n` included.
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// The longest escaped text of one line, in bytes (`…` included when cut).
pub const MAX_TEXT: usize = 2048;
pub const MAX_CURSOR: usize = 256;
/// How many journal entries `journalctl` returns at most (`-n`).
pub const JOURNAL_ENTRIES: u32 = 20_000;
/// The `SYSLOG_IDENTIFIER` prefix of LinVPN's NM OpenVPN service's OpenVPN (resolved point 6).
pub const OPENVPN_IDENT_PREFIX: &str = "linvpn-ovpn-";
/// NetworkManager's own `SYSLOG_IDENTIFIER`.
pub const NM_IDENT: &str = "NetworkManager";
/// The VPN plugins' idents whose lines carry no connection: returned only while the connection is the only active VPN.
pub const PLUGIN_IDENTS: [&str; 10] = [
    "charon-nm",
    "nm-l2tp-service",
    "xl2tpd",
    "pppd",
    "nm-sstp-service",
    "sstpc",
    "nm-vpnc-service",
    "vpnc",
    "nm-openvpn",
    "nm-openvpn-serv",
];
const ELLIPSIS: char = '…';
/// NetworkManager's systemd unit (the journal's trusted `_SYSTEMD_UNIT` of its own lines).
pub const NM_UNIT: &str = "NetworkManager.service";
/// OpenVPN's process name (`_COMM`).
pub const OPENVPN_COMM: &str = "openvpn";
/// The user NetworkManager's OpenVPN plugin drops OpenVPN to (`--user nm-openvpn`); its uid is looked up at runtime.
pub const NM_OPENVPN_USER: &str = "nm-openvpn";
const OUTPUT_FIELDS: &str = "--output-fields=__REALTIME_TIMESTAMP,__CURSOR,SYSLOG_IDENTIFIER,MESSAGE,NM_CONNECTION,\
     NM_LOG_DOMAINS,CODE_FUNC,_UID,_SYSTEMD_UNIT,_COMM";
/// How many journal entries the VPN history query returns at most (`-n`, the newest).
pub const HISTORY_ENTRIES: u32 = 5_000;

/// The processes a plugin ident's lines may come from: their `_COMM` names (the kernel's name, at most 15 bytes:
/// `nm-openvpn-service` and its helper are `nm-openvpn-serv`) and whether the `nm-openvpn` user may send them (else
/// only root). `None` for an ident outside [`PLUGIN_IDENTS`].
pub fn plugin_senders(ident: &str) -> Option<(&'static [&'static str], bool)> {
    Some(match ident {
        "charon-nm" => (&["charon-nm"], false),
        "nm-l2tp-service" => (&["nm-l2tp-service"], false),
        "xl2tpd" => (&["xl2tpd"], false),
        "pppd" => (&["pppd"], false),
        "nm-sstp-service" => (&["nm-sstp-service"], false),
        "sstpc" => (&["sstpc"], false),
        "nm-vpnc-service" => (&["nm-vpnc-service"], false),
        "vpnc" => (&["vpnc"], false),
        // The stock plugin's OpenVPN (`--syslog nm-openvpn`) and the service itself.
        "nm-openvpn" => (&[OPENVPN_COMM, "nm-openvpn-serv"], true),
        "nm-openvpn-serv" => (&["nm-openvpn-serv"], true),
        _ => return None,
    })
}

/// Who besides root may send OpenVPN's lines: the uid of [`NM_OPENVPN_USER`] (`None` when it does not exist: then
/// only root's lines count). The server resolves it at runtime (`getpwnam`); the pure rules take it as a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Senders {
    pub nm_openvpn_uid: Option<u32>,
}

impl Senders {
    fn openvpn_uid(&self, uid: u32) -> bool {
        uid == 0 || self.nm_openvpn_uid == Some(uid)
    }
}

/// What the client asks: the lines of `connection` (a LinVPN connection id, not the NM UUID) since `since_usec`
/// (journal realtime, µs), after `cursor` when given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub connection: Uuid,
    pub since_usec: u64,
    pub cursor: Option<String>,
}

impl Request {
    pub fn encode(&self) -> String {
        format!(
            "{MAGIC} {} {} {}\n",
            self.connection.hyphenated(),
            self.since_usec,
            self.cursor.as_deref().unwrap_or("-")
        )
    }

    /// Strict: exactly the form [`Request::encode`] writes (lower-case UUID, no leading zero, one `\n`), or `None`.
    pub fn parse(s: &str) -> Option<Request> {
        if s.len() > MAX_REQUEST {
            return None;
        }
        let body = s.strip_suffix('\n')?;
        let mut it = body.split(' ');
        let (magic, id, since, cursor) = (it.next()?, it.next()?, it.next()?, it.next()?);
        if magic != MAGIC || it.next().is_some() {
            return None;
        }
        let connection = canonical_uuid(id)?;
        let since_usec = parse_dec(since)?;
        let cursor = if cursor == "-" { None } else { Some(valid_cursor(cursor)?.to_string()) };
        Some(Request { connection, since_usec, cursor })
    }
}

/// Where a returned line came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    NetworkManager,
    OpenVpn,
    /// One of [`PLUGIN_IDENTS`] (on the wire: any ident of `[a-z0-9_.-]{1,32}`).
    Plugin(String),
}

impl Source {
    fn encode(&self) -> String {
        match self {
            Source::NetworkManager => "nm".into(),
            Source::OpenVpn => "openvpn".into(),
            Source::Plugin(p) => format!("plugin:{p}"),
        }
    }

    fn parse(s: &str) -> Option<Source> {
        match s {
            "nm" => Some(Source::NetworkManager),
            "openvpn" => Some(Source::OpenVpn),
            _ => {
                let p = s.strip_prefix("plugin:")?;
                valid_ident(p).then(|| Source::Plugin(p.to_string()))
            }
        }
    }
}

/// One returned line; `text` is already escaped ([`escape_text`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub usec: u64,
    pub source: Source,
    pub text: String,
}

/// The server's answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    pub lines: Vec<Line>,
    /// Plugin lines existed in the window but another VPN was active in it, so none was returned.
    pub withheld: bool,
    /// The cursor of the last returned line (the client's next `after-cursor`).
    pub cursor: Option<String>,
}

impl Response {
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(self.lines.iter().map(line_len).sum::<usize>() + 300);
        for l in &self.lines {
            push_line(&mut out, l);
        }
        out.push_str(&self.tail());
        out
    }

    fn tail(&self) -> String {
        format!("{}C {}\nE\n", if self.withheld { "W\n" } else { "" }, self.cursor.as_deref().unwrap_or("-"))
    }

    /// Strict: the order `L*`, `W?`, `C`, `E`, every field valid, the bounds kept, or `None`.
    pub fn parse(s: &str) -> Option<Response> {
        if s.len() > MAX_RESPONSE {
            return None;
        }
        let body = s.strip_suffix("C -\nE\n").map(|b| (b, None)).or_else(|| {
            let b = s.strip_suffix("\nE\n")?;
            let at = b.rfind('\n').map_or(0, |i| i + 1);
            let c = b[at..].strip_prefix("C ")?;
            Some((&b[..at], Some(valid_cursor(c)?.to_string())))
        });
        let (body, cursor) = body?;
        let (body, withheld) = match body.strip_suffix("W\n") {
            Some(b) if b.is_empty() || b.ends_with('\n') => (b, true),
            _ => (body, false),
        };
        let mut lines = Vec::new();
        for raw in body.split_inclusive('\n') {
            let raw = raw.strip_suffix('\n')?;
            let mut f = raw.splitn(4, ' ');
            let (tag, usec, source, text) = (f.next()?, f.next()?, f.next()?, f.next()?);
            if tag != "L" || text.len() > MAX_TEXT || text.chars().any(is_control) {
                return None;
            }
            lines.push(Line { usec: parse_dec(usec)?, source: Source::parse(source)?, text: text.to_string() });
            if lines.len() > MAX_LINES {
                return None;
            }
        }
        Some(Response { lines, withheld, cursor })
    }
}

/// One journal entry as `journalctl -o json` prints it (only the fields LinVPN asks for).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub usec: u64,
    pub cursor: String,
    pub ident: String,
    /// Escaped and bounded ([`escape_text`]).
    pub message: String,
    pub nm_connection: Option<String>,
    pub nm_domains: Option<String>,
    /// The trusted `_UID` (journald, from the kernel's credentials of the sender).
    pub uid: Option<u32>,
    /// The trusted `_SYSTEMD_UNIT` (journald, from the sender's cgroup).
    pub unit: Option<String>,
    /// The trusted `_COMM` (journald, the sender's kernel process name).
    pub comm: Option<String>,
    /// `CODE_FUNC` (NetworkManager's C function; only read on NetworkManager's trusted lines).
    pub code_func: Option<String>,
}

/// One line of `journalctl -o json`, or `None` when it lacks a field or a field has an unexpected form (a
/// multi-valued field, a non-decimal time or uid, an invalid cursor). The trusted fields may be missing (journald
/// cannot always read them for a process that already exited); [`select`] then drops the line. A byte-array `MESSAGE` (journalctl's form for
/// non-UTF-8) is decoded lossily; the message is escaped and bounded here.
pub fn parse_entry(json_line: &str) -> Option<Entry> {
    let v: Value = serde_json::from_str(json_line).ok()?;
    let o = v.as_object()?;
    let text = |k: &str| o.get(k).and_then(Value::as_str);
    let usec = parse_dec(text("__REALTIME_TIMESTAMP")?)?;
    let cursor = valid_cursor(text("__CURSOR")?)?.to_string();
    let ident = text("SYSLOG_IDENTIFIER")?.to_string();
    let message = match o.get("MESSAGE")? {
        Value::String(s) => escape_text(s),
        Value::Array(a) => {
            let bytes = a.iter().map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok())).collect::<Option<Vec<u8>>>()?;
            escape_text(&String::from_utf8_lossy(&bytes))
        }
        _ => return None,
    };
    let optional = |k: &str| match o.get(k) {
        None => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        Some(_) => None,
    };
    Some(Entry {
        usec,
        cursor,
        ident,
        message,
        nm_connection: optional("NM_CONNECTION")?,
        nm_domains: optional("NM_LOG_DOMAINS")?,
        uid: match optional("_UID")? {
            None => None,
            Some(u) => Some(u32::try_from(parse_dec(&u)?).ok()?),
        },
        unit: optional("_SYSTEMD_UNIT")?,
        comm: optional("_COMM")?,
        code_func: optional("CODE_FUNC")?,
    })
}

/// The caller's lines among `entries` (resolved point 10), sorted by time, newest kept within the bounds.
/// `nm_uuid` must be the canonical lower-case form of the derived UUID; anything else selects nothing. A line counts
/// only from its expected sender (`senders`, the module doc); a forged NetworkManager line neither passes nor moves a
/// session.
///
/// NetworkManager's lines of the UUID and OpenVPN's `linvpn-ovpn-<UUID>` lines are returned as they are. A VPN
/// plugin's line (no connection of its own) is returned only when NetworkManager's VPN state says it can be nobody
/// else's ([`VpnHistory`], built from `history`, NetworkManager's VPN lines since its last start, the
/// NetworkManager lines among `entries` and `observations`, logd's readings of NM's active VPN connections): the
/// caller's connection was active at that moment (between its own activation and its end) and no other VPN
/// connection may have been. Otherwise it is withheld (`W`).
pub fn select(
    entries: &[Entry],
    history: &[Entry],
    observations: &[Observation],
    nm_uuid: &str,
    since_usec: u64,
    senders: &Senders,
) -> Response {
    if canonical_uuid(nm_uuid).is_none() {
        return Response::default();
    }
    let ovpn_ident = format!("{OPENVPN_IDENT_PREFIX}{nm_uuid}");
    let mut sorted: Vec<&Entry> = entries.iter().filter(|e| e.usec >= since_usec).collect();
    sorted.sort_by_key(|e| e.usec);
    let vpn = VpnHistory::new(history.iter().chain(entries.iter()), observations);

    let own_nm = |e: &Entry| e.ident == NM_IDENT && from_nm(e) && nm_owner(e).as_deref() == Some(nm_uuid);
    let mut withheld = false;
    let mut picked: Vec<(&Entry, Source)> = Vec::new();
    for e in sorted {
        let source = if own_nm(e) {
            Source::NetworkManager
        } else if e.ident == ovpn_ident {
            if !from_openvpn(e, senders) {
                continue;
            }
            Source::OpenVpn
        } else if PLUGIN_IDENTS.contains(&e.ident.as_str()) {
            if !from_plugin(e, senders) {
                continue;
            }
            match vpn.at(e.usec, nm_uuid) {
                Attribution::Own => Source::Plugin(e.ident.clone()),
                Attribution::Shared => {
                    withheld = true;
                    continue;
                }
                Attribution::NotOwn => continue,
            }
        } else {
            continue;
        };
        picked.push((e, source));
    }
    // Without a complete history no plugin line passes; say so when the caller has lines here at all.
    if !vpn.complete && picked.iter().any(|(_, s)| *s == Source::NetworkManager) {
        withheld = true;
    }

    // The bounds: the newest MAX_LINES lines, then as many of those as fit MAX_RESPONSE.
    let skip = picked.len().saturating_sub(MAX_LINES);
    let picked = &picked[skip..];
    let tail_room = 4 + MAX_CURSOR + 4 + 2; // "W\n" + "C " + cursor + "\n" + "E\n", generously
    let mut room = MAX_RESPONSE - tail_room;
    let mut keep = 0;
    let lines: Vec<Line> =
        picked.iter().map(|(e, s)| Line { usec: e.usec, source: s.clone(), text: e.message.clone() }).collect();
    for l in lines.iter().rev() {
        let n = line_len(l);
        if n > room {
            break;
        }
        room -= n;
        keep += 1;
    }
    let first = lines.len() - keep;
    let cursor = picked.last().filter(|_| keep > 0).map(|(e, _)| e.cursor.clone());
    Response { lines: lines[first..].to_vec(), withheld, cursor }
}

/// Whose a plugin line at some moment can be ([`VpnHistory::at`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attribution {
    /// The caller's connection was active and no other VPN connection was.
    Own,
    /// The caller's connection was active, but so was another (or the history is incomplete): withheld.
    Shared,
    /// The caller's connection was not active.
    NotOwn,
}

/// One NetworkManager line's meaning for a VPN connection's state, from its own (trusted, `VPN` domain) lines. The
/// order is the order of lines with the same time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Change {
    /// NetworkManager started: no VPN connection is active.
    NmStart,
    /// `starting <plugin>`: the connection is activated.
    Activate,
    /// Any other line of the connection: active when nothing else is known of it (NM's trailing lines after an end
    /// do not bring it back).
    Other,
    /// A line NetworkManager writes only when the connection ends ([`vpn_change`]).
    End,
}

/// One stretch of time in which a VPN connection may have been active: `[start, end)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Session {
    uuid: String,
    start: u64,
    end: Option<u64>,
    /// Opened by the connection's own `starting <plugin>` line (not inferred from another line or a reading).
    activated: bool,
}

/// NetworkManager's VPN connections over time since its last start (`complete` when that start is among the lines:
/// only then is every connection active at a moment known), from its lines and logd's own readings of its active
/// connections ([`Observation`]).
struct VpnHistory {
    complete: bool,
    nm_start: u64,
    sessions: Vec<Session>,
    /// The time of every activation line since the start.
    activations: Vec<u64>,
}

impl VpnHistory {
    fn new<'a>(lines: impl Iterator<Item = &'a Entry>, observations: &[Observation]) -> VpnHistory {
        let mut seen = std::collections::HashSet::new();
        let mut changes: Vec<(u64, Option<String>, Change)> = Vec::new();
        for e in lines {
            if e.ident != NM_IDENT || !from_nm(e) || !seen.insert(e.cursor.as_str()) {
                continue;
            }
            if is_nm_start(e) {
                changes.push((e.usec, None, Change::NmStart));
                continue;
            }
            let vpn_domain = e.nm_domains.as_deref().is_some_and(|d| d.split([',', ' ']).any(|t| t == "VPN"));
            let Some(owner) = nm_owner(e).filter(|_| vpn_domain) else { continue };
            changes.push((e.usec, Some(owner), vpn_change(&e.message)));
        }
        changes.sort_by_key(|(t, _, c)| (*t, *c));
        let Some(start) = changes.iter().rposition(|(_, _, c)| *c == Change::NmStart) else {
            return VpnHistory { complete: false, nm_start: 0, sessions: Vec::new(), activations: Vec::new() };
        };
        let nm_start = changes[start].0;
        let changes = &changes[start + 1..];
        // A reading taken (even partly) before NM's last start says nothing about the connections since.
        let observations: Vec<&Observation> = observations.iter().filter(|o| o.before_usec >= nm_start).collect();
        let mut per: std::collections::BTreeMap<&str, Vec<(u64, Change)>> = std::collections::BTreeMap::new();
        for (t, owner, c) in changes {
            if let Some(owner) = owner {
                per.entry(owner.as_str()).or_default().push((*t, *c));
            }
        }
        for o in &observations {
            for u in &o.active {
                per.entry(u.as_str()).or_default();
            }
        }
        let activations = changes.iter().filter(|(_, _, c)| *c == Change::Activate).map(|(t, _, _)| *t).collect();
        let mut sessions = Vec::new();
        for (uuid, events) in per {
            replay(uuid, &events, &observations, nm_start, &mut sessions);
        }
        VpnHistory { complete: true, nm_start, sessions, activations }
    }

    /// The attribution of a plugin line at `usec` for `nm_uuid`.
    fn at(&self, usec: u64, nm_uuid: &str) -> Attribution {
        if !self.complete {
            return Attribution::Shared;
        }
        // Before the last NM start the caller's own state is not known either.
        if usec < self.nm_start {
            return Attribution::NotOwn;
        }
        let covers = |s: &Session| s.start <= usec && s.end.is_none_or(|e| usec < e);
        // The caller's own session must have started with its own activation line (not just any line of it).
        if !self.sessions.iter().any(|s| s.uuid == nm_uuid && s.activated && covers(s)) {
            return Attribution::NotOwn;
        }
        if self.sessions.iter().any(|s| s.uuid != nm_uuid && covers(s)) {
            Attribution::Shared
        } else {
            Attribution::Own
        }
    }
}

/// One connection's sessions from its NetworkManager lines (`events`, sorted) and logd's readings, appended to `out`.
///
/// - `starting <plugin>` opens a session (`activated`);
/// - an end line ([`vpn_change`]) closes it, unless a later reading still saw the connection with no activation
///   line in between (then the end did not happen: void);
/// - a reading that did not see the connection closes its session at the reading's end, when the session was known
///   to exist before the reading began (its activation line, or the reading that saw it, is older): a connection
///   that is gone stays gone until its next activation line;
/// - a reading that saw a connection with no open session opens one back to the last moment it was known to be
///   inactive (NM's start, an end, a reading without it): its activation line is missing (journald's rate limit);
/// - any other line opens a session only for a connection nothing else is known of.
fn replay(uuid: &str, events: &[(u64, Change)], observations: &[&Observation], nm_start: u64, out: &mut Vec<Session>) {
    let activations: Vec<u64> = events.iter().filter(|(_, c)| *c == Change::Activate).map(|(t, _)| *t).collect();
    let void_end = |at: u64| {
        observations
            .iter()
            .any(|o| o.has(uuid) && o.after_usec >= at && !activations.iter().any(|&a| a > at && a <= o.before_usec))
    };
    // (time, order, step): a line (`Some(change)`) or a reading (`None`, its index), lines first at a tie.
    let mut steps: Vec<(u64, u8, Option<Change>, usize)> = events.iter().map(|(t, c)| (*t, 0, Some(*c), 0)).collect();
    steps.extend(observations.iter().enumerate().map(|(i, o)| (o.after_usec, 1, None, i)));
    steps.sort_by_key(|(t, order, c, i)| (*t, *order, *c, *i));

    let session =
        |start: u64, end: Option<u64>, activated: bool| Session { uuid: uuid.to_string(), start, end, activated };
    // (start, activated, a moment the session is known to have existed)
    let mut open: Option<(u64, bool, u64)> = None;
    let mut known = false;
    let mut inactive_since = nm_start;
    for (t, _, change, i) in steps {
        match change {
            Some(Change::Activate) => {
                if let Some((start, activated, _)) = open.take() {
                    out.push(session(start, Some(t), activated));
                }
                open = Some((t, true, t));
            }
            Some(Change::End) => {
                if !void_end(t) {
                    if let Some((start, activated, _)) = open.take() {
                        out.push(session(start, Some(t), activated));
                    }
                    inactive_since = inactive_since.max(t);
                }
            }
            Some(Change::Other) => {
                if !known {
                    open = Some((t, false, t));
                }
            }
            Some(Change::NmStart) => {}
            None => {
                let o = observations[i];
                if o.has(uuid) {
                    if open.is_none() {
                        open = Some((inactive_since, false, o.after_usec));
                    }
                } else {
                    if let Some((start, activated, existed)) = open
                        && existed < o.before_usec
                    {
                        out.push(session(start, Some(o.after_usec), activated));
                        open = None;
                    }
                    if open.is_none() {
                        inactive_since = inactive_since.max(o.before_usec);
                    }
                }
            }
        }
        known = true;
    }
    if let Some((start, activated, _)) = open {
        out.push(session(start, None, activated));
    }
}

/// NetworkManager's start line (`NetworkManager (version …) is starting...`, logged from `main`).
fn is_nm_start(e: &Entry) -> bool {
    e.code_func.as_deref() == Some("main")
        && !e.nm_domains.as_deref().is_some_and(|d| d.split([',', ' ']).any(|t| t == "VPN"))
        && e.message.contains("NetworkManager (version ")
        && e.message.contains(") is starting")
}

/// The messages NetworkManager 1.54.3 writes for a VPN connection only as it ends (`src/core/vpn/nm-vpn-connection.c`):
/// each is followed by `_set_vpn_state(…, STATE_FAILED, …)` or `nm_vpn_connection_disconnect`, except the plugin's
/// `Failure` signal, after which the plugin stops the connection. All are `_LOGW` (written at NM's default level
/// `INFO`) but the debug-level state lines kept for a raised level. Exact messages.
const END_MESSAGES: [&str; 7] = [
    // _check_complete (no valid IP configuration from the plugin)
    "did not receive valid IP config information",
    // _connect_timeout_cb
    "connect timeout exceeded",
    // _secrets_dbus_need_secrets_cb
    "final secrets request failed to provide sufficient secrets",
    // _start_timeout_cb (then nm_vpn_connection_disconnect)
    "starting: timed out waiting for the service to start",
    "starting: timed out waiting for the VPN to activate",
    // _dbus_signal_state_changed_cb (_LOGD) and NetworkManager before 1.42's form
    "dbus: state changed: stopped (6)",
    "VPN plugin: state changed: stopped (6)",
];

/// End messages whose tail is another process's error text (anything): `(prefix, suffix)`.
const END_QUOTING: [(&str, &str); 4] = [
    // connect_cb, connect_interactive_cb
    ("failed to connect: '", "'"),
    ("connect: failed to connect interactively: '", "'"),
    // _secrets_dbus_new_secrets_cb
    ("sending new secrets to the plugin failed: ", ""),
    // _name_owner_changed (then nm_vpn_connection_disconnect)
    ("starting: failure to start VPN service: ", ""),
];

/// A VPN line's change. NM 1.54 writes `vpn[0x…,<uuid>,"<name>"…]: <message>` ([`vpn_message`]); the message must
/// be a whole known one, so a text NM quotes at its end cannot fake an end or an activation, and a connection's name
/// (its owner's choice) can only make that owner's own lines unreadable.
fn vpn_change(message: &str) -> Change {
    let Some(rest) = vpn_message(message) else { return Change::Other };
    let word = |w: &str| !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    let number = |n: &str| !n.is_empty() && n.len() <= 10 && n.bytes().all(|b| b.is_ascii_digit());
    if rest.strip_prefix("starting ").is_some_and(word) {
        return Change::Activate;
    }
    if END_MESSAGES.contains(&rest)
        || END_QUOTING.iter().any(|(p, s)| rest.strip_prefix(p).is_some_and(|r| r.ends_with(s)))
    {
        return Change::End;
    }
    // _set_vpn_state (_LOGD): `set state: disconnected|failed (was <state>)`
    let state = ["set state: disconnected (was ", "set state: failed (was "]
        .iter()
        .any(|p| rest.strip_prefix(p).and_then(|r| r.strip_suffix(')')).is_some_and(word));
    // _dbus_signal_failure_cb: `dbus: failure: <reason> (<n>)`
    let failure = rest
        .strip_prefix("dbus: failure: ")
        .and_then(|r| r.strip_suffix(')'))
        .and_then(|r| r.split_once(" ("))
        .is_some_and(|(reason, n)| word(reason) && number(n));
    // _secrets_dbus_need_secrets_cb, _secrets_get_secrets_cb: `… #<n> failed: <text>`, `… #<n>: <text>`
    let numbered = [("plugin NeedSecrets request #", " failed: "), ("secrets: failed to request VPN secrets #", ": ")]
        .iter()
        .any(|(p, s)| rest.strip_prefix(p).and_then(|r| r.split_once(s)).is_some_and(|(n, _)| number(n)));
    if state || failure || numbered { Change::End } else { Change::Other }
}

/// The message after NetworkManager 1.54's VPN prefix (`nm-vpn-connection.c`, `__LOG_create_prefix`):
/// `vpn[0x<hex>,<uuid>,"<name>"[,if:<n>][,dev:<n>][:(<iface>)]]: `. NM does not escape the name, so the prefix ends
/// at the first quote after which such a tail follows; `None` without a prefix.
fn vpn_message(message: &str) -> Option<&str> {
    let rest = &message[message.find("vpn[0x")? + 6..];
    let hex = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex == 0 {
        return None;
    }
    let rest = rest[hex..].strip_prefix(',')?;
    let rest = rest[rest.find(',')? + 1..].strip_prefix('"')?;
    let mut from = 0;
    while let Some(q) = rest[from..].find('"') {
        from += q + 1;
        if let Some(m) = prefix_tail(&rest[from..]) {
            return Some(m);
        }
    }
    None
}

/// The message after a VPN prefix's tail (`[,if:<n>][,dev:<n>][:(<iface>)]]: `), or `None`.
fn prefix_tail(s: &str) -> Option<&str> {
    let mut s = s;
    for key in [",if:", ",dev:"] {
        if let Some(r) = s.strip_prefix(key) {
            let n = r.bytes().take_while(u8::is_ascii_digit).count();
            if n == 0 {
                return None;
            }
            s = &r[n..];
        }
    }
    if let Some(r) = s.strip_prefix(":(") {
        let close = r.find(")]: ")?;
        let iface = &r[..close];
        if iface.is_empty() || iface.len() > 15 || iface.contains([')', '/', ':', ' ', '"']) {
            return None;
        }
        s = &r[close + 1..];
    }
    s.strip_prefix("]: ")
}

// ---- logd's readings of NetworkManager's active VPN connections ----

/// `linvpn-logd`'s `SYSLOG_IDENTIFIER` (its program name: the service's stderr goes to the journal).
pub const LOGD_IDENT: &str = "linvpn-logd";
/// The first word of a recorded [`Observation`].
pub const OBSERVATION_MAGIC: &str = "linvpn-logd-vpns-v1";
/// The journal priority of a recorded [`Observation`] (`<5>`, "notice": systemd's `SyslogLevelPrefix=`); logd's
/// other lines are "info", so the query ([`observation_args`]) gets only readings.
pub const OBSERVATION_PRIORITY: u8 = 5;
/// How many recorded readings the query returns at most (`-n`, the newest).
pub const OBSERVATION_ENTRIES: u32 = 2_000;
/// The most active VPN connections one reading may name (more: no reading).
pub const MAX_OBSERVED: usize = 256;

/// One reading of NetworkManager's active VPN connections over the system bus (`ActiveConnections`, each `Vpn`,
/// `Uuid`, `State`), taken between `before_usec` and `after_usec` (the journal's realtime clock, µs): every
/// connection in `active` was active at some moment in that interval, and every connection not in it was not
/// active at some moment in it. `active` is sorted, without duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub before_usec: u64,
    pub after_usec: u64,
    pub active: Vec<String>,
}

impl Observation {
    /// `None` when the times are out of order, there are more than [`MAX_OBSERVED`] connections or one's UUID is
    /// not `[A-Za-z0-9-]{1,64}` (NetworkManager validates its UUIDs; anything else is not trusted as one).
    pub fn new(before_usec: u64, after_usec: u64, active: impl IntoIterator<Item = String>) -> Option<Observation> {
        let mut active: Vec<String> = active.into_iter().collect();
        active.sort();
        active.dedup();
        let ok = before_usec <= after_usec
            && active.len() <= MAX_OBSERVED
            && active
                .iter()
                .all(|u| (1..=64).contains(&u.len()) && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        ok.then_some(Observation { before_usec, after_usec, active })
    }

    fn has(&self, uuid: &str) -> bool {
        self.active.binary_search_by(|u| u.as_str().cmp(uuid)).is_ok()
    }

    /// `linvpn-logd-vpns-v1 <before> <after> <uuid>,<uuid>…` (`-` for none).
    pub fn encode(&self) -> String {
        let list = if self.active.is_empty() { "-".to_string() } else { self.active.join(",") };
        format!("{OBSERVATION_MAGIC} {} {} {list}", self.before_usec, self.after_usec)
    }

    /// The line logd writes to its stderr to record the reading: [`Observation::encode`] with the priority prefix.
    pub fn record_line(&self) -> String {
        format!("<{OBSERVATION_PRIORITY}>{}", self.encode())
    }

    /// Strict: exactly what [`Observation::encode`] writes, or `None`.
    pub fn parse(s: &str) -> Option<Observation> {
        let mut it = s.split(' ');
        let (magic, before, after, list) = (it.next()?, it.next()?, it.next()?, it.next()?);
        if magic != OBSERVATION_MAGIC || it.next().is_some() {
            return None;
        }
        let active: Vec<String> = if list == "-" { Vec::new() } else { list.split(',').map(String::from).collect() };
        let o = Observation::new(parse_dec(before)?, parse_dec(after)?, active)?;
        (o.encode() == s).then_some(o)
    }
}

/// The recorded readings among `entries` (the [`observation_args`] query): only logd's own lines, by the journal's
/// trusted `_SYSTEMD_UNIT` (`linvpn-logd@….service`: only systemd starts processes in it, and only logd and its
/// `journalctl` run there). `_COMM` is not required: journald may name a stream's sender by the forked child's
/// pre-exec name.
pub fn observations(entries: &[Entry]) -> Vec<Observation> {
    entries
        .iter()
        .filter(|e| {
            e.ident == LOGD_IDENT
                && e.unit.as_deref().is_some_and(|u| u.starts_with("linvpn-logd@") && u.ends_with(".service"))
        })
        .filter_map(|e| Observation::parse(&e.message))
        .collect()
}

/// The recorded readings' query (without the program): logd's own notice-priority lines, the newest
/// [`OBSERVATION_ENTRIES`]. Fixed: nothing of the caller's.
pub fn observation_args() -> Vec<String> {
    let mut a: Vec<String> = vec!["--no-pager".into(), "-o".into(), "json".into(), OUTPUT_FIELDS.into()];
    a.extend(["-n".into(), OBSERVATION_ENTRIES.to_string()]);
    a.extend([format!("SYSLOG_IDENTIFIER={LOGD_IDENT}"), format!("PRIORITY={OBSERVATION_PRIORITY}")]);
    a
}

/// Whether logd should record `live` (its reading now) in the journal for later requests: only when it says
/// something the newest recorded reading since NetworkManager's last start (in `recorded`) does not, i.e. there is
/// none, the active set differs, or a connection was activated since that reading began (it may have ended unseen).
/// Never without NM's start in `history` (nothing would be attributed anyway).
pub fn should_record(history: &[Entry], recorded: &[Observation], live: &Observation) -> bool {
    let vpn = VpnHistory::new(history.iter(), &[]);
    if !vpn.complete {
        return false;
    }
    match recorded.iter().filter(|o| o.before_usec >= vpn.nm_start).max_by_key(|o| o.after_usec) {
        None => true,
        Some(o) => o.active != live.active || vpn.activations.iter().any(|&t| t >= o.before_usec),
    }
}

/// The VPN history query's argv (without the program): NetworkManager's `VPN` domain lines and its `main` lines (its
/// start), the newest [`HISTORY_ENTRIES`]. Fixed: nothing of the caller's.
pub fn history_args() -> Vec<String> {
    let mut a: Vec<String> = vec!["--no-pager".into(), "-o".into(), "json".into(), OUTPUT_FIELDS.into()];
    a.extend(["-n".into(), HISTORY_ENTRIES.to_string()]);
    a.extend(["_SYSTEMD_UNIT=NetworkManager.service".into(), "NM_LOG_DOMAINS=VPN".into()]);
    a.extend(["+".into(), "_SYSTEMD_UNIT=NetworkManager.service".into(), "CODE_FUNC=main".into()]);
    a
}

/// `journalctl`'s argv (without the program): fixed options and match groups ORed by `+`; only the validated
/// NM UUID, the time or a valid cursor are interpolated, each inside its own element. With a valid cursor the query
/// starts after it and the time bound is left to [`select`]: journalctl refuses `--since` together with
/// `--after-cursor` ("Please specify only one of --since=, --cursor=, --cursor-file=, and --after-cursor=", systemd
/// 259), which failed every query after a pump's first. An invalid cursor is left out (the time bound holds).
pub fn journalctl_args(nm_uuid: Uuid, since_usec: u64, cursor: Option<&str>) -> Vec<String> {
    let mut a: Vec<String> = vec!["--no-pager".into(), "-o".into(), "json".into(), OUTPUT_FIELDS.into()];
    match cursor.and_then(valid_cursor) {
        Some(c) => a.push(format!("--after-cursor={c}")),
        None => a.push(format!("--since=@{}.{:06}", since_usec / 1_000_000, since_usec % 1_000_000)),
    }
    a.extend(["-n".into(), JOURNAL_ENTRIES.to_string(), "_SYSTEMD_UNIT=NetworkManager.service".into()]);
    a.extend(["+".into(), format!("SYSLOG_IDENTIFIER={OPENVPN_IDENT_PREFIX}{}", nm_uuid.hyphenated())]);
    for p in PLUGIN_IDENTS {
        a.extend(["+".into(), format!("SYSLOG_IDENTIFIER={p}")]);
    }
    a
}

/// Valid UTF-8 with every control character (C0, DEL, C1, U+2028, U+2029) written as `\xNN` (C0, DEL) or
/// `\u{NNNN}`, at most [`MAX_TEXT`] bytes: a longer text is cut on an escape/character boundary and gets `…`.
pub fn escape_text(s: &str) -> String {
    let limit = MAX_TEXT - ELLIPSIS.len_utf8();
    let mut out = String::with_capacity(s.len().min(MAX_TEXT));
    let mut cut_at = None;
    for c in s.chars() {
        let before = out.len();
        let n = c as u32;
        if n < 0x20 || n == 0x7f {
            out.push_str(&format!("\\x{n:02x}"));
        } else if is_control(c) {
            out.push_str(&format!("\\u{{{n:04x}}}"));
        } else {
            out.push(c);
        }
        if out.len() > limit && cut_at.is_none() {
            cut_at = Some(before);
        }
        if out.len() > MAX_TEXT {
            out.truncate(cut_at.unwrap_or(before));
            out.push(ELLIPSIS);
            return out;
        }
    }
    out
}

/// NetworkManager itself wrote it: its unit, as root.
fn from_nm(e: &Entry) -> bool {
    e.unit.as_deref() == Some(NM_UNIT) && e.uid == Some(0)
}

/// OpenVPN wrote it: its process name, as root or `nm-openvpn`.
fn from_openvpn(e: &Entry, senders: &Senders) -> bool {
    e.comm.as_deref() == Some(OPENVPN_COMM) && e.uid.is_some_and(|u| senders.openvpn_uid(u))
}

/// The plugin its ident names wrote it: one of that plugin's process names, as root (or `nm-openvpn` where allowed).
fn from_plugin(e: &Entry, senders: &Senders) -> bool {
    let Some((comms, nm_openvpn)) = plugin_senders(&e.ident) else { return false };
    let Some(uid) = e.uid else { return false };
    let uid_ok = uid == 0 || (nm_openvpn && senders.openvpn_uid(uid));
    uid_ok && e.comm.as_deref().is_some_and(|c| comms.contains(&c))
}

/// The NM connection a NetworkManager line names: the `NM_CONNECTION` field, else (NM without that field) the UUID
/// of a `vpn[0x…,<uuid>,` prefix or of a `(<uuid>)`, in canonical lower-case form only.
fn nm_owner(e: &Entry) -> Option<String> {
    if let Some(c) = &e.nm_connection {
        return Some(c.clone());
    }
    vpn_prefix_uuid(&e.message).or_else(|| paren_uuid(&e.message))
}

/// The UUID of the first `vpn[0x<hex>,<uuid>,` in `msg` (NM may put its `<level> [time]` before it).
fn vpn_prefix_uuid(msg: &str) -> Option<String> {
    let mut rest = msg;
    while let Some(i) = rest.find("vpn[0x") {
        rest = &rest[i + 6..];
        let hex = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
        if hex > 0
            && let Some(after) = rest[hex..].strip_prefix(',')
            && after.as_bytes().get(36) == Some(&b',')
            && let Some(u) = after.get(..36).and_then(canonical_uuid)
        {
            return Some(u.hyphenated().to_string());
        }
    }
    None
}

/// The UUID of the first `(<uuid>)` in `msg`.
fn paren_uuid(msg: &str) -> Option<String> {
    let mut rest = msg;
    while let Some(i) = rest.find('(') {
        rest = &rest[i + 1..];
        if rest.as_bytes().get(36) == Some(&b')')
            && let Some(u) = rest.get(..36).and_then(canonical_uuid)
        {
            return Some(u.hyphenated().to_string());
        }
    }
    None
}

/// A UUID in exactly its canonical lower-case hyphenated form.
fn canonical_uuid(s: &str) -> Option<Uuid> {
    let u = crate::models::parse_uuid(s)?;
    (u.hyphenated().to_string() == s).then_some(u)
}

/// ASCII decimal, no sign, no leading zero (but `0`), fits u64.
fn parse_dec(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

/// `^[A-Za-z0-9=;_-]{1,256}$`
fn valid_cursor(s: &str) -> Option<&str> {
    let ok =
        (1..=MAX_CURSOR).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"=;_-".contains(&b));
    ok.then_some(s)
}

/// `^[a-z0-9_.-]{1,32}$`
fn valid_ident(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

fn is_control(c: char) -> bool {
    let n = c as u32;
    n < 0x20 || (0x7f..=0x9f).contains(&n) || n == 0x2028 || n == 0x2029
}

fn push_line(out: &mut String, l: &Line) {
    out.push_str("L ");
    out.push_str(&l.usec.to_string());
    out.push(' ');
    out.push_str(&l.source.encode());
    out.push(' ');
    out.push_str(&l.text);
    out.push('\n');
}

fn line_len(l: &Line) -> usize {
    let mut s = String::new();
    push_line(&mut s, l);
    s.len()
}
