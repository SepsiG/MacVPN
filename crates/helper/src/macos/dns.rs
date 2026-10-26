//! The helper's DNS manager: the one place that changes the DNS of the macOS network services, for every kind that
//! sets DNS (OpenVPN and SSTP through the `ovpn-dns` hook, WireGuard after `wg-quick up`).
//!
//! `networksetup -setdnsservers` is a **persistent** change (SystemConfiguration preferences, survives a reboot),
//! so what it overwrites is kept in a persistent, root-only **ledger** (`/var/db/macvpn/dns/ledger`, directory 0700,
//! file 0600, never through a symlink; one `flock` serializes every change across processes):
//!
//! - the **original** DNS servers and search domains of each network service, captured only when there is no
//!   ledger yet (the first owner), so the DNS of another VPN connection is never taken for the original;
//! - the **owners**: the connections currently holding DNS, oldest first, each with its own servers and domains.
//!   The newest owner's DNS is in effect; when an owner leaves while others remain, the newest remaining owner's
//!   DNS is applied again; the last owner's leaving restores the originals and removes the ledger.
//!
//! [`Manager::reconcile`] (at every `up`, `down`, `status` and `dns-reconcile`) drops the owners whose engine no
//! longer runs (crash, kill, reboot), so DNS is restored even without a `down`. Every change is read back with
//! `networksetup -get…`, set again once if it did not take, and the result is logged. Services added during a
//! session are not touched; services removed in the meantime are skipped.

use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::log::Log;
use crate::macos::paths::{Settings, is_dir, is_file, is_symlink};
use crate::shared::cli::is_uuid;
use crate::shared::l10n::tr;
use std::path::{Path, PathBuf};

/// The ledger's first line (its format version).
const HEADER: &str = "macvpn-dns-ledger 1";
const LEDGER: &str = "ledger";
const LOCK: &str = "lock";
const LEDGER_MAX: u64 = 256 * 1024;
/// A ledger over [`LEDGER_MAX`] (or otherwise unreadable) is still read up to this size, to recover its originals.
const SALVAGE_MAX: u64 = 4 * 1024 * 1024;
/// At most this many originals and owners are recovered from such a ledger.
const SALVAGE_ENTRIES: usize = 256;
/// At most this many DNS servers per owner (macOS's resolver uses the first 3; a VPN pushes a handful).
pub const MAX_SERVERS: usize = 16;
/// At most this many search domains per owner (the resolver uses at most 6); each at most 253 bytes
/// ([`is_search_domain`]). One owner at the limits renders to about 9 KB, far below [`LEDGER_MAX`].
pub const MAX_DOMAINS: usize = 32;
/// Waiting for the ledger lock: at most 300 × 100 ms.
const LOCK_TRIES: u32 = 300;

/// The two lists `networksetup` keeps per service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    Servers,
    Domains,
}

/// The `networksetup` operations the manager needs (a fake in the tests).
pub trait Net {
    /// The network services (`-listallnetworkservices`); `None` if they cannot be listed.
    fn services(&self) -> Option<Vec<String>>;
    /// The current list (empty = `Empty`); `None` if it cannot be read or holds an unexpected value.
    fn get(&self, list: List, service: &str) -> Option<Vec<String>>;
    /// Sets the list (an empty list is sent as `Empty`).
    fn set(&self, list: List, service: &str, values: &[String]);
}

/// DNS servers and search domains (empty = `Empty`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dns {
    pub servers: Vec<String>,
    pub domains: Vec<String>,
}

impl Dns {
    /// What an owner may set: 1 to [`MAX_SERVERS`] valid servers and at most [`MAX_DOMAINS`] valid search domains
    /// (each at most 253 bytes). A VPN's DNS outside these limits is refused whole, not truncated: a shortened
    /// list would silently differ from what the VPN asked for, and an oversized one is a broken or hostile config.
    pub fn within_limits(&self) -> bool {
        (1..=MAX_SERVERS).contains(&self.servers.len())
            && self.domains.len() <= MAX_DOMAINS
            && self.servers.iter().all(|v| is_valid(List::Servers, v))
            && self.domains.iter().all(|v| is_valid(List::Domains, v))
    }
}

/// The log line of a refused owner (see [`Dns::within_limits`]).
pub fn log_over_limits(dns: &Dns, log: &Log) {
    log.step(&tr(
        "the VPN's DNS settings exceed the limits (%@ servers, %@ search domains; at most %@ and %@): DNS not changed",
        &[
            &dns.servers.len().to_string(),
            &dns.domains.len().to_string(),
            &MAX_SERVERS.to_string(),
            &MAX_DOMAINS.to_string(),
        ],
    ));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Original {
    pub service: String,
    pub dns: Dns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub id: String,
    pub dns: Dns,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    pub originals: Vec<Original>,
    /// Oldest first: the last one's DNS is in effect.
    pub owners: Vec<Owner>,
}

/// A network service name as `networksetup` lists it: no TAB, no line break, no control character.
pub fn is_service(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control)
}

/// A search domain: letters, digits, `.`, `-`, `_`, starting with a letter, digit or `_`, at most 253 bytes.
pub fn is_search_domain(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 253
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

fn is_valid(list: List, v: &str) -> bool {
    match list {
        List::Servers => crate::macos::hook_dns::is_dns(v),
        List::Domains => is_search_domain(v),
    }
}

/// `a b c`, or `Empty`.
fn words(v: &[String]) -> String {
    if v.is_empty() { "Empty".into() } else { v.join(" ") }
}

/// Parses `words` back; `None` if a value is not valid for `list`.
fn parse_words(list: List, s: &str) -> Option<Vec<String>> {
    if s == "Empty" {
        return Some(Vec::new());
    }
    let v: Vec<String> = s.split(' ').filter(|w| !w.is_empty()).map(String::from).collect();
    (!v.is_empty() && v.iter().all(|w| is_valid(list, w))).then_some(v)
}

/// The output of `networksetup -getdnsservers` / `-getsearchdomains`: "There aren't any …" is `Empty`; otherwise
/// every line must be a valid value, else `None` (an error message, something unexpected).
pub fn parse_get(list: List, out: &str) -> Option<Vec<String>> {
    if out.contains("aren't any") {
        return Some(Vec::new());
    }
    let v: Vec<String> = out.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect();
    (!v.is_empty() && v.iter().all(|w| is_valid(list, w))).then_some(v)
}

impl Ledger {
    pub fn render(&self) -> String {
        let mut s = format!("{HEADER}\n");
        for o in &self.originals {
            s.push_str(&format!("orig\t{}\t{}\t{}\n", o.service, words(&o.dns.servers), words(&o.dns.domains)));
        }
        for o in &self.owners {
            s.push_str(&format!("owner\t{}\t{}\t{}\n", o.id, words(&o.dns.servers), words(&o.dns.domains)));
        }
        s
    }

    /// Strict: the header, then only well-formed lines with valid values; anything else is `None`.
    pub fn parse(text: &str) -> Option<Ledger> {
        let mut lines = text.lines();
        if lines.next()? != HEADER {
            return None;
        }
        let mut l = Ledger::default();
        for line in lines {
            if !l.add_line(line, false) {
                return None;
            }
        }
        Some(l)
    }

    /// What can be kept of a ledger [`Ledger::parse`] refuses (too large, a damaged line): after the header, every
    /// well-formed `orig` line, and every well-formed `owner` line within [`Dns::within_limits`], at most
    /// [`SALVAGE_ENTRIES`] of each; the rest is dropped. So the originals of a damaged ledger are still restored.
    /// Without the header nothing is kept.
    pub fn salvage(text: &str) -> Ledger {
        let mut l = Ledger::default();
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return l;
        }
        for line in lines {
            l.add_line(line, true);
        }
        l
    }

    /// One `orig` / `owner` line; `false` (nothing changed) if it is not valid. `salvage`: an owner must also be
    /// within the limits, and at most [`SALVAGE_ENTRIES`] originals / owners are kept.
    fn add_line(&mut self, line: &str, salvage: bool) -> bool {
        let f: Vec<&str> = line.split('\t').collect();
        let [tag, name, servers, domains] = f[..] else { return false };
        let (Some(servers), Some(domains)) = (parse_words(List::Servers, servers), parse_words(List::Domains, domains))
        else {
            return false;
        };
        let dns = Dns { servers, domains };
        match tag {
            "orig"
                if is_service(name)
                    && !(salvage && self.originals.len() >= SALVAGE_ENTRIES)
                    && !self.originals.iter().any(|o| o.service == name) =>
            {
                self.originals.push(Original { service: name.into(), dns })
            }
            "owner"
                if is_uuid(name)
                    && !dns.servers.is_empty()
                    && !(salvage && (self.owners.len() >= SALVAGE_ENTRIES || !dns.within_limits())) =>
            {
                self.owners.retain(|o| o.id != name);
                self.owners.push(Owner { id: name.into(), dns })
            }
            _ => return false,
        }
        true
    }
}

/// The real `networksetup` (always with the minimal environment).
pub struct NetworkSetup {
    pub program: PathBuf,
}

impl NetworkSetup {
    fn cmd(&self, args: &[&str]) -> Cmd {
        Cmd::new(&self.program).args(args)
    }

    fn output(&self, args: &[&str]) -> Option<String> {
        let (ok, out) = crate::macos::exec::capture(&self.cmd(args), EnvMode::Minimal, 1 << 20)?;
        ok.then(|| String::from_utf8_lossy(&out).into_owned())
    }
}

impl Net for NetworkSetup {
    fn services(&self) -> Option<Vec<String>> {
        let out = self.output(&["-listallnetworkservices"])?;
        // The first line is the note "An asterisk (*) denotes that a network service is disabled."
        Some(
            out.lines()
                .skip(1)
                .map(|s| s.strip_prefix('*').unwrap_or(s).to_string())
                .filter(|s| is_service(s))
                .collect(),
        )
    }

    fn get(&self, list: List, service: &str) -> Option<Vec<String>> {
        let flag = match list {
            List::Servers => "-getdnsservers",
            List::Domains => "-getsearchdomains",
        };
        parse_get(list, &self.output(&[flag, service])?)
    }

    fn set(&self, list: List, service: &str, values: &[String]) {
        let flag = match list {
            List::Servers => "-setdnsservers",
            List::Domains => "-setsearchdomains",
        };
        let mut c = Cmd::new(&self.program).arg(flag).arg(service);
        c = if values.is_empty() { c.arg("Empty") } else { c.args(values) };
        let _ = c
            .command(EnvMode::Minimal)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// The manager of this invocation: as root the fixed ledger directory and `/usr/sbin/networksetup`; in test mode
/// only with `MVPN_NETWORKSETUP` (a fake), never the real tool.
pub fn manager(s: &Settings) -> Option<Manager> {
    let program = s.networksetup.clone()?;
    Some(Manager::new(s.dns_base.clone(), Box::new(NetworkSetup { program })))
}

/// An owner is alive while its run directory has a valid kind and its engine is not `failed` (as `status` sees it).
pub fn owner_alive(s: &Settings, id: &str) -> bool {
    let d = s.run_dir(id);
    is_uuid(id)
        && is_dir(&d)
        && !is_symlink(&d)
        && crate::shared::cli::is_kind(&fsx::cat(&d.join("kind")))
        && crate::macos::status::one(s, &d).state != "failed"
}

/// The connection log of `id` for the reconcile's messages (only an existing regular file).
pub fn log_of(s: &Settings, id: &str) -> Log {
    let p = s.log_file(id);
    if is_uuid(id) && is_file(&p) && !is_symlink(&p) { Log::at(p) } else { Log::none() }
}

/// [`Manager::reconcile`] with the run directories as the liveness source.
pub fn reconcile(s: &Settings, wait: bool) {
    if let Some(m) = manager(s) {
        m.reconcile(&|id| owner_alive(s, id), &|id| log_of(s, id), wait);
    }
}

/// The DNS manager over a ledger directory and a [`Net`].
pub struct Manager {
    pub dir: PathBuf,
    pub net: Box<dyn Net>,
}

/// The ledger lock, released when dropped (the descriptor closes).
struct Guard(#[allow(dead_code)] std::fs::File);

impl Manager {
    pub fn new(dir: PathBuf, net: Box<dyn Net>) -> Manager {
        Manager { dir, net }
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.dir.join(LEDGER)
    }

    /// A new owner `id` with `dns` (a reconnect of `id` replaces its entry and makes it the newest).
    pub fn acquire(&self, id: &str, dns: &Dns, log: &Log) {
        if !dns.within_limits() {
            log_over_limits(dns, log);
            return;
        }
        let Some(_g) = self.lock(true) else {
            log.step(&tr("the DNS ledger cannot be used, DNS not changed", &[]));
            return;
        };
        let mut l = self.load(log);
        let Some(services) = self.net.services() else {
            log.step(&tr("cannot list the network services, DNS not changed", &[]));
            return;
        };
        if l.originals.is_empty() {
            // The first owner: what is set now is the original (no other MacVPN connection holds DNS).
            for svc in &services {
                match (self.net.get(List::Servers, svc), self.net.get(List::Domains, svc)) {
                    (Some(servers), Some(domains)) => {
                        l.originals.push(Original { service: svc.clone(), dns: Dns { servers, domains } })
                    }
                    _ => log.step(&tr("cannot read the DNS settings of %@, the service is left unchanged", &[svc])),
                }
            }
        }
        l.owners.retain(|o| o.id != id);
        l.owners.push(Owner { id: id.into(), dns: dns.clone() });
        // Persisted before anything changes: a crash from here on still finds the originals.
        if !self.save(&l) {
            log.step(&tr("the DNS ledger cannot be used, DNS not changed", &[]));
            return;
        }
        self.apply(&owner_targets(&l, &services), false, log);
    }

    /// `id` leaves; `true` if it was an owner.
    pub fn release(&self, id: &str, log: &Log) -> bool {
        if !crate::macos::paths::exists(&self.ledger_path()) {
            return false;
        }
        let Some(_g) = self.lock(true) else {
            log.step(&tr("the DNS ledger cannot be used, DNS not changed", &[]));
            return false;
        };
        let mut l = self.load(log);
        let Some(pos) = l.owners.iter().position(|o| o.id == id) else { return false };
        let newest = pos + 1 == l.owners.len();
        l.owners.remove(pos);
        self.settle(l, newest, log);
        true
    }

    /// Drops the owners for which `alive` is false; restores or re-applies as [`Manager::release`] does. Without a
    /// ledger nothing is created or locked. `wait`: wait for the lock (otherwise skip if it is busy).
    pub fn reconcile(&self, alive: &dyn Fn(&str) -> bool, log_for: &dyn Fn(&str) -> Log, wait: bool) {
        if !crate::macos::paths::exists(&self.ledger_path()) {
            return;
        }
        let Some(_g) = self.lock(wait) else { return };
        let mut l = self.load(&Log::none());
        let dead: Vec<String> = l.owners.iter().filter(|o| !alive(&o.id)).map(|o| o.id.clone()).collect();
        let pending = l.owners.is_empty() && !l.originals.is_empty();
        if dead.is_empty() && !pending {
            return;
        }
        for id in &dead {
            log_for(id).step(&tr("the connection is no longer running: its DNS settings are released", &[]));
        }
        let newest_before = l.owners.last().map(|o| o.id.clone());
        l.owners.retain(|o| !dead.contains(&o.id));
        let changed = l.owners.last().map(|o| o.id.clone()) != newest_before;
        let log = dead.last().map(|id| log_for(id)).unwrap_or_default();
        self.settle(l, changed, &log);
    }

    /// The `dns-backup` of a root layer before the ledger (`service<TAB>servers<TAB>domains` lines): restored
    /// (verified) and deleted.
    pub fn restore_legacy(&self, backup: &Path, log: &Log) {
        let data = fsx::read_private(backup, LEDGER_MAX).unwrap_or_default();
        let services = self.net.services().unwrap_or_default();
        let mut targets = Vec::new();
        for line in String::from_utf8_lossy(&data).lines() {
            let Some((svc, servers, domains)) = crate::macos::hook_dns::parse_backup_line(line) else { continue };
            let servers = parse_words(List::Servers, &servers.join(" "));
            let domains =
                if domains.is_empty() { Some(Vec::new()) } else { parse_words(List::Domains, &domains.join(" ")) };
            if let (Some(servers), Some(domains)) = (servers, domains)
                && services.contains(&svc)
            {
                targets.push((svc, Dns { servers, domains }));
            }
        }
        // Restored even without the lock: this connection's backup is not shared with any other.
        let _g = self.lock(true);
        self.apply(&targets, true, log);
        fsx::remove_file(backup);
    }

    /// After an owner left: the originals back when none is left (the ledger removed), the newest remaining
    /// owner's DNS again when the one in effect left.
    fn settle(&self, l: Ledger, newest_changed: bool, log: &Log) {
        if l.owners.is_empty() {
            let Some(services) = self.net.services() else {
                // Kept without owners: the next reconcile restores.
                log.step(&tr("cannot list the network services; the DNS restore is retried later", &[]));
                self.save(&l);
                return;
            };
            let targets: Vec<(String, Dns)> = l
                .originals
                .iter()
                .filter(|o| services.contains(&o.service))
                .map(|o| (o.service.clone(), o.dns.clone()))
                .collect();
            self.apply(&targets, true, log);
            self.save(&Ledger::default());
            return;
        }
        self.save(&l);
        if !newest_changed {
            log.step(&tr(
                "another MacVPN connection still holds DNS; the original DNS comes back when the last one disconnects",
                &[],
            ));
            return;
        }
        log.step(&tr("another MacVPN connection still holds DNS: the newest one's DNS settings are applied", &[]));
        if let Some(services) = self.net.services() {
            self.apply(&owner_targets(&l, &services), false, log);
        }
    }

    /// Sets every target, reads them back, sets the ones that did not take once more, and logs the result.
    fn apply(&self, targets: &[(String, Dns)], restore: bool, log: &Log) {
        if targets.is_empty() {
            return;
        }
        for (svc, d) in targets {
            self.set(svc, d, log);
        }
        let mut bad = self.mismatched(targets);
        if !bad.is_empty() {
            for (svc, d, _) in &bad {
                self.set(svc, d, log);
            }
            let again: Vec<(String, Dns)> = bad.iter().map(|(s, d, _)| (s.clone(), d.clone())).collect();
            bad = self.mismatched(&again);
        }
        for (svc, want, found) in &bad {
            let found = found.as_ref().map(show).unwrap_or_else(|| "?".into());
            log.step(&tr("DNS check failed on %@ after a retry: expected %@, found %@", &[svc, &show(want), &found]));
        }
        if bad.is_empty() {
            let n = targets.len().to_string();
            log.step(&tr(
                if restore {
                    "original DNS restored and verified on %@ network service(s)"
                } else {
                    "DNS set and verified on %@ network service(s)"
                },
                &[&n],
            ));
        }
    }

    fn set(&self, svc: &str, d: &Dns, log: &Log) {
        log.cmd(&format!("networksetup -setdnsservers \"{svc}\" {}", words(&d.servers)));
        self.net.set(List::Servers, svc, &d.servers);
        log.cmd(&format!("networksetup -setsearchdomains \"{svc}\" {}", words(&d.domains)));
        self.net.set(List::Domains, svc, &d.domains);
    }

    /// The targets whose read-back differs, with what was found (`None`: unreadable).
    fn mismatched(&self, targets: &[(String, Dns)]) -> Vec<(String, Dns, Option<Dns>)> {
        let mut bad = Vec::new();
        for (svc, want) in targets {
            let found = match (self.net.get(List::Servers, svc), self.net.get(List::Domains, svc)) {
                (Some(servers), Some(domains)) => Some(Dns { servers, domains }),
                _ => None,
            };
            if !found.as_ref().is_some_and(|f| same(want, f)) {
                bad.push((svc.clone(), want.clone(), found));
            }
        }
        bad
    }

    /// The ledger directory (0700, ours, not a symlink; its parent is created 0700 if missing) and the lock.
    fn lock(&self, wait: bool) -> Option<Guard> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        let mkdir = |p: &Path| {
            if std::fs::symlink_metadata(p).is_err() {
                let _ = std::fs::DirBuilder::new().mode(0o700).create(p);
            }
        };
        if let Some(parent) = self.dir.parent() {
            mkdir(parent);
            if !std::fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_dir()) {
                return None;
            }
        }
        mkdir(&self.dir);
        let m = std::fs::symlink_metadata(&self.dir).ok()?;
        if !m.file_type().is_dir() || m.uid() != crate::macos::sys::geteuid() {
            return None;
        }
        if m.mode() & 0o777 != 0o700 {
            fsx::chmod(&self.dir, 0o700).ok()?;
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.dir.join(LOCK))
            .ok()?;
        for _ in 0..LOCK_TRIES {
            if crate::macos::sys::try_lock_exclusive(&f) {
                return Some(Guard(f));
            }
            if !wait {
                return None;
            }
            crate::macos::exec::sleep_ms(100, false);
        }
        None
    }

    /// The ledger (absent: empty). An unreadable or malformed one is set aside as `ledger.bad` (logged); what can
    /// be recovered of it ([`Ledger::salvage`]: the originals and the valid owners) is written back and used, so
    /// the original DNS is never lost to a damaged or oversized ledger.
    fn load(&self, log: &Log) -> Ledger {
        let p = self.ledger_path();
        if std::fs::symlink_metadata(&p).is_err() {
            return Ledger::default();
        }
        let text = fsx::read_private(&p, SALVAGE_MAX).map(|d| String::from_utf8_lossy(&d).into_owned());
        if let Some(l) = text.as_deref().filter(|t| t.len() as u64 <= LEDGER_MAX).and_then(Ledger::parse) {
            return l;
        }
        log.step(&tr("the DNS ledger was unreadable and has been set aside", &[]));
        let bad = self.dir.join("ledger.bad");
        fsx::remove_rf(&bad);
        if std::fs::rename(&p, &bad).is_err() {
            fsx::remove_rf(&p);
        }
        let l = text.as_deref().map(Ledger::salvage).unwrap_or_default();
        if !l.originals.is_empty() {
            log.step(&tr("the original DNS settings were recovered from it", &[]));
            self.save(&l);
        }
        l
    }

    /// Writes the ledger atomically (a temporary file renamed over it); an empty ledger is removed. A ledger that
    /// [`Manager::load`] could not read back exactly (over [`LEDGER_MAX`], or not parsing to the same value) is
    /// never written: `false`, and the ledger on disk stays as it was.
    fn save(&self, l: &Ledger) -> bool {
        let p = self.ledger_path();
        if l.originals.is_empty() && l.owners.is_empty() {
            fsx::remove_file(&p);
            return true;
        }
        let text = l.render();
        if text.len() as u64 > LEDGER_MAX || Ledger::parse(&text).as_ref() != Some(l) {
            return false;
        }
        let tmp = self.dir.join("ledger.tmp");
        fsx::remove_rf(&tmp);
        fsx::create_new(&tmp, text.as_bytes(), 0o600).is_ok() && std::fs::rename(&tmp, &p).is_ok()
    }
}

/// The newest owner's DNS for every original service that still exists; without its own search domains the
/// service's original ones are kept.
fn owner_targets(l: &Ledger, services: &[String]) -> Vec<(String, Dns)> {
    let Some(owner) = l.owners.last() else { return Vec::new() };
    l.originals
        .iter()
        .filter(|o| services.contains(&o.service))
        .map(|o| {
            let domains = if owner.dns.domains.is_empty() { o.dns.domains.clone() } else { owner.dns.domains.clone() };
            (o.service.clone(), Dns { servers: owner.dns.servers.clone(), domains })
        })
        .collect()
}

/// `servers / domains` for the log.
fn show(d: &Dns) -> String {
    format!("{} / {}", words(&d.servers), words(&d.domains))
}

/// Equal up to the address notation and the case / final dot of the domains.
fn same(a: &Dns, b: &Dns) -> bool {
    let ip = |v: &[String]| -> Vec<String> {
        v.iter().map(|s| s.parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| s.clone())).collect()
    };
    let dom =
        |v: &[String]| -> Vec<String> { v.iter().map(|s| s.trim_end_matches('.').to_ascii_lowercase()).collect() };
    ip(&a.servers) == ip(&b.servers) && dom(&a.domains) == dom(&b.domains)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    #[derive(Default)]
    pub struct Inner {
        pub services: RefCell<Vec<String>>,
        pub state: RefCell<BTreeMap<String, Dns>>,
        /// The next this many `set` calls are dropped (a change that did not take).
        pub drop_sets: Cell<u32>,
        pub sets: RefCell<Vec<String>>,
    }

    #[derive(Clone, Default)]
    pub struct FakeNet(pub Rc<Inner>);

    impl FakeNet {
        pub fn with(services: &[(&str, &[&str], &[&str])]) -> FakeNet {
            let f = FakeNet::default();
            for (s, servers, domains) in services {
                f.add(s, servers, domains);
            }
            f
        }

        pub fn add(&self, s: &str, servers: &[&str], domains: &[&str]) {
            self.0.services.borrow_mut().push(s.into());
            self.0.state.borrow_mut().insert(s.into(), dns(servers, domains));
        }

        pub fn remove(&self, s: &str) {
            self.0.services.borrow_mut().retain(|x| x != s);
            self.0.state.borrow_mut().remove(s);
        }

        pub fn of(&self, s: &str) -> Dns {
            self.0.state.borrow()[s].clone()
        }
    }

    impl Net for FakeNet {
        fn services(&self) -> Option<Vec<String>> {
            Some(self.0.services.borrow().clone())
        }
        fn get(&self, list: List, service: &str) -> Option<Vec<String>> {
            let st = self.0.state.borrow();
            let d = st.get(service)?;
            Some(if list == List::Servers { d.servers.clone() } else { d.domains.clone() })
        }
        fn set(&self, list: List, service: &str, values: &[String]) {
            self.0.sets.borrow_mut().push(format!("{list:?} {service} {}", words(values)));
            if self.0.drop_sets.get() > 0 {
                self.0.drop_sets.set(self.0.drop_sets.get() - 1);
                return;
            }
            let mut st = self.0.state.borrow_mut();
            let Some(d) = st.get_mut(service) else { return };
            if list == List::Servers {
                d.servers = values.to_vec();
            } else {
                d.domains = values.to_vec();
            }
        }
    }

    pub fn dns(servers: &[&str], domains: &[&str]) -> Dns {
        Dns {
            servers: servers.iter().map(|s| s.to_string()).collect(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
        }
    }

    const A: &str = "0A1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    const B: &str = "0B1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    const C: &str = "0C1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

    struct T {
        base: PathBuf,
        net: FakeNet,
        m: Manager,
        log: Log,
    }

    impl T {
        fn new() -> T {
            let net = FakeNet::with(&[("Wi-Fi", &[], &[]), ("Ethernet", &["192.168.1.1"], &["lan.example.com"])]);
            let base = std::env::temp_dir().join(format!("mvpn-dns-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&base).unwrap();
            let m = Manager::new(base.join("db/dns"), Box::new(net.clone()));
            let log = Log::at(base.join("conn.log"));
            T { base, net, m, log }
        }

        /// A new process (after a reboot): the same ledger directory and network state.
        fn restart(&self) -> Manager {
            Manager::new(self.m.dir.clone(), Box::new(self.net.clone()))
        }

        fn log_text(&self) -> String {
            std::fs::read_to_string(self.base.join("conn.log")).unwrap_or_default()
        }

        fn originals_back(&self) {
            assert_eq!(self.net.of("Wi-Fi"), dns(&[], &[]));
            assert_eq!(self.net.of("Ethernet"), dns(&["192.168.1.1"], &["lan.example.com"]));
        }
    }

    impl Drop for T {
        fn drop(&mut self) {
            fsx::remove_rf(&self.base);
        }
    }

    fn vpn_a() -> Dns {
        dns(&["10.8.0.1"], &["corp.example"])
    }

    fn vpn_b() -> Dns {
        dns(&["10.9.0.1", "fd00::53"], &["b.corp.example"])
    }

    #[test]
    fn first_owner_captures_the_originals_and_the_last_restores_them() {
        use std::os::unix::fs::PermissionsExt;
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        assert_eq!(t.net.of("Wi-Fi"), vpn_a());
        assert_eq!(t.net.of("Ethernet"), vpn_a());
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&t.m.dir), 0o700);
        assert_eq!(mode(&t.m.ledger_path()), 0o600);
        let l = Ledger::parse(&std::fs::read_to_string(t.m.ledger_path()).unwrap()).unwrap();
        assert_eq!(l.originals.len(), 2);
        assert_eq!(l.owners, vec![Owner { id: A.into(), dns: vpn_a() }]);
        assert!(t.m.release(A, &t.log));
        t.originals_back();
        assert!(!t.m.ledger_path().exists(), "the ledger is removed with the last owner");
        let log = t.log_text();
        assert!(log.contains("$ networksetup -setdnsservers \"Wi-Fi\" 10.8.0.1"), "{log}");
        assert!(log.contains("$ networksetup -setdnsservers \"Ethernet\" 192.168.1.1"), "{log}");
        assert!(log.contains("DNS set and verified on 2 network service(s)"), "{log}");
        assert!(log.contains("original DNS restored and verified on 2 network service(s)"), "{log}");
        assert!(!t.m.release(A, &t.log), "not an owner any more");
    }

    #[test]
    fn an_owner_without_domains_keeps_the_original_search_domains() {
        let t = T::new();
        t.m.acquire(A, &dns(&["10.8.0.1"], &[]), &t.log);
        assert_eq!(t.net.of("Ethernet"), dns(&["10.8.0.1"], &["lan.example.com"]));
        assert_eq!(t.net.of("Wi-Fi"), dns(&["10.8.0.1"], &[]));
    }

    #[test]
    fn stacking_a_then_b_up_a_down_keeps_b_then_b_down_restores() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.m.acquire(B, &vpn_b(), &t.log);
        assert_eq!(t.net.of("Wi-Fi"), vpn_b(), "the newest owner wins");
        assert!(t.m.release(A, &t.log));
        assert_eq!(t.net.of("Wi-Fi"), vpn_b(), "B's DNS stays");
        assert_eq!(t.net.of("Ethernet"), vpn_b());
        assert!(t.m.release(B, &t.log));
        t.originals_back();
        assert!(!t.m.ledger_path().exists());
    }

    #[test]
    fn stacking_b_down_first_applies_a_again() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.m.acquire(B, &vpn_b(), &t.log);
        assert!(t.m.release(B, &t.log));
        assert_eq!(t.net.of("Wi-Fi"), vpn_a(), "the newest remaining owner's DNS");
        assert!(t.m.release(A, &t.log));
        t.originals_back();
    }

    #[test]
    fn a_reconnect_does_not_capture_the_vpn_dns_as_original() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.m.acquire(A, &vpn_a(), &t.log);
        let l = Ledger::parse(&std::fs::read_to_string(t.m.ledger_path()).unwrap()).unwrap();
        assert_eq!(l.owners.len(), 1);
        assert!(t.m.release(A, &t.log));
        t.originals_back();
    }

    #[test]
    fn crash_reconcile_restores_when_the_owner_is_dead() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.m.reconcile(&|_| true, &|_| t.log.clone(), true);
        assert_eq!(t.net.of("Wi-Fi"), vpn_a(), "a live owner keeps its DNS");
        t.m.reconcile(&|_| false, &|_| t.log.clone(), true);
        t.originals_back();
        assert!(!t.m.ledger_path().exists());
        assert!(t.log_text().contains("the connection is no longer running: its DNS settings are released"));
    }

    #[test]
    fn crash_reconcile_with_a_live_owner_left_applies_its_dns() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.m.acquire(B, &vpn_b(), &t.log);
        t.m.reconcile(&|id| id == A, &|_| t.log.clone(), true);
        assert_eq!(t.net.of("Wi-Fi"), vpn_a());
        let l = Ledger::parse(&std::fs::read_to_string(t.m.ledger_path()).unwrap()).unwrap();
        assert_eq!(l.owners.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), vec![A]);
    }

    #[test]
    fn reboot_ledger_without_run_dir_restores_and_the_next_up_captures_the_true_originals() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        // Reboot: the run directory is gone (no owner is alive), the persistent DNS change and the ledger stay.
        let m = t.restart();
        m.reconcile(&|_| false, &|_| Log::none(), true);
        t.originals_back();
        m.acquire(C, &vpn_b(), &t.log);
        assert!(m.release(C, &t.log));
        t.originals_back();
    }

    #[test]
    fn without_reconcile_a_new_owner_after_reboot_still_keeps_the_true_originals() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        let m = t.restart();
        m.acquire(C, &vpn_b(), &t.log);
        let l = Ledger::parse(&std::fs::read_to_string(m.ledger_path()).unwrap()).unwrap();
        assert_eq!(l.originals.iter().find(|o| o.service == "Wi-Fi").unwrap().dns, dns(&[], &[]));
        m.reconcile(&|id| id == C, &|_| Log::none(), true);
        assert!(m.release(C, &t.log));
        t.originals_back();
    }

    #[test]
    fn reconcile_without_a_ledger_creates_nothing() {
        let t = T::new();
        t.m.reconcile(&|_| false, &|_| Log::none(), false);
        assert!(!t.m.dir.exists());
        assert!(t.net.0.sets.borrow().is_empty());
    }

    #[test]
    fn a_change_that_did_not_take_is_retried_once_and_verified() {
        let t = T::new();
        t.net.0.drop_sets.set(1);
        t.m.acquire(A, &vpn_a(), &t.log);
        assert_eq!(t.net.of("Wi-Fi"), vpn_a());
        assert!(t.log_text().contains("DNS set and verified on 2 network service(s)"));
        t.net.0.drop_sets.set(1);
        assert!(t.m.release(A, &t.log));
        t.originals_back();
        assert!(t.log_text().contains("original DNS restored and verified on 2 network service(s)"));
    }

    #[test]
    fn a_restore_that_never_takes_is_logged() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.net.0.drop_sets.set(100);
        assert!(t.m.release(A, &t.log));
        let log = t.log_text();
        assert!(
            log.contains(
                "DNS check failed on Wi-Fi after a retry: expected Empty / Empty, found 10.8.0.1 / corp.example"
            ),
            "{log}"
        );
        assert!(!log.contains("original DNS restored and verified"), "{log}");
    }

    #[test]
    fn removed_services_are_skipped_and_added_ones_untouched() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        t.net.remove("Ethernet");
        t.net.add("USB LAN", &["192.168.2.1"], &[]);
        t.m.acquire(B, &vpn_b(), &t.log);
        assert_eq!(t.net.of("USB LAN"), dns(&["192.168.2.1"], &[]));
        t.net.0.sets.borrow_mut().clear();
        assert!(t.m.release(B, &t.log));
        assert!(t.m.release(A, &t.log));
        assert_eq!(t.net.of("Wi-Fi"), dns(&[], &[]));
        assert_eq!(t.net.of("USB LAN"), dns(&["192.168.2.1"], &[]));
        assert!(t.net.0.sets.borrow().iter().all(|s| s.contains("Wi-Fi")), "{:?}", t.net.0.sets.borrow());
    }

    #[test]
    fn an_unreadable_service_is_left_alone() {
        let t = T::new();
        t.net.0.services.borrow_mut().push("Ghost".into());
        t.m.acquire(A, &vpn_a(), &t.log);
        assert!(t.net.0.sets.borrow().iter().all(|s| !s.contains("Ghost")));
        assert!(t.log_text().contains("cannot read the DNS settings of Ghost, the service is left unchanged"));
    }

    #[test]
    fn a_symlinked_ledger_directory_is_refused() {
        let t = T::new();
        std::fs::create_dir_all(t.base.join("db")).unwrap();
        std::fs::create_dir(t.base.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(t.base.join("elsewhere"), &t.m.dir).unwrap();
        t.m.acquire(A, &vpn_a(), &t.log);
        assert_eq!(t.net.of("Wi-Fi"), dns(&[], &[]), "no change without a safe ledger");
        assert!(!t.base.join("elsewhere/ledger").exists());
        assert!(t.log_text().contains("the DNS ledger cannot be used, DNS not changed"));
    }

    #[test]
    fn a_corrupt_ledger_is_set_aside() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        std::fs::write(t.m.ledger_path(), "garbage\n").unwrap();
        t.m.reconcile(&|_| false, &|_| t.log.clone(), true);
        assert!(!t.m.ledger_path().exists());
        assert!(t.m.dir.join("ledger.bad").exists());
    }

    #[test]
    fn legacy_backup_is_restored_and_deleted() {
        let t = T::new();
        t.net.0.state.borrow_mut().insert("Wi-Fi".into(), vpn_a());
        let b = t.base.join("dns-backup");
        std::fs::write(&b, "Wi-Fi\tEmpty\tEmpty\nEthernet\t192.168.1.1\tlan.example.com\nGone\tEmpty\tEmpty\n")
            .unwrap();
        t.m.restore_legacy(&b, &t.log);
        t.originals_back();
        assert!(!b.exists());
    }

    #[test]
    fn ledger_format_is_strict() {
        let l = Ledger {
            originals: vec![Original { service: "Wi-Fi 2".into(), dns: dns(&[], &["lan.example.com"]) }],
            owners: vec![Owner { id: A.into(), dns: vpn_b() }],
        };
        assert_eq!(Ledger::parse(&l.render()), Some(l.clone()));
        let text = l.render();
        assert!(Ledger::parse(&text.replace(HEADER, "x")).is_none());
        assert!(Ledger::parse(&text.replace("10.9.0.1", "10.9.0.1;x")).is_none());
        assert!(Ledger::parse(&text.replace(A, "not-a-uuid")).is_none());
        assert!(Ledger::parse(&format!("{text}extra\tline\n")).is_none());
        assert!(Ledger::parse(&format!("{text}owner\t{B}\tEmpty\tEmpty\n")).is_none(), "an owner sets servers");
    }

    /// `n` servers (`10.0.x.y`) and `m` search domains of `len` bytes each.
    fn big(n: usize, m: usize, len: usize) -> Dns {
        Dns {
            servers: (0..n).map(|i| format!("10.0.{}.{}", i / 250, i % 250 + 1)).collect(),
            domains: (0..m).map(|i| format!("d{i:03}{}", "x".repeat(len - 4))).collect(),
        }
    }

    fn ledger_on_disk(m: &Manager) -> Ledger {
        Ledger::parse(&std::fs::read_to_string(m.ledger_path()).unwrap()).unwrap()
    }

    #[test]
    fn owner_lists_are_capped() {
        assert!(big(MAX_SERVERS, MAX_DOMAINS, 253).within_limits());
        assert!(!big(MAX_SERVERS + 1, 1, 10).within_limits());
        assert!(!big(1, MAX_DOMAINS + 1, 10).within_limits());
        assert!(!big(1, 1, 254).within_limits(), "a domain over 253 bytes");
        assert!(!dns(&["10.0.0.1;x"], &[]).within_limits(), "an invalid server");
        assert!(!dns(&["10.0.0.1"], &["-x"]).within_limits(), "an invalid domain");
        assert!(!dns(&[], &["corp.example"]).within_limits(), "an owner sets servers");
        let longest = big(MAX_SERVERS, MAX_DOMAINS, 253);
        let l = Ledger { originals: vec![], owners: vec![Owner { id: A.into(), dns: longest }] };
        assert!(l.render().len() < 16 * 1024, "one owner is far below LEDGER_MAX");
    }

    #[test]
    fn an_oversized_owner_is_refused_and_the_originals_stay() {
        let t = T::new();
        // M-2: about 1040 domains of 253 bytes would have made a ledger over LEDGER_MAX.
        t.m.acquire(A, &big(1, 1040, 253), &t.log);
        t.originals_back();
        assert!(!t.m.ledger_path().exists(), "nothing recorded for a refused owner");
        assert!(t.net.0.sets.borrow().is_empty());
        assert!(t.log_text().contains("the VPN's DNS settings exceed the limits"), "{}", t.log_text());
        t.m.acquire(A, &big(MAX_SERVERS + 1, 0, 1), &t.log);
        t.originals_back();
        assert!(!t.m.release(A, &t.log));
        t.originals_back();
    }

    #[test]
    fn an_oversized_owner_next_to_another_changes_nothing() {
        let t = T::new();
        t.m.acquire(B, &vpn_b(), &t.log);
        let before = std::fs::read(t.m.ledger_path()).unwrap();
        t.m.acquire(A, &big(1, MAX_DOMAINS + 1, 20), &t.log);
        assert_eq!(t.net.of("Wi-Fi"), vpn_b());
        assert_eq!(std::fs::read(t.m.ledger_path()).unwrap(), before, "the ledger is untouched");
        assert!(!t.m.release(A, &t.log));
        assert!(t.m.release(B, &t.log));
        t.originals_back();
    }

    #[test]
    fn the_largest_owner_still_round_trips() {
        let t = T::new();
        let d = big(MAX_SERVERS, MAX_DOMAINS, 253);
        t.m.acquire(A, &d, &t.log);
        assert_eq!(t.net.of("Wi-Fi"), d);
        assert_eq!(ledger_on_disk(&t.m).owners, vec![Owner { id: A.into(), dns: d }]);
        assert!(t.m.release(A, &t.log));
        t.originals_back();
    }

    #[test]
    fn a_ledger_that_would_not_read_back_is_never_written() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        let before = std::fs::read(t.m.ledger_path()).unwrap();
        // "Empty" is a valid search domain but is the ledger's word for an empty list: it would not read back.
        t.m.acquire(B, &dns(&["10.9.0.1"], &["Empty"]), &t.log);
        assert_eq!(std::fs::read(t.m.ledger_path()).unwrap(), before);
        assert_eq!(t.net.of("Wi-Fi"), vpn_a(), "DNS not changed");
        assert!(t.log_text().contains("the DNS ledger cannot be used, DNS not changed"));
        assert!(t.m.release(A, &t.log));
        t.originals_back();
    }

    #[test]
    fn many_owners_never_push_the_ledger_over_its_limit() {
        let t = T::new();
        let d = big(MAX_SERVERS, MAX_DOMAINS, 253);
        let ids: Vec<String> = (0..40).map(|i| format!("{i:08X}-4B5A-6978-8796-A5B4C3D2E1F0")).collect();
        for id in &ids {
            t.m.acquire(id, &d, &t.log);
            let size = std::fs::metadata(t.m.ledger_path()).unwrap().len();
            assert!(size <= LEDGER_MAX, "{size}");
            assert!(ledger_on_disk(&t.m).originals.len() == 2, "the originals are always in the ledger");
        }
        let held = ledger_on_disk(&t.m).owners.len();
        assert!(held < ids.len(), "the owners past the limit were refused");
        assert!(t.log_text().contains("the DNS ledger cannot be used, DNS not changed"));
        for id in &ids {
            t.m.release(id, &t.log);
        }
        t.originals_back();
        assert!(!t.m.ledger_path().exists());
    }

    #[test]
    fn an_oversized_ledger_keeps_its_originals() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        // A ledger over LEDGER_MAX (an older root layer, a damaged file): its originals are recovered, the
        // oversized owner dropped, so the restore still happens.
        let huge = Owner { id: B.into(), dns: big(1, 1100, 253) };
        let mut text = std::fs::read_to_string(t.m.ledger_path()).unwrap();
        text.push_str(&Ledger { originals: vec![], owners: vec![huge] }.render().replacen(
            &format!("{HEADER}\n"),
            "",
            1,
        ));
        text.push_str("garbage line\n");
        assert!(text.len() as u64 > LEDGER_MAX);
        std::fs::write(t.m.ledger_path(), &text).unwrap();
        t.m.reconcile(&|_| false, &|_| t.log.clone(), true);
        t.originals_back();
        assert!(t.m.dir.join("ledger.bad").exists(), "the unreadable ledger is kept for inspection");
        assert!(!t.m.ledger_path().exists());
    }

    #[test]
    fn a_damaged_ledger_keeps_its_originals_and_valid_owners() {
        let t = T::new();
        t.m.acquire(A, &vpn_a(), &t.log);
        let mut text = std::fs::read_to_string(t.m.ledger_path()).unwrap();
        text.push_str("owner\tnot-a-uuid\t10.0.0.1\tEmpty\n");
        std::fs::write(t.m.ledger_path(), &text).unwrap();
        t.m.acquire(B, &vpn_b(), &t.log);
        assert!(t.log_text().contains("the original DNS settings were recovered from it"), "{}", t.log_text());
        assert_eq!(t.net.of("Wi-Fi"), vpn_b());
        let l = ledger_on_disk(&t.m);
        assert_eq!(l.originals.len(), 2, "the originals were not captured again from the VPN's DNS");
        assert_eq!(l.owners.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), vec![A, B]);
        assert!(t.m.release(B, &t.log));
        assert_eq!(t.net.of("Wi-Fi"), vpn_a(), "the live owner's DNS again");
        assert!(t.m.release(A, &t.log));
        t.originals_back();
    }

    #[test]
    fn salvage_keeps_the_originals_and_the_owners_within_the_limits() {
        let orig = Original { service: "Wi-Fi".into(), dns: dns(&["192.168.1.1"], &[]) };
        let ok = Owner { id: A.into(), dns: vpn_a() };
        let huge = Owner { id: B.into(), dns: big(1, MAX_DOMAINS + 1, 10) };
        let text = Ledger { originals: vec![orig.clone()], owners: vec![ok.clone(), huge] }.render();
        let text = format!("{text}junk\norig\tWi-Fi\tEmpty\tEmpty\n");
        assert!(Ledger::parse(&text).is_none());
        assert_eq!(Ledger::salvage(&text), Ledger { originals: vec![orig], owners: vec![ok] });
        assert_eq!(Ledger::salvage(&text.replace(HEADER, "x")), Ledger::default(), "not a ledger");
        let many: String = (0..SALVAGE_ENTRIES + 10).map(|i| format!("orig\tsvc {i}\tEmpty\tEmpty\n")).collect();
        assert_eq!(Ledger::salvage(&format!("{HEADER}\n{many}")).originals.len(), SALVAGE_ENTRIES);
    }

    #[test]
    fn networksetup_output() {
        assert_eq!(parse_get(List::Servers, "There aren't any DNS Servers set on Wi-Fi.\n"), Some(vec![]));
        assert_eq!(parse_get(List::Domains, "There aren't any Search Domains set on Wi-Fi.\n"), Some(vec![]));
        assert_eq!(parse_get(List::Servers, "1.1.1.1\nfd00::53\n"), Some(vec!["1.1.1.1".into(), "fd00::53".into()]));
        assert_eq!(parse_get(List::Servers, "** Error: The parameters were not valid.\n"), None);
        assert_eq!(parse_get(List::Domains, "corp.example\n"), Some(vec!["corp.example".into()]));
        assert!(!is_search_domain("-x") && !is_search_domain("a b") && is_search_domain("_x.example"));
        assert!(is_service("Thunderbolt Bridge") && !is_service("a\tb") && !is_service(""));
    }
}
