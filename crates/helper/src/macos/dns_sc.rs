//! The DNS manager's [`Net`] as root (root layer 14): the DNS servers and search domains are read and written in
//! the SystemConfiguration preferences directly, as `networksetup` does internally, but every service of a batch in
//! one locked session with **one** commit and apply instead of four `networksetup` processes per service.
//!
//! Parity with `networksetup` (DNS leaks are the risk): the same keys of the service's DNS entity
//! (`ServerAddresses`, `SearchDomains`), an empty list removes the key (`networksetup … Empty`), every other key of
//! that entity is kept, a read sees the committed preferences (a new session per read). The service list itself
//! still comes from `networksetup -listallnetworkservices` (one process), so the ledger's names are the same.
//!
//! Whatever is not certain goes to the fallback (`networksetup`, as before root layer 14): the whole batch when the
//! preferences cannot be opened, locked, committed or applied; a service whose name is not unique in the current
//! set or not found there, a disabled service, a service without a DNS entity or with a disabled one, and a read
//! whose values are not the expected strings.

use crate::macos::dns_legacy::{Dns, List, Net, is_valid, words};
use crate::macos::log::Log;
use crate::macos::sc_prefs::{self, Protocol};
use crate::shared::l10n::tr;
use core_foundation::base::CFType;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::string::CFString;
use std::path::PathBuf;

/// The `SCPreferencesCreate` name.
const NAME: &str = "mvpn";

pub struct ScNet {
    /// `None`: the system's preferences; a path: a private preferences file (the tests).
    pub prefs_id: Option<PathBuf>,
    /// `SCPreferencesApplyChanges` after the commit (only for the system's preferences).
    pub apply: bool,
    /// `networksetup`: the service list, and every operation the preferences cannot do with certainty.
    pub fallback: Box<dyn Net>,
}

impl ScNet {
    /// As root: the system's preferences, `networksetup` as the fallback.
    pub fn system(fallback: Box<dyn Net>) -> ScNet {
        ScNet { prefs_id: None, apply: true, fallback }
    }

    fn open(&self) -> Result<sc_prefs::Prefs, String> {
        sc_prefs::open(NAME, self.prefs_id.as_deref())
    }
}

/// The DNS entity of the one enabled service named `name` in the current set, if it has an enabled one.
fn dns_of(services: &[(Option<String>, sc_prefs::Service)], name: &str) -> Option<Protocol> {
    let mut found = services.iter().filter(|(n, _)| n.as_deref() == Some(name));
    let (_, svc) = found.next()?;
    if found.next().is_some() || !svc.enabled() {
        return None;
    }
    svc.dns().filter(Protocol::enabled)
}

fn named(p: &sc_prefs::Prefs) -> Result<Vec<(Option<String>, sc_prefs::Service)>, String> {
    Ok(p.current_services()?.into_iter().map(|s| (s.name(), s)).collect())
}

/// One list of a DNS configuration: a missing key is empty; anything but valid strings is `None`.
fn read_list(cfg: &CFDictionary<CFString, CFType>, key: &CFString, list: List) -> Option<Vec<String>> {
    let Some(v) = cfg.find(key) else { return Some(Vec::new()) };
    let v = sc_prefs::string_list(&v)?;
    v.iter().all(|w| is_valid(list, w)).then_some(v)
}

fn read(p: &Protocol) -> Option<Dns> {
    let Some(cfg) = p.configuration().ok()? else { return Some(Dns::default()) };
    Some(Dns {
        servers: read_list(&cfg, &sc_prefs::key_servers(), List::Servers)?,
        domains: read_list(&cfg, &sc_prefs::key_domains(), List::Domains)?,
    })
}

/// The configuration with both lists replaced (an empty list removes its key); every other key kept.
fn write(p: &Protocol, d: &Dns) -> Result<(), String> {
    let mut cfg: CFMutableDictionary<CFString, CFType> = match p.configuration() {
        Ok(Some(c)) => CFMutableDictionary::from(&c),
        Ok(None) => CFMutableDictionary::new(),
        Err(()) => return Err("the DNS configuration is not a dictionary".into()),
    };
    for (key, values) in [(sc_prefs::key_servers(), &d.servers), (sc_prefs::key_domains(), &d.domains)] {
        if values.is_empty() {
            cfg.remove(key);
        } else {
            cfg.set(key, sc_prefs::cf_strings(values));
        }
    }
    p.set_configuration(&cfg.to_immutable())
}

/// The log line of a failed SystemConfiguration batch.
fn log_fallback(log: &Log, why: &str) {
    log.step(&tr("the DNS change through SystemConfiguration failed (%@); networksetup is used instead", &[why]));
}

impl Net for ScNet {
    fn services(&self) -> Option<Vec<String>> {
        self.fallback.services()
    }

    fn get(&self, list: List, service: &str) -> Option<Vec<String>> {
        self.fallback.get(list, service)
    }

    fn set(&self, list: List, service: &str, values: &[String]) {
        self.fallback.set(list, service, values)
    }

    fn get_many(&self, services: &[String]) -> Vec<Option<Dns>> {
        let Ok(p) = self.open() else { return self.fallback.get_many(services) };
        let Ok(all) = named(&p) else { return self.fallback.get_many(services) };
        let mut out: Vec<Option<Dns>> = Vec::with_capacity(services.len());
        let mut rest: Vec<usize> = Vec::new();
        for (i, svc) in services.iter().enumerate() {
            match dns_of(&all, svc).as_ref().and_then(read) {
                Some(d) => out.push(Some(d)),
                None => {
                    out.push(None);
                    rest.push(i);
                }
            }
        }
        if !rest.is_empty() {
            let names: Vec<String> = rest.iter().map(|&i| services[i].clone()).collect();
            for (i, d) in rest.into_iter().zip(self.fallback.get_many(&names)) {
                out[i] = d;
            }
        }
        out
    }

    /// What the preferences wrote but did not read back as written goes through `networksetup` the second time.
    fn retry_many(&self, items: &[(String, Dns)], log: &Log) {
        self.fallback.set_many(items, log)
    }

    fn set_many(&self, items: &[(String, Dns)], log: &Log) {
        if items.is_empty() {
            return;
        }
        let p = match self.open() {
            Ok(p) => p,
            Err(e) => {
                log_fallback(log, &e);
                return self.fallback.set_many(items, log);
            }
        };
        // Locked before the first read, so the session's snapshot is the one written back.
        let all = match p.lock().and_then(|()| named(&p)) {
            Ok(all) => all,
            Err(e) => {
                drop(p);
                log_fallback(log, &e);
                return self.fallback.set_many(items, log);
            }
        };
        let mut done: Vec<&(String, Dns)> = Vec::new();
        let mut rest: Vec<(String, Dns)> = Vec::new();
        for item in items {
            match dns_of(&all, &item.0) {
                Some(proto) if write(&proto, &item.1).is_ok() => done.push(item),
                _ => rest.push(item.clone()),
            }
        }
        if !done.is_empty() {
            let r = p.commit().and_then(|()| if self.apply { p.apply() } else { Ok(()) });
            p.unlock();
            if let Err(e) = r {
                // Nothing is known to have taken: the whole batch again through networksetup.
                log_fallback(log, &e);
                return self.fallback.set_many(items, log);
            }
            for (svc, d) in &done {
                log.step(&tr(
                    "DNS of %@ written: servers %@, search domains %@",
                    &[svc, &words(&d.servers), &words(&d.domains)],
                ));
            }
        }
        drop(p);
        if !rest.is_empty() {
            self.fallback.set_many(&rest, log);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::dns_legacy::tests::{FakeNet, dns};

    const WIFI: &str = "11111111-1111-1111-1111-111111111111";
    const ETH: &str = "22222222-2222-2222-2222-222222222222";
    const NODNS: &str = "33333333-3333-3333-3333-333333333333";
    const OFF: &str = "44444444-4444-4444-4444-444444444444";
    const DNSOFF: &str = "55555555-5555-5555-5555-555555555555";
    const DUP1: &str = "66666666-6666-6666-6666-666666666666";
    const DUP2: &str = "77777777-7777-7777-7777-777777777777";
    const SET: &str = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA";

    fn service(name: &str, dev: &str, dns: &str, extra: &str) -> String {
        format!(
            "<dict>{extra}<key>DNS</key><dict>{dns}</dict>\
             <key>IPv4</key><dict><key>ConfigMethod</key><string>DHCP</string></dict>\
             <key>Interface</key><dict><key>DeviceName</key><string>{dev}</string>\
             <key>Hardware</key><string>Ethernet</string><key>Type</key><string>Ethernet</string>\
             <key>UserDefinedName</key><string>{name}</string></dict>\
             <key>UserDefinedName</key><string>{name}</string></dict>"
        )
    }

    fn strings(v: &[&str]) -> String {
        v.iter().map(|s| format!("<string>{s}</string>")).collect()
    }

    /// A private preferences file: Wi-Fi (servers, domains and an extra key), Ethernet (an empty DNS entity), a
    /// service without a DNS entity, a disabled one, one whose DNS entity is disabled, two with the same name.
    fn prefs_file(dir: &std::path::Path) -> PathBuf {
        let wifi_dns = format!(
            "<key>ServerAddresses</key><array>{}</array><key>SearchDomains</key><array>{}</array>\
             <key>Options</key><string>keep-me</string>",
            strings(&["192.168.1.1", "fd00::53"]),
            strings(&["lan.example.com"])
        );
        let mut services = String::new();
        let all = [
            (WIFI, service("Wi-Fi", "en0", &wifi_dns, "")),
            (ETH, service("Ethernet", "en1", "", "")),
            (NODNS, service("NoDNS", "en2", "", "").replace("<key>DNS</key><dict></dict>", "")),
            (OFF, service("Off", "en3", "", "<key>__INACTIVE__</key><true/>")),
            (DNSOFF, service("DnsOff", "en4", "<key>__INACTIVE__</key><true/>", "")),
            (DUP1, service("Twin", "en5", "", "")),
            (DUP2, service("Twin", "en6", "", "")),
        ];
        let mut links = String::new();
        let mut order = String::new();
        for (id, body) in &all {
            services.push_str(&format!("<key>{id}</key>{body}"));
            links.push_str(&format!(
                "<key>{id}</key><dict><key>__LINK__</key><string>/NetworkServices/{id}</string></dict>"
            ));
            order.push_str(&format!("<string>{id}</string>"));
        }
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CurrentSet</key><string>/Sets/{SET}</string>
<key>NetworkServices</key><dict>{services}</dict>
<key>Sets</key><dict><key>{SET}</key><dict>
<key>Network</key><dict><key>Global</key><dict><key>IPv4</key><dict><key>ServiceOrder</key><array>{order}</array></dict></dict>
<key>Service</key><dict>{links}</dict></dict>
<key>UserDefinedName</key><string>Automatic</string></dict></dict>
<key>__VERSION__</key><integer>20191120</integer>
</dict></plist>
"#
        );
        let p = dir.join("preferences.plist");
        std::fs::write(&p, xml).unwrap();
        p
    }

    struct T {
        dir: PathBuf,
        file: PathBuf,
        fake: FakeNet,
    }

    impl T {
        fn new() -> T {
            let dir = std::env::temp_dir().join(format!("mvpn-sc-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let file = prefs_file(&dir);
            // The fallback: what `networksetup` would see of the services the preferences leave to it.
            let fake = FakeNet::with(&[
                ("NoDNS", &["10.0.0.1"], &[]),
                ("Off", &["10.0.0.2"], &[]),
                ("DnsOff", &["10.0.0.3"], &[]),
                ("Twin", &["10.0.0.4"], &[]),
            ]);
            T { dir, file, fake }
        }

        fn net(&self) -> ScNet {
            ScNet { prefs_id: Some(self.file.clone()), apply: false, fallback: Box::new(self.fake.clone()) }
        }

        fn log(&self) -> Log {
            Log::at(self.dir.join("conn.log"))
        }

        fn log_text(&self) -> String {
            std::fs::read_to_string(self.dir.join("conn.log")).unwrap_or_default()
        }

        /// The DNS entity of `id` as the file holds it now (`plutil`, read-only).
        fn on_disk(&self, id: &str) -> String {
            let out = std::process::Command::new("/usr/bin/plutil")
                .args(["-extract", &format!("NetworkServices.{id}.DNS"), "json", "-o", "-"])
                .arg(&self.file)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        }
    }

    impl Drop for T {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn reads_come_from_the_preferences_and_the_uncertain_ones_from_the_fallback() {
        let t = T::new();
        let got = t.net().get_many(&names(&["Wi-Fi", "Ethernet", "NoDNS", "Off", "DnsOff", "Twin", "Gone"]));
        assert_eq!(
            got,
            vec![
                Some(dns(&["192.168.1.1", "fd00::53"], &["lan.example.com"])),
                Some(dns(&[], &[])),
                Some(dns(&["10.0.0.1"], &[])),
                Some(dns(&["10.0.0.2"], &[])),
                Some(dns(&["10.0.0.3"], &[])),
                Some(dns(&["10.0.0.4"], &[])),
                None,
            ]
        );
    }

    #[test]
    #[ignore = "SCPreferencesLock needs root even for a private file: sudo cargo test -p macvpn-helper dns_sc -- --ignored"]
    fn one_commit_sets_the_lists_and_keeps_the_other_keys() {
        let t = T::new();
        let log = t.log();
        let vpn = dns(&["10.8.0.1", "10.8.0.2"], &["corp.example"]);
        let items: Vec<(String, Dns)> =
            ["Wi-Fi", "Ethernet", "NoDNS", "Twin"].iter().map(|s| (s.to_string(), vpn.clone())).collect();
        t.net().set_many(&items, &log);
        // A new session reads the committed file.
        let got = t.net().get_many(&names(&["Wi-Fi", "Ethernet", "NoDNS", "Twin"]));
        assert!(got.iter().all(|d| d.as_ref() == Some(&vpn)), "{got:?}");
        let wifi = t.on_disk(WIFI);
        assert!(wifi.contains("keep-me") && wifi.contains("10.8.0.2") && wifi.contains("corp.example"), "{wifi}");
        assert!(!wifi.contains("192.168.1.1"), "{wifi}");
        assert!(t.on_disk(ETH).contains("10.8.0.1"));
        // The services the preferences leave alone went through the fallback (its log lines included).
        assert_eq!(
            *t.fake.0.sets.borrow(),
            vec![
                "Servers NoDNS 10.8.0.1 10.8.0.2",
                "Domains NoDNS corp.example",
                "Servers Twin 10.8.0.1 10.8.0.2",
                "Domains Twin corp.example"
            ]
        );
        let text = t.log_text();
        assert!(
            text.contains("DNS of Wi-Fi written: servers 10.8.0.1 10.8.0.2, search domains corp.example"),
            "{text}"
        );
        assert!(text.contains("$ networksetup -setdnsservers \"NoDNS\" 10.8.0.1 10.8.0.2"), "{text}");
        assert!(!text.contains("networksetup -setdnsservers \"Wi-Fi\""), "{text}");
    }

    #[test]
    #[ignore = "SCPreferencesLock needs root even for a private file: sudo cargo test -p macvpn-helper dns_sc -- --ignored"]
    fn an_empty_list_removes_its_key() {
        let t = T::new();
        t.net().set_many(&[("Wi-Fi".into(), dns(&[], &[]))], &t.log());
        assert_eq!(t.net().get_many(&names(&["Wi-Fi"])), vec![Some(dns(&[], &[]))]);
        let wifi = t.on_disk(WIFI);
        assert!(!wifi.contains("ServerAddresses") && !wifi.contains("SearchDomains"), "{wifi}");
        assert!(wifi.contains("keep-me"), "{wifi}");
        assert!(t.log_text().contains("DNS of Wi-Fi written: servers Empty, search domains Empty"));
    }

    /// What a session writes (before the commit, which needs root): the lists replaced, an empty one's key
    /// removed, every other key kept; only the certain services are offered for writing.
    #[test]
    fn a_session_write_replaces_the_lists_and_keeps_the_other_keys() {
        let t = T::new();
        let p = t.net().open().unwrap();
        let all = named(&p).unwrap();
        for uncertain in ["NoDNS", "Off", "DnsOff", "Twin", "Gone"] {
            assert!(dns_of(&all, uncertain).is_none(), "{uncertain}");
        }
        let wifi = dns_of(&all, "Wi-Fi").unwrap();
        let vpn = dns(&["10.8.0.1", "10.8.0.2"], &["corp.example"]);
        write(&wifi, &vpn).unwrap();
        assert_eq!(read(&wifi), Some(vpn));
        let options = || {
            wifi.configuration()
                .unwrap()
                .unwrap()
                .find(CFString::new("Options"))
                .and_then(|v| v.downcast::<CFString>())
                .map(|v| v.to_string())
        };
        assert!(options().is_some_and(|v| v.contains("keep-me")));
        write(&wifi, &dns(&[], &[])).unwrap();
        let cfg = wifi.configuration().unwrap().unwrap();
        assert!(cfg.find(sc_prefs::key_servers()).is_none() && cfg.find(sc_prefs::key_domains()).is_none());
        assert!(options().is_some_and(|v| v.contains("keep-me")), "the other keys stay");
        let eth = dns_of(&all, "Ethernet").unwrap();
        write(&eth, &dns(&["10.9.0.1"], &[])).unwrap();
        assert_eq!(read(&eth), Some(dns(&["10.9.0.1"], &[])));
    }

    /// Not as root `SCPreferencesLock` is refused: the whole batch goes through the fallback, logged.
    #[test]
    fn a_lock_failure_sends_the_whole_batch_to_the_fallback() {
        if crate::macos::sys::geteuid() == 0 {
            return;
        }
        let t = T::new();
        t.fake.add("Wi-Fi", &[], &[]);
        let items =
            vec![("Wi-Fi".to_string(), dns(&["10.8.0.1"], &[])), ("NoDNS".to_string(), dns(&["10.8.0.1"], &[]))];
        t.net().set_many(&items, &t.log());
        assert_eq!(t.fake.of("Wi-Fi"), dns(&["10.8.0.1"], &[]));
        assert_eq!(t.fake.of("NoDNS"), dns(&["10.8.0.1"], &[]));
        assert!(!t.on_disk(WIFI).contains("10.8.0.1"), "the preferences are untouched");
        let text = t.log_text();
        assert!(text.contains("the DNS change through SystemConfiguration failed (SCPreferencesLock"), "{text}");
        assert!(text.contains("$ networksetup -setdnsservers \"Wi-Fi\" 10.8.0.1"), "{text}");
    }

    #[test]
    fn missing_preferences_go_to_the_fallback() {
        let t = T::new();
        let net = ScNet {
            prefs_id: Some(t.dir.join("missing/dir/preferences.plist")),
            apply: false,
            fallback: Box::new(t.fake.clone()),
        };
        net.set_many(&[("NoDNS".into(), dns(&["10.9.0.1"], &[]))], &t.log());
        assert_eq!(t.fake.of("NoDNS"), dns(&["10.9.0.1"], &[]));
        assert_eq!(net.get_many(&names(&["NoDNS", "Wi-Fi"])), vec![Some(dns(&["10.9.0.1"], &[])), None]);
    }

    /// Read-only parity on this Mac: the preferences read the same as `networksetup -get…` for every service.
    /// Changes nothing; run by hand (`cargo test -p macvpn-helper sc_reads_match -- --ignored`).
    #[test]
    #[ignore = "reads this Mac's network services"]
    fn sc_reads_match_networksetup_on_this_mac() {
        let ns = crate::macos::dns_legacy::NetworkSetup { program: crate::macos::paths::NETWORKSETUP.into() };
        let services = ns.services().unwrap();
        let sc = ScNet { prefs_id: None, apply: false, fallback: Box::new(FakeNet::default()) };
        let a = sc.get_many(&services);
        let b = ns.get_many(&services);
        for ((s, a), b) in services.iter().zip(&a).zip(&b) {
            println!("{s}: sc {a:?} / networksetup {b:?}");
            if a.is_some() {
                assert_eq!(a, b, "{s}");
            }
        }
    }
}
