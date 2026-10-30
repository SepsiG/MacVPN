//! `LinNotifier` against a fake `org.freedesktop.Notifications` on the test's own session bus (run under
//! `dbus-run-session`: no notification reaches the desktop).
#![cfg(target_os = "linux")]

use macvpn_platform_api::Notifier;
use macvpn_platform_linux::LinNotifier;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;
use zbus::zvariant::OwnedValue;

const DEST: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

#[derive(Debug)]
struct Notify {
    app_name: String,
    replaces_id: u32,
    summary: String,
    body: String,
    actions: Vec<String>,
    hints: HashMap<String, OwnedValue>,
}

#[derive(Default)]
struct Seen {
    notify: Vec<Notify>,
    closed: Vec<u32>,
}

struct Fake {
    seen: Arc<Mutex<Seen>>,
    next: u32,
}

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl Fake {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &mut self,
        app_name: String,
        replaces_id: u32,
        _app_icon: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        self.next += 1;
        let notify = Notify { app_name, replaces_id, summary, body, actions, hints };
        self.seen.lock().unwrap_or_else(PoisonError::into_inner).notify.push(notify);
        self.next
    }

    fn close_notification(&mut self, id: u32) {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner).closed.push(id);
    }
}

#[test]
fn posts_replaces_clicks_and_closes() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let server = zbus::blocking::connection::Builder::session()
        .unwrap()
        .name(DEST)
        .unwrap()
        .serve_at(PATH, Fake { seen: seen.clone(), next: 40 })
        .unwrap()
        .build()
        .expect("a private session bus (run under dbus-run-session)");

    let notifier = LinNotifier::for_tests();
    let (tx, rx) = mpsc::channel::<BTreeMap<String, String>>();
    let tx = Mutex::new(tx);
    notifier.start(Box::new(move |info| {
        let _ = tx.lock().unwrap_or_else(PoisonError::into_inner).send(info);
    }));

    notifier.post("connected", "Office VPN", "Connected", ("connection", "6F1C"));
    let first = {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.notify.len(), 1);
        let n = &seen.notify[0];
        assert_eq!(n.app_name, "LinVPN");
        assert_eq!(n.replaces_id, 0);
        assert_eq!((n.summary.as_str(), n.body.as_str()), ("Office VPN", "Connected"));
        assert_eq!(n.actions, vec!["default".to_string(), String::new()]);
        assert_eq!(n.hints.keys().collect::<Vec<_>>(), vec!["desktop-entry"], "no hint beyond desktop-entry");
        assert_eq!(String::try_from(n.hints["desktop-entry"].try_clone().unwrap()).unwrap(), "linvpn");
        41
    };

    notifier.post("connected", "Office VPN", "Connected", ("connection", "6F1C"));
    let second = {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.notify.len(), 2);
        assert_eq!(seen.notify[1].replaces_id, first, "a repost replaces the shown one");
        42
    };

    server.emit_signal(None::<&str>, PATH, DEST, "ActionInvoked", &(second, "default")).unwrap();
    let info = rx.recv_timeout(Duration::from_secs(2)).expect("the click reaches the handler");
    assert_eq!(info, BTreeMap::from([("connection".to_string(), "6F1C".to_string())]));

    notifier.remove_delivered("connected");
    assert_eq!(seen.lock().unwrap().closed, vec![second]);
}
