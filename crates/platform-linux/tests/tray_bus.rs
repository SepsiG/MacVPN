//! `SniTray` against a fake `org.kde.StatusNotifierWatcher` on the test's own session bus (run under
//! `dbus-run-session`: no icon reaches the desktop). The test plays the host: it calls the item's methods the way
//! GNOME's AppIndicator extension does (spike L0-2) and reads the menu over `com.canonical.dbusmenu`.
#![cfg(target_os = "linux")]

use macvpn_core::TargetOs;
use macvpn_core::l10n::{AppLanguage, TextPlatform};
use macvpn_platform_linux::{SniTray, TrayEvent};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};
use zbus::blocking::{Connection, Proxy, proxy::Builder};
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedValue, Value};

const WATCHER: &str = "org.kde.StatusNotifierWatcher";
const ITEM: &str = "org.kde.StatusNotifierItem";
const MENU: &str = "com.canonical.dbusmenu";

struct FakeWatcher {
    items: Arc<Mutex<Vec<String>>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl FakeWatcher {
    fn register_status_notifier_item(&mut self, service: String) {
        self.items.lock().unwrap_or_else(PoisonError::into_inner).push(service);
    }

    #[zbus(property)]
    fn is_status_notifier_host_registered(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn protocol_version(&self) -> i32 {
        0
    }
}

fn proxy<'a>(bus: &Connection, dest: &'a str, path: &'a str, interface: &'a str) -> Proxy<'a> {
    Builder::new(bus)
        .destination(dest)
        .unwrap()
        .path(path)
        .unwrap()
        .interface(interface)
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .unwrap()
}

type Layout = (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>);
type Pixmap = Vec<(i32, i32, Vec<u8>)>;

/// The root menu's items as (id, label or "separator").
fn menu_items(menu: &Proxy<'_>) -> Vec<(i32, String)> {
    let (_revision, (_root, _props, children)): (u32, Layout) =
        menu.call("GetLayout", &(0i32, -1i32, Vec::<String>::new())).unwrap();
    children
        .into_iter()
        .map(|child| {
            let (id, props, _): Layout = child.try_into().unwrap();
            let text = |key: &str| props.get(key).map(|v| String::try_from(v.try_clone().unwrap()).unwrap());
            let label = text("type").filter(|t| t == "separator").or_else(|| text("label")).unwrap_or_default();
            (id, label)
        })
        .collect()
}

/// The tests own the watcher's well-known name one at a time.
static ONE_WATCHER: Mutex<()> = Mutex::new(());

type Registered = Arc<Mutex<Vec<String>>>;

fn watcher() -> (Connection, Registered) {
    let items = Registered::default();
    let bus = zbus::blocking::connection::Builder::session()
        .unwrap()
        .name(WATCHER)
        .unwrap()
        .serve_at("/StatusNotifierWatcher", FakeWatcher { items: items.clone() })
        .unwrap()
        .build()
        .expect("a private session bus (run under dbus-run-session)");
    (bus, items)
}

/// The item's bus name, once it has registered with the watcher.
fn registered(items: &Registered) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(name) = items.lock().unwrap_or_else(PoisonError::into_inner).first().cloned() {
            return name;
        }
        assert!(Instant::now() < deadline, "the item registers with the watcher");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn next(rx: &mpsc::Receiver<TrayEvent>) -> TrayEvent {
    rx.recv_timeout(Duration::from_secs(3)).expect("the tray event reaches the callback")
}

#[test]
fn registers_toggles_opens_quits_and_updates_its_icon() {
    macvpn_core::l10n::set_text_platform(TextPlatform { os: TargetOs::Linux, product: "LinVPN" });
    let _one = ONE_WATCHER.lock().unwrap_or_else(PoisonError::into_inner);
    let (_watcher, items) = watcher();

    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let white = [255u8, 255, 255, 255].repeat(4);
    let tray = SniTray::spawn(&white, 2, 2, "LinVPN", move |event| {
        let _ = tx.lock().unwrap_or_else(PoisonError::into_inner).send(event);
    })
    .expect("the item registers");

    let name = registered(&items);
    assert!(name.starts_with("org.kde.StatusNotifierItem-"), "{name}");

    let host = Connection::session().unwrap();
    let item = proxy(&host, &name, "/StatusNotifierItem", ITEM);
    assert_eq!(item.get_property::<String>("Id").unwrap(), "linvpn");
    assert_eq!(item.get_property::<String>("Title").unwrap(), "LinVPN");
    assert!(!item.get_property::<bool>("ItemIsMenu").unwrap(), "Activate reaches the app, not the menu");
    let pixmap: Pixmap = item.get_property("IconPixmap").unwrap();
    assert_eq!(pixmap, vec![(2, 2, white.clone())]);

    // GNOME's double click: the token first, then Activate (spike L0-2).
    item.call_method("ProvideXdgActivationToken", &("token-1",)).unwrap();
    item.call_method("Activate", &(1096i32, 16i32)).unwrap();
    assert_eq!(next(&rx), TrayEvent::Toggle { at: (1096, 16), token: Some("token-1".into()) });
    // The middle click toggles too; without a token the event has none.
    item.call_method("SecondaryActivate", &(5i32, 6i32)).unwrap();
    assert_eq!(next(&rx), TrayEvent::Toggle { at: (5, 6), token: None });

    // The menu: "Open LinVPN", a separator, "Quit LinVPN"; translated when the host asks.
    let menu = proxy(&host, &name, "/MenuBar", MENU);
    let labels = menu_items(&menu);
    let texts: Vec<&str> = labels.iter().map(|(_, l)| l.as_str()).collect();
    assert_eq!(texts, ["Open LinVPN", "separator", "Quit LinVPN"]);
    AppLanguage::set_override(Some(AppLanguage::Hu));
    tray.refresh();
    let texts_hu: Vec<String> = menu_items(&menu).into_iter().map(|(_, l)| l).collect();
    AppLanguage::set_override(None);
    assert_eq!(texts_hu, ["LinVPN megnyitása", "separator", "Kilépés a LinVPN-ből"]);

    let click = |id: i32| {
        menu.call_method("Event", &(id, "clicked", Value::from(0i32), 0u32)).unwrap();
    };
    item.call_method("ProvideXdgActivationToken", &("token-2",)).unwrap();
    click(labels[0].0);
    assert_eq!(next(&rx), TrayEvent::Open { token: Some("token-2".into()) });
    click(labels[2].0);
    assert_eq!(next(&rx), TrayEvent::Quit);

    // A new state: the icon (RGBA → ARGB) and the tooltip.
    tray.set_icon(&[10, 20, 30, 255], 1, 1, "LinVPN — Office VPN");
    let pixmap: Pixmap = item.get_property("IconPixmap").unwrap();
    assert_eq!(pixmap, vec![(1, 1, vec![255, 10, 20, 30])]);
    let (_, _, title, _): (String, Pixmap, String, String) = item.get_property("ToolTip").unwrap();
    assert_eq!(title, "LinVPN — Office VPN");

    tray.shutdown();
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "no event beyond the ones asked for");
}

#[test]
fn registers_when_the_watcher_appears_later() {
    // At login LinVPN may start before the shell's extension, and GNOME disables the extension (its watcher) while
    // the screen is locked: spawning without a watcher succeeds and the item registers once one appears.
    let _one = ONE_WATCHER.lock().unwrap_or_else(PoisonError::into_inner);
    let tray = SniTray::spawn(&[0, 0, 0, 0], 1, 1, "LinVPN", |_| {}).expect("no watcher is not an error");
    std::thread::sleep(Duration::from_millis(200));
    let (_watcher, items) = watcher();
    assert!(registered(&items).starts_with("org.kde.StatusNotifierItem-"));
    tray.shutdown();
}
