//! Notifications through `org.freedesktop.Notifications` (GNOME Shell's server): app name "LinVPN", the hint
//! `desktop-entry = linvpn` (GNOME shows the app's icon and groups them), the default action (a click), and
//! `replaces_id` so a repost of one identifier replaces the shown notification. `ActionInvoked(id, "default")` calls
//! the click handler with that notification's user info; `NotificationClosed` forgets it. The body never carries a
//! secret (the callers post titles and states only).

use crate::pure::notify::Book;
use macvpn_platform_api::Notifier;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::Value;

const DEST: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

type OnClick = Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>;

pub struct LinNotifier {
    bus: fn() -> zbus::Result<Connection>,
    book: Arc<Mutex<Book>>,
}

impl LinNotifier {
    /// The process' shared session bus, opened at the first call (never at construction).
    pub fn production() -> LinNotifier {
        LinNotifier { bus: crate::lin::bus::session, book: Arc::default() }
    }

    /// A connection of its own to the session bus (the test's private one).
    #[doc(hidden)]
    pub fn for_tests() -> LinNotifier {
        LinNotifier { bus: Connection::session, book: Arc::default() }
    }

    fn proxy(&self) -> Option<Proxy<'static>> {
        let bus = (self.bus)().ok()?;
        Proxy::new(&bus, DEST, PATH, DEST).ok()
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Notifier for LinNotifier {
    fn start(&self, on_click: OnClick) {
        let Some(proxy) = self.proxy() else { return };
        let Ok(invoked) = proxy.receive_signal("ActionInvoked") else { return };
        let Ok(closed) = proxy.receive_signal("NotificationClosed") else { return };
        let closed_book = self.book.clone();
        std::thread::Builder::new()
            .name("linvpn-notify-closed".into())
            .spawn(move || {
                for m in closed {
                    if let Ok((id, _reason)) = m.body().deserialize::<(u32, u32)>() {
                        closed_book.lock().unwrap_or_else(PoisonError::into_inner).closed(id);
                    }
                }
            })
            .ok();
        let book = self.book.clone();
        std::thread::Builder::new()
            .name("linvpn-notify-click".into())
            .spawn(move || {
                for m in invoked {
                    let Ok((id, action)) = m.body().deserialize::<(u32, String)>() else { continue };
                    if action != "default" {
                        continue;
                    }
                    let info = book.lock().unwrap_or_else(PoisonError::into_inner).clicked(id);
                    if let Some(info) = info {
                        on_click(info);
                    }
                }
            })
            .ok();
    }

    fn post(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str)) {
        let Some(proxy) = self.proxy() else { return };
        let replaces = self.book().replaces(identifier);
        let hints: HashMap<&str, Value> = HashMap::from([("desktop-entry", Value::from("linvpn"))]);
        let reply: zbus::Result<u32> =
            proxy.call("Notify", &("LinVPN", replaces, "linvpn", title, body, vec!["default", ""], hints, -1i32));
        if let Ok(id) = reply {
            self.book().posted(identifier, id, user_info);
        }
    }

    fn remove_delivered(&self, identifier: &str) {
        let id = self.book().id_of(identifier);
        if let (Some(id), Some(proxy)) = (id, self.proxy()) {
            let _: zbus::Result<()> = proxy.call("CloseNotification", &(id,));
        }
    }
}
