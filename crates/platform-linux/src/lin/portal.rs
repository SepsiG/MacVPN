//! `org.freedesktop.portal.Desktop` on the session bus: `Settings.ReadOne("org.freedesktop.appearance",
//! "color-scheme")` (older portals: `Read`, which wraps the value once more), its `SettingChanged` signal, and the
//! `FileChooser`'s `OpenFile` / `SaveFile` with the `Response` signal on the returned request object. The file
//! chooser has an empty parent window id (not modal to the panel; LinVPN plan, "Resolved points").

use crate::pure::portal::{dark_from_color_scheme, paths_from_uris};
use macvpn_core::l10n;
use macvpn_platform_api::{FilePanels, NativeWindow};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use zbus::blocking::Proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const DEST: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";

/// The `u` of `ReadOne`, or the `u` inside the extra variant of `Read`.
fn unwrap_u32(v: &Value<'_>) -> Option<u32> {
    match v {
        Value::U32(n) => Some(*n),
        Value::Value(inner) => unwrap_u32(inner),
        _ => None,
    }
}

/// `Some(true)` dark, `Some(false)` light, `None` no preference or no portal.
pub fn system_dark() -> Option<bool> {
    let bus = crate::lin::bus::session().ok()?;
    let settings = Proxy::new(&bus, DEST, PATH, "org.freedesktop.portal.Settings").ok()?;
    let value: OwnedValue = settings
        .call("ReadOne", &("org.freedesktop.appearance", "color-scheme"))
        .or_else(|_| settings.call("Read", &("org.freedesktop.appearance", "color-scheme")))
        .ok()?;
    dark_from_color_scheme(unwrap_u32(&value)?)
}

/// Calls `on_change` on its own thread whenever `color-scheme` changes.
// Its caller is Task 16's `AppLifecycle::observe_appearance`.
#[allow(dead_code)]
pub fn watch_color_scheme(on_change: Box<dyn Fn() + Send + Sync>) {
    let Ok(bus) = crate::lin::bus::session() else { return };
    let Ok(settings) = Proxy::new(&bus, DEST, PATH, "org.freedesktop.portal.Settings") else { return };
    let Ok(changes) = settings.receive_signal("SettingChanged") else { return };
    std::thread::Builder::new()
        .name("linvpn-color-scheme".into())
        .spawn(move || {
            for m in changes {
                if let Ok((ns, key, _)) = m.body().deserialize::<(String, String, OwnedValue)>()
                    && ns == "org.freedesktop.appearance"
                    && key == "color-scheme"
                {
                    on_change();
                }
            }
        })
        .ok();
}

/// Each request's `handle_token` (letters, digits and `_` only): unique within the process.
static TOKEN: AtomicU64 = AtomicU64::new(1);

/// A blocking file-chooser request; call it off the main thread. `save`: `SaveFile` with `suggested` as the
/// current name. The paths the user chose; empty on cancel or error.
pub fn choose(save: bool, multiple: bool, suggested: &str, title: &str) -> Vec<PathBuf> {
    let Ok(bus) = crate::lin::bus::session() else { return Vec::new() };
    let Ok(chooser) = Proxy::new(&bus, DEST, PATH, "org.freedesktop.portal.FileChooser") else { return Vec::new() };
    let token = format!("linvpn{}_{}", std::process::id(), TOKEN.fetch_add(1, Ordering::Relaxed));
    let mut options: HashMap<&str, Value> =
        HashMap::from([("handle_token", Value::from(token.as_str())), ("modal", Value::from(true))]);
    if save {
        options.insert("current_name", Value::from(suggested));
    } else {
        options.insert("multiple", Value::from(multiple));
    }
    let method = if save { "SaveFile" } else { "OpenFile" };
    // Subscribe before the call: the request path is predictable from the sender and the token
    // (/org/freedesktop/portal/desktop/request/<sender with . → _ and no :>/<token>).
    let sender = bus.unique_name().map(|n| n.trim_start_matches(':').replace('.', "_")).unwrap_or_default();
    let request_path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
    let Ok(request) = Proxy::new(&bus, DEST, request_path.as_str(), "org.freedesktop.portal.Request") else {
        return Vec::new();
    };
    let Ok(mut responses) = request.receive_signal("Response") else { return Vec::new() };
    let reply: zbus::Result<OwnedObjectPath> = chooser.call(method, &("", title, options));
    if reply.is_err() {
        return Vec::new();
    }
    let Some(m) = responses.next() else { return Vec::new() };
    let Ok((code, results)) = m.body().deserialize::<(u32, HashMap<String, OwnedValue>)>() else {
        return Vec::new();
    };
    if code != 0 {
        return Vec::new();
    }
    let uris: Vec<String> = results
        .get("uris")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<String>::try_from(v).ok())
        .unwrap_or_default();
    paths_from_uris(&uris)
}

type Done = Box<dyn FnOnce(Vec<PathBuf>)>;

thread_local! {
    /// The `done` callbacks (not `Send`) of the open requests, on the main thread.
    static PENDING: RefCell<HashMap<u64, Done>> = RefCell::new(HashMap::new());
}

static NEXT: AtomicU64 = AtomicU64::new(1);

/// Runs the request on a thread of its own and hands the result back to the GTK main context (the main thread),
/// where `done` waits. Off the main thread `done` gets nothing at once (the trait's contract).
fn ask(save: bool, multiple: bool, suggested: String, title: String, done: Done) {
    let context = glib::MainContext::default();
    if !context.is_owner() {
        done(Vec::new());
        return;
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    PENDING.with(|p| p.borrow_mut().insert(id, done));
    let spawned = std::thread::Builder::new().name("linvpn-file-chooser".into()).spawn(move || {
        let paths = choose(save, multiple, &suggested, &title);
        context.invoke(move || {
            if let Some(done) = PENDING.with(|p| p.borrow_mut().remove(&id)) {
                done(paths);
            }
        });
    });
    if spawned.is_err()
        && let Some(done) = PENDING.with(|p| p.borrow_mut().remove(&id))
    {
        done(Vec::new());
    }
}

/// The open and save panels: the portal's file chooser.
pub struct Panels;

impl FilePanels for Panels {
    fn choose_files(&self, _parent: NativeWindow, multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>) {
        ask(false, multiple, String::new(), l10n::tr("Open", &[]), done);
    }

    fn choose_save_path(
        &self,
        _parent: NativeWindow,
        suggested: &str,
        message: Option<&str>,
        done: Box<dyn FnOnce(Option<PathBuf>)>,
    ) {
        let title = message.map(str::to_string).unwrap_or_else(|| l10n::tr("Save", &[]));
        ask(true, false, suggested.to_string(), title, Box::new(move |paths| done(paths.into_iter().next())));
    }
}
