//! The app's quit request and the system's sleep and wake on Linux. SIGTERM (logout: systemd stops the session's
//! scope) and SIGINT go to the terminate handler on the GTK main loop (= the main thread): `Now` → the exit hook;
//! `Later` → the app answers through `reply_to_terminate`; `Cancel` → logged, LinVPN stays (logout follows with
//! SIGKILL after systemd's stop timeout). Sleep and wake: logind's `PrepareForSleep(true/false)` on the system bus.
//! Appearance: the portal's `color-scheme` changes.

use macvpn_platform_api::{AppLifecycle, TerminateReply};
use std::sync::{Arc, Mutex, PoisonError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedValue;

type Hook = Box<dyn Fn() + Send + Sync>;

/// How the app exits (the app sets `AppHandle::exit(0)`; before it does: `std::process::exit(0)`).
static EXIT: Mutex<Option<Hook>> = Mutex::new(None);

pub fn set_exit_hook(hook: Hook) {
    *EXIT.lock().unwrap_or_else(PoisonError::into_inner) = Some(hook);
}

fn exit_now() {
    match EXIT.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
        Some(hook) => hook(),
        None => std::process::exit(0),
    }
}

pub struct Lifecycle;

impl AppLifecycle for Lifecycle {
    /// Must run on the main thread while it owns GLib's default main context (the app's `setup`).
    fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool {
        let handler = Arc::new(handler);
        for signal in [libc::SIGTERM, libc::SIGINT] {
            let handler = handler.clone();
            // The returned `SourceId` is never zero: adding the source cannot fail.
            let _source = glib::unix_signal_add_local(signal, move || {
                match handler() {
                    TerminateReply::Now => exit_now(),
                    TerminateReply::Later => {}
                    TerminateReply::Cancel => eprintln!("LinVPN: the quit request was declined"),
                }
                glib::ControlFlow::Continue
            });
        }
        true
    }

    fn reply_to_terminate(&self, terminate: bool) {
        if terminate {
            exit_now();
        }
    }

    fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>) {
        watch_sleep(Box::new(move |sleeping| {
            if !sleeping {
                on_wake()
            }
        }));
    }

    fn observe_sleep(&self, on_sleep: Box<dyn Fn() + Send + Sync>) {
        watch_sleep(Box::new(move |sleeping| {
            if sleeping {
                on_sleep()
            }
        }));
    }

    fn observe_appearance(&self, on_change: Box<dyn Fn() + Send + Sync>) {
        watch_color_scheme(on_change);
    }
}

fn watch_sleep(on: Box<dyn Fn(bool) + Send + Sync>) {
    if let Ok(bus) = crate::lin::bus::system() {
        let _ = watch_sleep_on(&bus, on);
    }
}

/// `PrepareForSleep(bool)` of logind's manager on `bus`, delivered on a thread of its own (the tests: a fake
/// logind on a private session bus; nothing ever suspends).
pub fn watch_sleep_on(bus: &Connection, on: Box<dyn Fn(bool) + Send + Sync>) -> zbus::Result<()> {
    let manager =
        Proxy::new(bus, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager")?;
    let signals = manager.receive_signal("PrepareForSleep")?;
    std::thread::Builder::new()
        .name("linvpn-sleep".into())
        .spawn(move || {
            for m in signals {
                if let Ok(sleeping) = m.body().deserialize::<bool>() {
                    on(sleeping);
                }
            }
        })
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    Ok(())
}

/// The portal's `SettingChanged` for `org.freedesktop.appearance` / `color-scheme`, on a thread of its own.
/// (Task 15's `lin::portal` reads the value; this only watches for changes.)
fn watch_color_scheme(on_change: Box<dyn Fn() + Send + Sync>) {
    let Ok(bus) = crate::lin::bus::session() else { return };
    let Ok(settings) = Proxy::new(
        &bus,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings",
    ) else {
        return;
    };
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
