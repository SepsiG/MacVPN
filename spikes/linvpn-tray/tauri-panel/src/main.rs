//! LinVPN L0-2 throwaway spike: can a tray click open the card panel near the top-right corner
//! on Ubuntu GNOME (Wayland) with the Ubuntu AppIndicators extension?
//!
//! Environment switches (all optional):
//! - `TRAY=tauri|ksni`          (default ksni) which tray implementation to use
//! - `MENU=0|1`                 (default 0) give the tray a one-item menu ("Open panel")
//! - `PLACE=none|move|overlay`  (default move) how to place the panel
//!     none:    just show the window, the compositor chooses
//!     move:    set_position() to the top-right corner (or under the click for ksni Activate)
//!     overlay: a maximized transparent window with the card drawn at the top-right and the
//!              input region limited to the card
//! - `HINT=none|utility|dropdown|popup|dock|splash` (default none) GDK window type hint
//! - `TOKEN=0|1`                (default 1) use the XDG activation token of the SNI host
//! - `SHOW_AT_START=0|1`        (default 0) show the panel right away (placement test)
//! - `HIDE_ON_BLUR=0|1`         (default 1)
//!
//! Every event goes to stderr as `[ms] ...`.

use std::sync::OnceLock;
use std::time::Instant;

use gtk::prelude::*;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, LogicalPosition, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};

const W: f64 = 360.0;
const H: f64 = 420.0;
const MARGIN: f64 = 8.0;

static START: OnceLock<Instant> = OnceLock::new();

macro_rules! log {
    ($($t:tt)*) => {
        eprintln!("[{:>7}] {}", START.get().unwrap().elapsed().as_millis(), format!($($t)*))
    };
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn place() -> String {
    env("PLACE", "move")
}

/// Show or hide the panel. `click` is the SNI Activate point, `token` the XDG activation token.
fn toggle(app: &AppHandle, click: Option<(i32, i32)>, token: Option<String>) {
    let Some(win) = app.get_webview_window("panel") else { return };
    if win.is_visible().unwrap_or(false) {
        log!("toggle: hide");
        let _ = win.hide();
        return;
    }
    show(&win, click, token);
}

fn show(win: &WebviewWindow, click: Option<(i32, i32)>, token: Option<String>) {
    let gw = win.gtk_window().expect("gtk window");
    match (env("TOKEN", "1").as_str(), &token) {
        ("1", Some(t)) => {
            log!("show: set_startup_id({t})");
            gw.set_startup_id(t);
        }
        _ => log!("show: no activation token used (token={token:?})"),
    }
    // GDK's monitor geometry is in logical pixels; the work area excludes the top bar and the dock.
    let (mw, top) = gtk::gdk::Display::default()
        .and_then(|d| d.primary_monitor().or_else(|| d.monitor(0)))
        .map(|m| (m.geometry().x() as f64 + m.geometry().width() as f64, m.workarea().y() as f64))
        .unwrap_or((0.0, 0.0));
    let scale = 1.0;
    log!("show: monitor right edge {mw}, work area top {top}");
    match place().as_str() {
        "move" => {
            let (x, y) = match click {
                // Under the clicked icon, clamped to the screen.
                Some((cx, cy)) => (((cx as f64) - W / 2.0).min(mw / scale - W - MARGIN).max(MARGIN), (cy as f64 + 16.0).max(top + MARGIN)),
                None => (mw / scale - W - MARGIN, top + MARGIN),
            };
            log!("show: set_position({x}, {y}) [logical]");
            let _ = win.set_position(LogicalPosition::new(x, y));
            gw.move_(x as i32, y as i32);
        }
        "overlay" => {
            let _ = win.maximize();
        }
        _ => {}
    }
    let _ = win.show();
    let _ = win.set_focus();
    gw.present();
    if place() == "overlay" {
        set_overlay_input_region(&gw);
    }
    let w2 = win.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(600));
        let w3 = w2.clone();
        let _ = w2.run_on_main_thread(move || {
            let gw = w3.gtk_window().unwrap();
            let gdk_origin = gw.window().map(|g| g.origin());
            log!(
                "after show: tauri outer_position={:?} inner_size={:?} focused={:?} gtk position={:?} gdk origin={:?} is_active={}",
                w3.outer_position().ok(),
                w3.inner_size().ok(),
                w3.is_focused().ok(),
                gw.position(),
                gdk_origin,
                gw.is_active()
            );
            if place() == "overlay" {
                set_overlay_input_region(&gw);
            }
        });
    });
}

/// Overlay mode: only the card (top-right of the maximized window) receives input.
///
/// GtkWindow resets the input shape on every size-allocate (its CSD shape update), so the region is
/// re-applied from a size-allocate handler that runs after GTK's own one.
fn set_overlay_input_region(gw: &gtk::ApplicationWindow) {
    let Some(gdk) = gw.window() else { return };
    let w = gdk.width();
    let rect = gtk::cairo::RectangleInt::new(w - (W + MARGIN) as i32, MARGIN as i32, W as i32, H as i32);
    let region = gtk::cairo::Region::create_rectangle(&rect);
    gdk.input_shape_combine_region(&region, 0, 0);
    log!("overlay: window {}x{}, input region {:?}", w, gdk.height(), rect);
}

fn tray_png() -> tauri::image::Image<'static> {
    tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png")).expect("icon")
}

struct KTray {
    app: AppHandle,
    menu: bool,
}

impl KTray {
    fn token() -> Option<String> {
        // The token may arrive slightly after the event (ksni docs): retry briefly.
        for _ in 0..50 {
            if let Some(t) = ksni::current_xdg_activation_token() {
                return Some(t);
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        None
    }
}

impl ksni::Tray for KTray {
    fn id(&self) -> String {
        "linvpn-tray-spike".into()
    }
    fn title(&self) -> String {
        "LinVPN spike".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let img = tray_png();
        // SNI wants ARGB32 in network byte order.
        let mut data = img.rgba().to_vec();
        for px in data.chunks_exact_mut(4) {
            px.rotate_right(1);
        }
        vec![ksni::Icon { width: img.width() as i32, height: img.height() as i32, data }]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: "LinVPN spike".into(), ..Default::default() }
    }
    fn activate(&mut self, x: i32, y: i32) {
        let token = Self::token();
        log!("ksni: Activate(x={x}, y={y}) token={token:?}");
        let app = self.app.clone();
        let _ = self.app.run_on_main_thread(move || toggle(&app, Some((x, y)), token));
    }
    fn secondary_activate(&mut self, x: i32, y: i32) {
        log!("ksni: SecondaryActivate(x={x}, y={y}) token={:?}", Self::token());
    }
    fn scroll(&mut self, delta: i32, dir: ksni::Orientation) {
        log!("ksni: Scroll({delta}, {dir:?})");
    }
    fn menu_about_to_show(&mut self) {
        log!("ksni: menu about to show");
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        if !self.menu {
            return vec![];
        }
        vec![ksni::menu::StandardItem {
            label: "Open panel".into(),
            activate: Box::new(|t: &mut Self| {
                let token = Self::token();
                log!("ksni: menu item 'Open panel' token={token:?}");
                let app = t.app.clone();
                let _ = t.app.run_on_main_thread(move || toggle(&app, None, token));
            }),
            ..Default::default()
        }
        .into()]
    }
}

fn main() {
    START.set(Instant::now()).unwrap();
    let tray_kind = env("TRAY", "ksni");
    let with_menu = env("MENU", "0") == "1";
    log!(
        "start: TRAY={tray_kind} MENU={with_menu} PLACE={} HINT={} TOKEN={} GDK_BACKEND={:?} WAYLAND_DISPLAY={:?}",
        place(),
        env("HINT", "none"),
        env("TOKEN", "1"),
        std::env::var("GDK_BACKEND").ok(),
        std::env::var("WAYLAND_DISPLAY").ok()
    );
    tauri::Builder::default()
        .on_window_event(|w, e| match e {
            WindowEvent::Focused(f) => {
                log!("window {}: Focused({f})", w.label());
                if !f && env("HIDE_ON_BLUR", "1") == "1" && w.label() == "panel" {
                    log!("window panel: focus lost -> hide");
                    let _ = w.hide();
                }
            }
            WindowEvent::Moved(p) => log!("window {}: Moved({}, {})", w.label(), p.x, p.y),
            WindowEvent::Resized(s) => log!("window {}: Resized({}x{})", w.label(), s.width, s.height),
            _ => {}
        })
        .setup(move |app| {
            let p = place();
            let url = format!("index.html?tray={tray_kind}&place={p}");
            let mut b = WebviewWindowBuilder::new(app, "panel", WebviewUrl::App(url.into()))
                .title("LinVPN panel")
                .inner_size(W, H)
                .decorations(false)
                .resizable(false)
                .always_on_top(true)
                .skip_taskbar(true)
                .visible(false);
            if p == "overlay" {
                b = b.transparent(true).resizable(true).inner_size(800.0, 600.0);
            }
            let win = b.build()?;
            let gw = win.gtk_window()?;
            let hint = match env("HINT", "none").as_str() {
                "utility" => Some(gtk::gdk::WindowTypeHint::Utility),
                "dropdown" => Some(gtk::gdk::WindowTypeHint::DropdownMenu),
                "popup" => Some(gtk::gdk::WindowTypeHint::PopupMenu),
                "dock" => Some(gtk::gdk::WindowTypeHint::Dock),
                "splash" => Some(gtk::gdk::WindowTypeHint::Splashscreen),
                _ => None,
            };
            if let Some(h) = hint {
                log!("setup: type hint {h:?}");
                gw.set_type_hint(h);
            }
            gw.set_keep_above(true);
            if p == "overlay" {
                gw.connect_size_allocate(|gw, _| set_overlay_input_region(gw));
            }
            log!("setup: panel window created (hidden), backend display = {:?}", gtk::gdk::Display::default().map(|d| d.type_().name()));

            match tray_kind.as_str() {
                "tauri" => {
                    let mut tb = TrayIconBuilder::with_id("spike")
                        .icon(tray_png())
                        .tooltip("LinVPN spike (tauri tray)")
                        .on_tray_icon_event(|_t, e| log!("tauri tray: event {e:?}"))
                        .on_menu_event(|app, e| {
                            log!("tauri tray: menu event {:?}", e.id());
                            if e.id().as_ref() == "open" {
                                toggle(app, None, None);
                            }
                        });
                    if with_menu {
                        let open = MenuItem::with_id(app, "open", "Open panel", true, None::<&str>)?;
                        tb = tb.menu(&Menu::with_items(app, &[&open])?).show_menu_on_left_click(false);
                    }
                    let tray = tb.build(app)?;
                    log!("setup: tauri tray built id={:?}", tray.id());
                    app.manage(tray);
                }
                _ => {
                    use ksni::blocking::TrayMethods;
                    let handle = KTray { app: app.handle().clone(), menu: with_menu }.spawn()?;
                    log!("setup: ksni tray spawned");
                    app.manage(handle);
                }
            }
            if env("SHOW_AT_START", "0") == "1" {
                show(&win, None, None);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("tauri app")
        .run(|_app, e| {
            if let tauri::RunEvent::ExitRequested { api, .. } = e {
                api.prevent_exit();
            }
        });
}
