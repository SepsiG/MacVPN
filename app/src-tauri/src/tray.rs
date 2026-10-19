//! The menu bar icon and the popover window anchored to it.
//!
//! The icons are template images (black + alpha, the system tints them), rendered from the same SF Symbols as the
//! Swift app's `menuBarSymbol` by `scripts/make-tray-icons.swift`.

use macvpn_app_core::TrayIcon;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, PhysicalPosition, Rect, WebviewWindowBuilder};

use crate::state::AppState;

pub const TRAY_ID: &str = "main";
pub const MENU_WINDOW: &str = "menu";
/// Whether the popover is shown, kept by [`show_menu`] and [`hide_menu`] (read by the poller without a main
/// thread round trip).
static MENU_SHOWN: AtomicBool = AtomicBool::new(false);

pub fn menu_shown() -> bool {
    MENU_SHOWN.load(Ordering::SeqCst)
}

/// Hides the popover (every hide goes through here, so [`menu_shown`] stays true to the window).
pub fn hide_menu(app: &AppHandle) {
    MENU_SHOWN.store(false, Ordering::SeqCst);
    if let Some(window) = app.get_webview_window(MENU_WINDOW) {
        let _ = window.hide();
    }
}

/// The popover's width (points); its height follows the content (`set_menu_height`).
pub const MENU_WIDTH: f64 = 330.0;

const IDLE: &[u8] = include_bytes!("../icons/tray/idle.png");
const ACTIVE: &[u8] = include_bytes!("../icons/tray/active.png");
const FAILURE: &[u8] = include_bytes!("../icons/tray/failure.png");
const AUTH: &[u8] = include_bytes!("../icons/tray/auth.png");

fn image(icon: TrayIcon) -> Option<Image<'static>> {
    let bytes = match icon {
        TrayIcon::Idle => IDLE,
        TrayIcon::Active => ACTIVE,
        TrayIcon::Failure => FAILURE,
        TrayIcon::Auth => AUTH,
    };
    Image::from_bytes(bytes).ok()
}

/// The popover window, from its entry in tauri.conf.json (`"create": false` there, so that it gets the navigation
/// allowlist like every other window).
pub fn create_menu_window(app: &AppHandle) -> tauri::Result<()> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MENU_WINDOW)
        .cloned()
        .ok_or_else(|| tauri::Error::WindowNotFound)?;
    WebviewWindowBuilder::from_config(app, &config)?.on_navigation(crate::navigation::is_allowed).build()?;
    Ok(())
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .icon_as_template(true)
        .tooltip("MacVPN")
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| handle_event(tray.app_handle(), event));
    if let Some(icon) = image(TrayIcon::Idle) {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

pub fn set_icon(app: &AppHandle, icon: TrayIcon) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(image(icon));
        let _ = tray.set_icon_as_template(true);
    }
}

fn remember_anchor(app: &AppHandle, rect: &Rect) {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return };
    let scale = app.get_webview_window(MENU_WINDOW).and_then(|w| w.scale_factor().ok()).unwrap_or(2.0);
    let anchor = (rect.position.to_physical::<f64>(scale), rect.size.to_physical::<f64>(scale));
    *state.tray_anchor.lock().unwrap_or_else(PoisonError::into_inner) = Some(anchor);
}

fn handle_event(app: &AppHandle, event: TrayIconEvent) {
    match event {
        TrayIconEvent::Click { rect, button: MouseButton::Left, button_state: MouseButtonState::Up, .. } => {
            remember_anchor(app, &rect);
            toggle_menu(app);
        }
        TrayIconEvent::Enter { rect, .. } | TrayIconEvent::Move { rect, .. } => remember_anchor(app, &rect),
        _ => {}
    }
}

/// A click on the icon while the popover is open first takes its focus away (hiding it): that click must not
/// open it again.
const BLUR_CLICK_WINDOW: Duration = Duration::from_millis(300);

fn toggle_menu(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MENU_WINDOW) else { return };
    if window.is_visible().unwrap_or(false) {
        hide_menu(app);
        return;
    }
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        let hidden = *state.hidden_on_blur.lock().unwrap_or_else(PoisonError::into_inner);
        if hidden.is_some_and(|t| t.elapsed() < BLUR_CLICK_WINDOW) {
            return;
        }
    }
    show_menu(app);
}

/// Shows the popover below the tray icon (centred on it, kept on the screen) and refreshes the state at once
/// (the Swift menu's `.task { refresh() }`).
pub fn show_menu(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MENU_WINDOW) else { return };
    let state = app.try_state::<Arc<AppState>>();
    let anchor = state.as_ref().and_then(|s| *s.tray_anchor.lock().unwrap_or_else(PoisonError::into_inner));
    if let (Some((position, size)), Ok(window_size)) = (anchor, window.outer_size()) {
        let width = f64::from(window_size.width);
        let mut x = position.x + size.width / 2.0 - width / 2.0;
        let y = position.y + size.height + 2.0;
        if let Ok(Some(monitor)) = app.monitor_from_point(position.x, position.y) {
            let left = f64::from(monitor.position().x) + 8.0;
            let right = f64::from(monitor.position().x) + f64::from(monitor.size().width) - width - 8.0;
            x = x.clamp(left, right.max(left));
        }
        let _ = window.set_position(PhysicalPosition::new(x.round() as i32, y.round() as i32));
    }
    let _ = window.show();
    MENU_SHOWN.store(true, Ordering::SeqCst);
    let _ = window.set_focus();
    if let Some(state) = state {
        state.poller.wake();
        // The Swift menu's `onAppear { loginItem.refresh() }`.
        state.inner().clone().refresh_login_item();
        state.publisher.mark();
    }
}

/// The popover lost the focus: it hides (like a menu).
pub fn hide_on_blur(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MENU_WINDOW) {
        if window.is_visible().unwrap_or(false)
            && let Some(state) = app.try_state::<Arc<AppState>>()
        {
            *state.hidden_on_blur.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        }
        hide_menu(app);
    }
}
