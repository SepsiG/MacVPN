//! The menu bar (macOS) or notification-area (Windows) icon and the popover window anchored to it; on Linux the
//! platform's own tray icon (a StatusNotifierItem) and the popover as the card panel's overlay
//! ([`platform::menu_is_overlay`]).
//!
//! The icons are template images (black + alpha, the system tints them), rendered from the same SF Symbols as the
//! Swift app's `menuBarSymbol` by `scripts/make-tray-icons.swift`; where the system has no template images
//! (Windows), the same images are recoloured at runtime ([`WindowChrome::tray_tint`]).
//!
//! [`WindowChrome::tray_tint`]: macvpn_platform_api::WindowChrome::tray_tint

use macvpn_app_core::TrayIcon;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, LogicalSize, Manager, PhysicalPosition, PhysicalSize, Rect, WebviewWindow, WebviewWindowBuilder,
};

use crate::platform;
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
/// The popover's corner radius (points; macOS: the system popovers' and Control Center's).
pub fn menu_corner_radius() -> f64 {
    platform::get().windows().popover_corner_radius()
}

/// Where the popover sits relative to its tray icon ([`popover_position`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Below the icon (the macOS menu bar): its top edge stays when it resizes.
    Below,
    /// Above the icon (the Windows taskbar): its bottom edge stays when it resizes.
    Above,
}

/// The placement [`show_menu`] chose last (`true`: [`Placement::Above`]); below until the popover is first shown.
static MENU_ABOVE: AtomicBool = AtomicBool::new(false);

fn menu_placement() -> Placement {
    if MENU_ABOVE.load(Ordering::SeqCst) { Placement::Above } else { Placement::Below }
}

/// The popover's frame as [`resize_menu`] needs it to keep the bottom edge (physical pixels).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MenuGeometry {
    /// The outer frame: left, top, width, height.
    pub outer: (i32, i32, u32, u32),
    /// The page's (inner) height; the outer frame adds the same borders to any height.
    pub inner_height: u32,
    pub scale: f64,
    /// The top and bottom of the monitor's work area (without the taskbar), when known.
    pub work: Option<(i32, i32)>,
}

/// The outer top edge after a resize from `old_height` to `new_height` (physical pixels): unchanged below the icon
/// (the top edge stays: macOS, as before); above it the bottom edge stays, so the popover grows and shrinks upward
/// where [`popover_position`] would put it for the new size, kept inside the work area (8 px from its top).
pub fn resized_top(
    placement: Placement,
    old_top: i32,
    old_height: u32,
    new_height: u32,
    work: Option<(i32, i32)>,
) -> i32 {
    if placement == Placement::Below {
        return old_top;
    }
    let (old_height, new_height) = (i64::from(old_height), i64::from(new_height));
    let mut top = i64::from(old_top) + old_height - new_height;
    if let Some((work_top, work_bottom)) = work {
        let lowest = i64::from(work_bottom) - new_height;
        let highest = i64::from(work_top) + 8;
        top = top.min(lowest).max(highest);
    }
    i32::try_from(top).unwrap_or(old_top)
}

/// The popover window as [`create_menu_window`] and [`resize_menu`] use it (a fake in the tests).
pub trait MenuWindow {
    fn set_height(&self, height: f64) -> Result<(), String>;
    /// The current frame, for a resize that keeps the bottom edge; `None`: unknown (the top edge stays).
    fn geometry(&self) -> Option<MenuGeometry>;
    /// The new `height` (points) with the outer frame at `top` and `outer_height` high (physical pixels), in one
    /// step where the platform can.
    fn set_height_at(&self, height: f64, top: i32, outer_height: u32) -> Result<(), String>;
    /// Rounds the borderless window's corners (and recomputes its shadow), on the main thread.
    fn round_corners(&self, radius: f64);
}

impl MenuWindow for WebviewWindow {
    fn set_height(&self, height: f64) -> Result<(), String> {
        self.set_size(LogicalSize::new(MENU_WIDTH, height)).map_err(|e| e.to_string())
    }

    fn geometry(&self) -> Option<MenuGeometry> {
        let position = self.outer_position().ok()?;
        let outer = self.outer_size().ok()?;
        let inner = self.inner_size().ok()?;
        let scale = self.scale_factor().ok()?;
        let work = self.current_monitor().ok().flatten().map(|m| {
            let area = m.work_area();
            let height = i32::try_from(area.size.height).unwrap_or(i32::MAX);
            (area.position.y, area.position.y.saturating_add(height))
        });
        Some(MenuGeometry {
            outer: (position.x, position.y, outer.width, outer.height),
            inner_height: inner.height,
            scale,
            work,
        })
    }

    fn set_height_at(&self, height: f64, top: i32, outer_height: u32) -> Result<(), String> {
        let (left, width) = match (self.outer_position(), self.outer_size()) {
            (Ok(p), Ok(s)) => (p.x, s.width),
            _ => return self.set_height(height),
        };
        let target = self.clone();
        self.run_on_main_thread(move || {
            let done = platform::native_window(&target).is_some_and(|native| {
                platform::get().windows().set_outer_frame(native, left, top, width, outer_height)
            });
            if !done {
                // Two steps where the platform cannot do one.
                let _ = target.set_size(LogicalSize::new(MENU_WIDTH, height));
                let _ = target.set_position(PhysicalPosition::new(left, top));
            }
        })
        .map_err(|e| e.to_string())
    }

    fn round_corners(&self, radius: f64) {
        let target = self.clone();
        // Queued after the window's pending changes (a resize), so the shadow follows the new size.
        let _ = self.run_on_main_thread(move || {
            if let Some(native) = platform::native_window(&target) {
                platform::get().windows().round_corners(native, radius);
            }
        });
    }
}

/// Rounds the popover's corners: once created ([`create_menu_window`]) and after each resize ([`resize_menu`]).
pub fn shape_menu(window: &impl MenuWindow) {
    window.round_corners(menu_corner_radius());
}

/// The popover follows its content's height; the shadow is recomputed for the new shape. Below the icon its top
/// edge stays (macOS, as before); above it (the Windows taskbar) its bottom edge stays ([`resized_top`]).
pub fn resize_menu(window: &impl MenuWindow, height: f64, placement: Placement) -> Result<(), String> {
    match (placement, window.geometry()) {
        (Placement::Above, Some(g)) => {
            let (_, top, _, outer_height) = g.outer;
            let new_inner = (height * g.scale).round() as i64;
            let new_outer = (i64::from(outer_height) + new_inner - i64::from(g.inner_height)).max(1);
            let new_outer = u32::try_from(new_outer).unwrap_or(outer_height);
            let top = resized_top(placement, top, outer_height, new_outer, g.work);
            window.set_height_at(height, top, new_outer)?;
        }
        _ => window.set_height(height)?,
    }
    shape_menu(window);
    Ok(())
}

/// [`resize_menu`] with the placement [`show_menu`] chose last. The overlay (Linux) keeps its size (the work area):
/// the page reports the card instead ([`set_menu_card`]).
pub fn resize_shown_menu(window: &impl MenuWindow, height: f64) -> Result<(), String> {
    if platform::menu_is_overlay() {
        return Ok(());
    }
    resize_menu(window, height, menu_placement())
}

const IDLE: &[u8] = include_bytes!("../icons/tray/idle.png");
const CONNECTING: &[u8] = include_bytes!("../icons/tray/connecting.png");
const ACTIVE: &[u8] = include_bytes!("../icons/tray/active.png");
const FAILURE: &[u8] = include_bytes!("../icons/tray/failure.png");
const AUTH: &[u8] = include_bytes!("../icons/tray/auth.png");

/// The icon in the platform's colour: a template image (the system tints it: macOS), or recoloured opaque pixels
/// (Windows' notification area has no template images).
fn image(icon: TrayIcon) -> Option<Image<'static>> {
    let bytes = match icon {
        TrayIcon::Idle => IDLE,
        // Waiting for network: the same half-filled shield (its tooltip says why).
        TrayIcon::Connecting | TrayIcon::WaitingForNetwork => CONNECTING,
        TrayIcon::Active => ACTIVE,
        TrayIcon::Failure => FAILURE,
        TrayIcon::Auth => AUTH,
    };
    let image = Image::from_bytes(bytes).ok()?;
    match platform::get().windows().tray_tint() {
        None => Some(image),
        Some(rgb) => Some(Image::new_owned(tinted(image.rgba(), rgb), image.width(), image.height())),
    }
}

/// Every pixel takes `rgb`; the alpha (the shape) stays.
fn tinted(rgba: &[u8], rgb: [u8; 3]) -> Vec<u8> {
    rgba.as_chunks::<4>().0.iter().flat_map(|p| [rgb[0], rgb[1], rgb[2], p[3]]).collect()
}

/// Whether the icons are template images (the system tints them).
fn is_template() -> bool {
    platform::get().windows().tray_tint().is_none()
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
    let window = WebviewWindowBuilder::from_config(app, &config)?
        .use_https_scheme(crate::navigation::uses_https_scheme())
        .on_navigation(crate::navigation::is_allowed)
        .build()?;
    // Borderless (`decorations: false`): rounded like a system popover, through the public AppKit API (no
    // private API, no transparent webview).
    shape_menu(&window);
    // Linux: the card panel's overlay.
    platform::prepare_menu_window(&window);
    Ok(())
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let name = platform::get().product().name;
    // The platform's own tray icon (Linux): Tauri's is not built.
    if let Some(icon) = image(TrayIcon::Idle)
        && platform::create_own_tray(app, icon.rgba(), icon.width(), icon.height(), name)
    {
        return Ok(());
    }
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .icon_as_template(is_template())
        .tooltip(name)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| handle_event(tray.app_handle(), event));
    if let Some(icon) = image(TrayIcon::Idle) {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

/// The icon shown last and its tooltip ([`set_icon`]; `None`: the product name); [`redraw_icon`] draws it again.
/// Held while the icon is set, so a redraw never puts back an older icon.
static SHOWN_ICON: Mutex<(TrayIcon, Option<String>)> = Mutex::new((TrayIcon::Idle, None));

/// The icon and its tooltip (the state in the current language: [`TrayIcon::tooltip`]; the product name alone when
/// idle or failed). The publisher calls it again when either changes (a language switch changes the tooltip only).
pub fn set_icon(app: &AppHandle, icon: TrayIcon, tooltip: Option<&str>) {
    let mut shown = SHOWN_ICON.lock().unwrap_or_else(PoisonError::into_inner);
    *shown = (icon, tooltip.map(str::to_string));
    let tip = tooltip.unwrap_or(platform::get().product().name);
    if set_own_icon(icon, tip) {
        return;
    }
    apply_icon(app, icon);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(tip));
    }
}

/// The current icon again, in the platform's current colour (Windows: after a taskbar theme switch,
/// `AppLifecycle::observe_appearance`).
pub fn redraw_icon(app: &AppHandle) {
    let shown = SHOWN_ICON.lock().unwrap_or_else(PoisonError::into_inner);
    let (icon, tooltip) = &*shown;
    if set_own_icon(*icon, tooltip.as_deref().unwrap_or(platform::get().product().name)) {
        return;
    }
    apply_icon(app, *icon);
}

/// The platform's own tray icon (Linux), when there is one.
fn set_own_icon(icon: TrayIcon, tooltip: &str) -> bool {
    image(icon).is_some_and(|img| platform::set_own_tray_icon(img.rgba(), img.width(), img.height(), tooltip))
}

fn apply_icon(app: &AppHandle, icon: TrayIcon) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(image(icon));
        let _ = tray.set_icon_as_template(is_template());
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
    toggle_menu_activated(app, None);
}

/// [`toggle_menu`] from the platform's own tray (Linux: a double or middle click), with the activation token its host
/// sent for the focus.
pub(crate) fn toggle_menu_activated(app: &AppHandle, activation_token: Option<String>) {
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
    show_menu_activated(app, activation_token);
}

/// Where the popover goes (physical pixels): centred on the icon and kept 8 px inside the monitor horizontally;
/// below the icon when it is in the upper half of its monitor (the macOS menu bar: the 1.5 formula, unchanged), above
/// it otherwise (the Windows taskbar).
pub fn popover_position(
    icon: (PhysicalPosition<f64>, PhysicalSize<f64>),
    window: (f64, f64),
    monitor: Option<(PhysicalPosition<i32>, PhysicalSize<u32>)>,
) -> (i32, i32) {
    let (position, size) = icon;
    let (width, height) = window;
    let mut x = position.x + size.width / 2.0 - width / 2.0;
    let mut y = position.y + size.height + 2.0;
    if let Some((origin, extent)) = monitor {
        let left = f64::from(origin.x) + 8.0;
        let right = f64::from(origin.x) + f64::from(extent.width) - width - 8.0;
        x = x.clamp(left, right.max(left));
        if placement(position.y, monitor) == Placement::Above {
            y = (position.y - height - 2.0).max(f64::from(origin.y) + 8.0);
        }
    }
    (x.round() as i32, y.round() as i32)
}

/// Above the icon when it is in the lower half of its monitor ([`popover_position`]); below it otherwise and
/// without a monitor.
pub fn placement(icon_y: f64, monitor: Option<(PhysicalPosition<i32>, PhysicalSize<u32>)>) -> Placement {
    match monitor {
        Some((origin, extent)) if icon_y > f64::from(origin.y) + f64::from(extent.height) / 2.0 => Placement::Above,
        _ => Placement::Below,
    }
}

/// Shows the popover at the tray icon ([`popover_position`]) and refreshes the state at once (the Swift menu's
/// `.task { refresh() }`).
pub fn show_menu(app: &AppHandle) {
    show_menu_activated(app, None);
}

/// [`show_menu`] with the activation token of the platform's own tray (Linux), if it sent one. As the overlay
/// (Linux), the popover is not positioned: it covers the work area and the page draws the card at its top-right.
pub(crate) fn show_menu_activated(app: &AppHandle, activation_token: Option<String>) {
    let Some(window) = app.get_webview_window(MENU_WINDOW) else { return };
    let state = app.try_state::<Arc<AppState>>();
    let anchor = state.as_ref().and_then(|s| *s.tray_anchor.lock().unwrap_or_else(PoisonError::into_inner));
    if platform::present_menu_overlay(&window, activation_token.as_deref()) {
        MENU_ABOVE.store(false, Ordering::SeqCst);
    } else if let (Some((position, size)), Ok(window_size)) = (anchor, window.outer_size()) {
        let monitor = app.monitor_from_point(position.x, position.y).ok().flatten().map(|m| (*m.position(), *m.size()));
        let (x, y) =
            popover_position((position, size), (f64::from(window_size.width), f64::from(window_size.height)), monitor);
        MENU_ABOVE.store(placement(position.y, monitor) == Placement::Above, Ordering::SeqCst);
        let _ = window.set_position(PhysicalPosition::new(x, y));
    } else if let (Ok(window_size), Some(area)) = (window.outer_size(), current_work_area(app))
        && let Some((x, y)) = platform::corner_position(area, (window_size.width, window_size.height))
    {
        // No icon position (Linux outside the overlay): the work area's top-right corner.
        MENU_ABOVE.store(false, Ordering::SeqCst);
        let _ = window.set_position(PhysicalPosition::new(x, y));
    }
    let _ = window.show();
    MENU_SHOWN.store(true, Ordering::SeqCst);
    let _ = window.set_focus();
    if let Some(state) = state {
        state.poller.wake();
        // The Swift menu's `onAppear { loginItem.refresh() }`.
        state.inner().clone().refresh_login_item();
        // An engine installed outside the app (Terminal, by hand) shows up without "Check Again".
        crate::system::recheck_if_incomplete(state.inner());
        state.publisher.mark();
    }
}

/// The work area of the monitor under the pointer (or the primary one), physical pixels: (x, y, width, height).
fn current_work_area(app: &AppHandle) -> Option<(i32, i32, u32, u32)> {
    let monitor = app
        .cursor_position()
        .ok()
        .and_then(|p| app.monitor_from_point(p.x, p.y).ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten())?;
    let area = monitor.work_area();
    Some((area.position.x, area.position.y, area.size.width, area.size.height))
}

/// The card's rectangle as the overlay's page laid it out (CSS pixels: left, top, width, height): only the card
/// takes clicks (Linux). Nothing where the popover is no overlay.
pub fn set_menu_card(window: &WebviewWindow, card: (f64, f64, f64, f64)) -> Result<(), String> {
    if !platform::menu_is_overlay() {
        return Ok(());
    }
    let target = window.clone();
    window.run_on_main_thread(move || platform::set_menu_card(&target, card)).map_err(|e| e.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn monitor() -> Option<(PhysicalPosition<i32>, PhysicalSize<u32>)> {
        Some((PhysicalPosition::new(0, 0), PhysicalSize::new(2560, 1600)))
    }

    #[test]
    fn below_a_menu_bar_icon_exactly_as_before() {
        let icon = (PhysicalPosition::new(2000.0, 0.0), PhysicalSize::new(44.0, 48.0));
        // The 1.5 formula: x = centre − width/2 (kept on the monitor), y = icon bottom + 2.
        assert_eq!(popover_position(icon, (660.0, 720.0), monitor()), (1692, 50));
        assert_eq!(popover_position(icon, (660.0, 720.0), None), (1692, 50));
    }

    #[test]
    fn above_a_taskbar_icon_and_kept_on_the_screen() {
        let icon = (PhysicalPosition::new(2400.0, 1552.0), PhysicalSize::new(48.0, 48.0));
        assert_eq!(popover_position(icon, (660.0, 720.0), monitor()), (1892, 830));
    }

    #[test]
    fn a_tint_keeps_the_shape() {
        assert_eq!(tinted(&[0, 0, 0, 255, 0, 0, 0, 0], [255, 255, 255]), [255, 255, 255, 255, 255, 255, 255, 0]);
    }

    #[test]
    fn the_placement_follows_the_icons_half_of_the_monitor() {
        assert_eq!(placement(0.0, monitor()), Placement::Below);
        assert_eq!(placement(800.0, monitor()), Placement::Below);
        assert_eq!(placement(1552.0, monitor()), Placement::Above);
        assert_eq!(placement(1552.0, None), Placement::Below);
    }

    /// The Windows work area of `monitor()` with a 48 px taskbar at the bottom.
    const WORK: Option<(i32, i32)> = Some((0, 1552));

    #[test]
    fn below_the_icon_a_resize_keeps_the_top_edge() {
        for (old, new) in [(720, 900), (900, 720), (720, 5000)] {
            assert_eq!(resized_top(Placement::Below, 50, old, new, WORK), 50);
            assert_eq!(resized_top(Placement::Below, 50, old, new, None), 50);
        }
    }

    #[test]
    fn above_the_icon_a_resize_keeps_the_bottom_edge() {
        // Shown above a taskbar icon: bottom at 1550 (icon top 1552 − 2).
        let (top, height) = (830, 720);
        // Settings expand: it grows upward…
        assert_eq!(resized_top(Placement::Above, top, height, 1000, WORK), 550);
        // …and collapse: it shrinks back down onto the taskbar, no gap.
        assert_eq!(resized_top(Placement::Above, 550, 1000, 720, WORK), 830);
        // Exactly where popover_position puts a popover of the new size.
        let icon = (PhysicalPosition::new(2400.0, 1552.0), PhysicalSize::new(48.0, 48.0));
        assert_eq!(popover_position(icon, (660.0, 1000.0), monitor()).1, 550);
        assert_eq!(resized_top(Placement::Above, top, height, height, WORK), top);
        assert_eq!(resized_top(Placement::Above, top, height, 1000, None), 550);
    }

    #[test]
    fn above_the_icon_a_resize_stays_in_the_work_area() {
        // Taller than the space above: kept 8 px from the work area's top.
        assert_eq!(resized_top(Placement::Above, 830, 720, 1600, WORK), 8);
        // A frame that reached under the taskbar comes back above it.
        assert_eq!(resized_top(Placement::Above, 1000, 600, 600, WORK), 952);
        // A work area that does not start at 0 (a second monitor above the first).
        assert_eq!(resized_top(Placement::Above, -400, 300, 2000, Some((-1440, 0))), -1432);
    }

    #[derive(Default)]
    struct FakeWindow {
        calls: RefCell<Vec<String>>,
        fail: bool,
        geometry: Option<MenuGeometry>,
    }

    impl MenuWindow for FakeWindow {
        fn set_height(&self, height: f64) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("height {height}"));
            if self.fail { Err("gone".into()) } else { Ok(()) }
        }

        fn geometry(&self) -> Option<MenuGeometry> {
            self.geometry
        }

        fn set_height_at(&self, height: f64, top: i32, outer_height: u32) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("height {height} at {top} outer {outer_height}"));
            if self.fail { Err("gone".into()) } else { Ok(()) }
        }

        fn round_corners(&self, radius: f64) {
            self.calls.borrow_mut().push(format!("round {radius}"));
        }
    }

    /// macOS: the system popovers' radius; Windows 11: the system's rounded corners; Linux: square (L-a).
    const RADIUS: f64 = if cfg!(windows) {
        8.0
    } else if cfg!(target_os = "linux") {
        0.0
    } else {
        12.0
    };

    #[test]
    fn the_corner_radius_is_a_popovers() {
        assert_eq!(menu_corner_radius(), RADIUS);
    }

    #[test]
    fn a_new_menu_is_rounded() {
        let window = FakeWindow::default();
        shape_menu(&window);
        assert_eq!(*window.calls.borrow(), [format!("round {RADIUS}")]);
    }

    #[test]
    fn a_resize_rounds_again_after_the_new_size() {
        let window = FakeWindow::default();
        assert_eq!(resize_menu(&window, 420.0, Placement::Below), Ok(()));
        assert_eq!(*window.calls.borrow(), ["height 420".to_string(), format!("round {RADIUS}")]);
    }

    #[test]
    fn a_failed_resize_leaves_the_shape() {
        let window = FakeWindow { fail: true, ..FakeWindow::default() };
        assert!(resize_menu(&window, 420.0, Placement::Below).is_err());
        assert_eq!(*window.calls.borrow(), ["height 420"]);
    }

    /// A popover above the taskbar at 150 %: outer 1 px top + 7 px side/bottom borders around a 360 pt page.
    fn above_the_taskbar() -> MenuGeometry {
        MenuGeometry { outer: (1892, 1002, 509, 548), inner_height: 540, scale: 1.5, work: WORK }
    }

    #[test]
    fn below_the_icon_the_resize_is_as_before() {
        // macOS: the frame is not even read; only the height changes.
        let window = FakeWindow { geometry: Some(above_the_taskbar()), ..FakeWindow::default() };
        assert_eq!(resize_menu(&window, 560.0, Placement::Below), Ok(()));
        assert_eq!(*window.calls.borrow(), ["height 560".to_string(), format!("round {RADIUS}")]);
    }

    #[test]
    fn above_the_icon_the_resize_grows_upward() {
        let window = FakeWindow { geometry: Some(above_the_taskbar()), ..FakeWindow::default() };
        // 360 → 560 pt: 300 px more, the bottom edge (1550) stays.
        assert_eq!(resize_menu(&window, 560.0, Placement::Above), Ok(()));
        assert_eq!(*window.calls.borrow(), ["height 560 at 702 outer 848".to_string(), format!("round {RADIUS}")]);
        let window = FakeWindow { geometry: Some(above_the_taskbar()), ..FakeWindow::default() };
        // 360 → 200 pt: it shrinks down onto the taskbar.
        assert_eq!(resize_menu(&window, 200.0, Placement::Above), Ok(()));
        assert_eq!(*window.calls.borrow(), ["height 200 at 1242 outer 308".to_string(), format!("round {RADIUS}")]);
    }

    #[test]
    fn above_the_icon_without_a_frame_the_height_still_changes() {
        let window = FakeWindow::default();
        assert_eq!(resize_menu(&window, 420.0, Placement::Above), Ok(()));
        assert_eq!(*window.calls.borrow(), ["height 420".to_string(), format!("round {RADIUS}")]);
        let window = FakeWindow { fail: true, geometry: Some(above_the_taskbar()), ..FakeWindow::default() };
        assert!(resize_menu(&window, 420.0, Placement::Above).is_err());
        assert_eq!(window.calls.borrow().len(), 1, "no rounding after a failed resize");
    }
}
