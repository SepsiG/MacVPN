//! The card panel's place: the top-right corner of the work area (physical pixels), 8 px in from the right edge and
//! below the top (GNOME's top bar is outside the work area), never left of the work area. On Wayland the panel is a
//! transparent maximized overlay (spike L0-2, CP-L0): the work area is then the overlay itself and this is the card's
//! offset inside it; on the Xwayland fallback it is the window's position.

/// `work_area` = (x, y, width, height), `panel` = (width, height); returns the panel's top-left corner.
pub fn panel_position(work_area: (i32, i32, u32, u32), panel: (u32, u32)) -> (i32, i32) {
    let (x, y, width, _) = work_area;
    let left = x.saturating_add_unsigned(width).saturating_sub_unsigned(panel.0).saturating_sub(8);
    (left.max(x), y.saturating_add(8))
}

/// The card's size before the page has reported its own (the popover's size in `tauri.conf.json`, logical pixels).
pub const DEFAULT_CARD: (u32, u32) = (330, 360);

/// The overlay's input region (spike L0-2: only the card takes clicks; the rest passes through): the card's
/// rectangle as the page reported it (`card` = left, top, width, height in CSS pixels, which are the GDK window's
/// logical pixels), rounded outward and kept inside the `window` (width, height); without a usable report, the
/// [`DEFAULT_CARD`] at [`panel_position`] inside the window. Returns (x, y, width, height).
pub fn card_input_rect(window: (u32, u32), card: Option<(f64, f64, f64, f64)>) -> (i32, i32, i32, i32) {
    let (window_width, window_height) = (f64::from(window.0), f64::from(window.1));
    let usable = card.filter(|&(x, y, w, h)| [x, y, w, h].iter().all(|v| v.is_finite()) && w >= 0.0 && h >= 0.0);
    let (left, top, right, bottom) = match usable {
        Some((x, y, w, h)) => (x.floor(), y.floor(), (x + w).ceil(), (y + h).ceil()),
        None => {
            let (x, y) = panel_position((0, 0, window.0, window.1), DEFAULT_CARD);
            let (x, y) = (f64::from(x), f64::from(y));
            (x, y, x + f64::from(DEFAULT_CARD.0), y + f64::from(DEFAULT_CARD.1))
        }
    };
    let clamp = |v: f64, max: f64| v.clamp(0.0, max);
    let (left, right) = (clamp(left, window_width), clamp(right, window_width));
    let (top, bottom) = (clamp(top, window_height), clamp(bottom, window_height));
    // Every value is inside 0…u32::MAX after the clamps.
    let px = |v: f64| v as i32;
    (px(left), px(top), px(right.max(left) - left), px(bottom.max(top) - top))
}
