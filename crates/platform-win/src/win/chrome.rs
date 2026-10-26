//! Window shape and placement, and the tray icon's colour.

use super::registry;
use macvpn_platform_api::{NativeWindow, WindowChrome};
use windows_sys::Win32::Foundation::{HWND, RECT};
#[cfg(debug_assertions)]
use windows_sys::Win32::Graphics::Dwm::DwmGetWindowAttribute;
use windows_sys::Win32::Graphics::Dwm::{DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWL_EXSTYLE, GWL_STYLE, GetWindowLongPtrW, GetWindowRect, HWND_NOTOPMOST, HWND_TOPMOST, SW_SHOWNORMAL,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SetForegroundWindow, SetWindowPos,
    ShowWindow,
};

const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

pub(crate) struct Chrome;

fn hwnd(w: NativeWindow) -> Option<HWND> {
    (!w.0.is_null()).then_some(w.0)
}

/// White on a dark taskbar (also when the value is missing: Windows' default), black on a light one.
fn tint_for(system_uses_light_theme: Option<u32>) -> [u8; 3] {
    if system_uses_light_theme == Some(1) { [0, 0, 0] } else { [255, 255, 255] }
}

/// Debug builds (the smoke run): whether DWM holds the round-corner preference [`Chrome::round_corners`] set on `w`
/// (Windows 10 has no such attribute: `false`).
#[cfg(debug_assertions)]
pub(crate) fn corners_round(w: NativeWindow) -> bool {
    let Some(h) = hwnd(w) else { return false };
    let mut preference: i32 = -1;
    // SAFETY: a window handle and a 4-byte out value that outlives the call.
    let hr = unsafe {
        DwmGetWindowAttribute(
            h,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            (&raw mut preference).cast(),
            size_of::<i32>() as u32,
        )
    };
    hr >= 0 && preference == DWMWCP_ROUND
}

impl WindowChrome for Chrome {
    /// Windows 11's window corner radius.
    fn popover_corner_radius(&self) -> f64 {
        8.0
    }

    /// Every window (the popover, Connections, System Status, the vault and prompt windows): Windows 11's round
    /// corners, asked for explicitly.
    fn window_corner_radius(&self) -> Option<f64> {
        Some(8.0)
    }

    /// Windows 11 rounds through DWM; Windows 10 has no rounded corners (`false`).
    fn round_corners(&self, w: NativeWindow, _radius: f64) -> bool {
        let Some(h) = hwnd(w) else { return false };
        let preference = DWMWCP_ROUND;
        // SAFETY: a window handle and a 4-byte attribute value that outlives the call.
        let hr = unsafe {
            DwmSetWindowAttribute(
                h,
                DWMWA_WINDOW_CORNER_PREFERENCE as u32,
                (&raw const preference).cast(),
                size_of::<i32>() as u32,
            )
        };
        hr >= 0
    }

    /// The client area becomes `width` × `viewport` (logical pixels, scaled by the window's DPI), at most the
    /// monitor's work area high; returns the logical client height set.
    fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64> {
        let h = hwnd(w)?;
        // SAFETY: a window handle; plain data out parameters.
        unsafe {
            let dpi = GetDpiForWindow(h);
            if dpi == 0 {
                return None;
            }
            let scale = f64::from(dpi) / 96.0;
            let (client_w, client_h) = ((width * scale).round() as i32, (viewport * scale).round() as i32);
            let mut frame = RECT { left: 0, top: 0, right: client_w, bottom: client_h };
            let style = GetWindowLongPtrW(h, GWL_STYLE) as u32;
            let ex_style = GetWindowLongPtrW(h, GWL_EXSTYLE) as u32;
            if AdjustWindowRectExForDpi(&mut frame, style, 0, ex_style, dpi) == 0 {
                return None;
            }
            let (outer_w, outer_h) = (frame.right - frame.left, frame.bottom - frame.top);
            let mut info: MONITORINFO = std::mem::zeroed();
            info.cbSize = size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST), &mut info) == 0 {
                return None;
            }
            let work = info.rcWork;
            let height = outer_h.min(work.bottom - work.top);
            let mut current = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            if GetWindowRect(h, &mut current) == 0 {
                return None;
            }
            let (x, y) = if center {
                (
                    work.left + ((work.right - work.left) - outer_w) / 2,
                    work.top + ((work.bottom - work.top) - height) / 2,
                )
            } else {
                (current.left, current.top.clamp(work.top, (work.bottom - height).max(work.top)))
            };
            if SetWindowPos(h, std::ptr::null_mut(), x, y, outer_w, height, SWP_NOZORDER | SWP_NOACTIVATE) == 0 {
                return None;
            }
            Some(f64::from(height - (outer_h - client_h)) / scale)
        }
    }

    fn set_outer_frame(&self, w: NativeWindow, x: i32, y: i32, width: u32, height: u32) -> bool {
        let Some(h) = hwnd(w) else { return false };
        let (Ok(width), Ok(height)) = (i32::try_from(width), i32::try_from(height)) else { return false };
        // SAFETY: a window handle; one move and resize, without changing the z-order or the focus.
        unsafe { SetWindowPos(h, std::ptr::null_mut(), x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE) != 0 }
    }

    fn order_front_regardless(&self, w: NativeWindow) {
        let Some(h) = hwnd(w) else { return };
        // SAFETY: a window handle; the topmost toggle brings it above other apps without keeping it there.
        unsafe {
            ShowWindow(h, SW_SHOWNORMAL);
            SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            SetForegroundWindow(h);
        }
    }

    /// Read again on every call (the user may switch the taskbar's theme while WinVPN runs).
    fn tray_tint(&self) -> Option<[u8; 3]> {
        Some(tint_for(registry::read_dword(PERSONALIZE, "SystemUsesLightTheme")))
    }
}
