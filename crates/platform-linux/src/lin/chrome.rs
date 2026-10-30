//! Window sizes through GTK. `NativeWindow` is the `GtkWindow *` the app passes (`gtk_window().as_ptr()`, Task 18).
//! Square corners on Linux (LinVPN plan, "Resolved points"); the tray icon is drawn white (GNOME's top bar is dark
//! in both themes); the light/dark setting comes from the portal (GTK 3 and WebKitGTK do not follow it).

use gtk::prelude::{GtkWindowExt, WidgetExt};
use macvpn_platform_api::{NativeWindow, WindowChrome};

pub struct Chrome;

fn window(w: NativeWindow) -> Option<gtk::Window> {
    if w.0.is_null() {
        return None;
    }
    use glib::translate::FromGlibPtrNone;
    // SAFETY: the app passes the pointer of a live GtkWindow on the main thread (the trait's contract); a new
    // reference is taken (`from_glib_none`) and dropped at the end of the call.
    Some(unsafe { gtk::Window::from_glib_none(w.0 as *mut gtk::ffi::GtkWindow) })
}

impl WindowChrome for Chrome {
    fn popover_corner_radius(&self) -> f64 {
        0.0
    }

    fn round_corners(&self, _w: NativeWindow, _radius: f64) -> bool {
        false
    }

    /// GTK sizes a window that is not resizable (the prompt and vault windows: Tauri's `resizable(false)`) from its
    /// default size, and ignores `resize` for it: the default size changes with it.
    fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64> {
        let window = window(w)?;
        let height = viewport.ceil();
        let (width, height_px) = (width.round() as i32, height as i32);
        if !window.is_resizable() {
            window.set_default_size(width, height_px);
        }
        window.resize(width, height_px);
        if center {
            window.set_position(gtk::WindowPosition::Center);
        }
        Some(height)
    }

    /// The window is built hidden (`visible(false)`), and so are the box and the web view Tauri put in it: `present`
    /// alone would map an empty window (GTK maps only shown children), so they are shown first.
    fn order_front_regardless(&self, w: NativeWindow) {
        if let Some(window) = window(w) {
            window.show_all();
            window.present();
        }
    }

    fn tray_tint(&self) -> Option<[u8; 3]> {
        Some([0xff, 0xff, 0xff])
    }

    fn system_dark(&self) -> Option<bool> {
        crate::lin::portal::system_dark()
    }
}
