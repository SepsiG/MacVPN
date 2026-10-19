//! The prompt windows (MFA `prompt-*`, credential `cred-*`, pairing `pair-*`) follow their content's height, the
//! way the menu does (`set_menu_height`): the page measures its rendered content (a `ResizeObserver`, so a retry
//! message, an error or the language's longer texts resize it too) and asks for that height with `fit_window`.
//!
//! Only the calling window is resized (by its own label: no window can resize another), only those three kinds,
//! with each kind's fixed width, and the height bounded. The window is centred on its first fit; later fits (an
//! error appearing) keep where the user put it.

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};
use tauri::WebviewWindow;

/// A prompt window's fixed width and its height bounds (points, the page's viewport: below the title bar).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FitBounds {
    pub width: f64,
    pub min: f64,
    pub max: f64,
}

pub const MFA: FitBounds = FitBounds { width: 440.0, min: 160.0, max: 800.0 };
pub const CREDENTIALS: FitBounds = FitBounds { width: 420.0, min: 200.0, max: 860.0 };
pub const PAIRING: FitBounds = FitBounds { width: 460.0, min: 240.0, max: 860.0 };

/// The bounds for a window label; `None` for every other window (the menu, Connections, …).
pub fn bounds_of(label: &str) -> Option<FitBounds> {
    if crate::prompts::is_prompt_window(label) {
        Some(MFA)
    } else if crate::credentials::is_credential_window(label) {
        Some(CREDENTIALS)
    } else if crate::pairing::is_pairing_window(label) {
        Some(PAIRING)
    } else {
        None
    }
}

/// The content size for a measured `height`: refused when not finite, otherwise clamped to the bounds (rounded
/// up to whole points).
pub fn fitted_size(bounds: FitBounds, height: f64) -> Result<(f64, f64), String> {
    if !height.is_finite() || height <= 0.0 {
        return Err("invalid height".into());
    }
    Ok((bounds.width, height.ceil().clamp(bounds.min, bounds.max)))
}

/// The windows already centred once (forgotten when they are destroyed).
static CENTRED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// True the first time for a label (until [`forget`]).
fn first_fit(label: &str) -> bool {
    CENTRED.lock().unwrap_or_else(PoisonError::into_inner).insert(label.to_string())
}

/// A prompt window is gone.
pub fn forget(label: &str) {
    CENTRED.lock().unwrap_or_else(PoisonError::into_inner).remove(label);
}

/// The calling prompt window's content height (points, as the page measured it): its own window only. The
/// window's page then gets exactly that height (the title bar is added on top: see `window_fit`).
#[tauri::command]
pub async fn fit_window(window: WebviewWindow, height: f64) -> Result<(), String> {
    let bounds = bounds_of(window.label()).ok_or("not a prompt window")?;
    let (width, height) = fitted_size(bounds, height)?;
    let center = first_fit(window.label());
    let target = window.clone();
    window
        .run_on_main_thread(move || {
            if let Ok(ns_window) = target.ns_window() {
                macvpn_platform_mac::window_fit::fit_viewport(ns_window, width, height, center);
            }
        })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_prompt_windows_fit() {
        assert_eq!(bounds_of("prompt-3"), Some(MFA));
        assert_eq!(bounds_of("cred-7"), Some(CREDENTIALS));
        assert_eq!(bounds_of("pair-2"), Some(PAIRING));
        for label in ["menu", "manage", "setup", "update", "cred-", "cred-x", "prompt-", "pair-1x", ""] {
            assert_eq!(bounds_of(label), None, "{label}");
        }
    }

    #[test]
    fn heights_are_bounded() {
        assert_eq!(fitted_size(CREDENTIALS, 431.2), Ok((420.0, 432.0)));
        assert_eq!(fitted_size(CREDENTIALS, 20.0), Ok((420.0, CREDENTIALS.min)));
        assert_eq!(fitted_size(CREDENTIALS, 5000.0), Ok((420.0, CREDENTIALS.max)));
        assert_eq!(fitted_size(MFA, 250.0), Ok((440.0, 250.0)));
        assert_eq!(fitted_size(PAIRING, 470.0), Ok((460.0, 470.0)));
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -10.0] {
            assert!(fitted_size(MFA, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn centred_on_the_first_fit_only() {
        assert!(first_fit("cred-990001"));
        assert!(!first_fit("cred-990001"));
        forget("cred-990001");
        assert!(first_fit("cred-990001"));
        forget("cred-990001");
    }
}
