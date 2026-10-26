//! Toast notifications (WinRT) under the AppUserModelID `local.winvpn`.
//!
//! The texts are the app's generic notification texts (`macvpn_app_core::notify`): never a secret. Nothing here is
//! logged.

use crate::pure::toast;
use macvpn_platform_api::Notifier;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
use windows::core::{HSTRING, IInspectable};

/// The AppUserModelID (`Product::app_id`; also on the MSI's Start-menu shortcut). A literal: the toast identity
/// never derives from `Product`.
pub(crate) const APP_ID: &str = "local.winvpn";
const GROUP: &str = "WinVPN";
/// The shown toasts kept alive (their `Activated` handler fires only while the object lives); the oldest go first.
const KEEP: usize = 32;

type OnClick = Arc<dyn Fn(BTreeMap<String, String>) + Send + Sync>;

#[derive(Default)]
pub(crate) struct Toasts {
    on_click: Arc<Mutex<Option<OnClick>>>,
    shown: Mutex<VecDeque<(String, ToastNotification)>>,
}

/// Before any window exists (`WinPlatform::new`).
pub(crate) fn set_app_id() {
    // SAFETY: a constant string; fails only with an invalid ID.
    let _ = unsafe { SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(APP_ID)) };
}

impl Toasts {
    fn show(&self, tag: &str, title: &str, body: &str, user_info: (&str, &str)) -> windows::core::Result<()> {
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(toast::xml(title, body)))?;
        let notification = ToastNotification::CreateToastNotification(&doc)?;
        notification.SetTag(&HSTRING::from(tag))?;
        notification.SetGroup(&HSTRING::from(GROUP))?;
        let on_click = self.on_click.clone();
        let info = BTreeMap::from([(user_info.0.to_string(), user_info.1.to_string())]);
        notification.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(move |_, _| {
            let f = on_click.lock().unwrap_or_else(PoisonError::into_inner).clone();
            if let Some(f) = f {
                f(info.clone());
            }
            Ok(())
        }))?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?.Show(&notification)?;
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        shown.retain(|(t, _)| t != tag);
        if shown.len() >= KEEP {
            shown.pop_front();
        }
        shown.push_back((tag.to_string(), notification));
        Ok(())
    }
}

impl Notifier for Toasts {
    /// The click callback runs on a WinRT thread pool thread (the app's handler moves to a worker thread itself).
    fn start(&self, on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>) {
        *self.on_click.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(on_click));
    }

    /// Errors (no Start-menu shortcut in a development run, notifications turned off) are ignored, as on macOS.
    fn post(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str)) {
        let _ = self.show(&toast::tag(identifier), title, body, user_info);
    }

    fn remove_delivered(&self, identifier: &str) {
        let tag = toast::tag(identifier);
        self.shown.lock().unwrap_or_else(PoisonError::into_inner).retain(|(t, _)| *t != tag);
        if let Ok(history) = ToastNotificationManager::History() {
            let _ = history.RemoveGroupedTagWithId(&HSTRING::from(tag), &HSTRING::from(GROUP), &HSTRING::from(APP_ID));
        }
    }
}
