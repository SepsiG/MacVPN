//! The tray icon as an own StatusNotifierItem (ksni; spike L0-2, variant S, CP-L0). `ItemIsMenu = false`, so the host
//! sends `Activate` (GNOME's AppIndicator extension: a double click; KDE: a single click) and `SecondaryActivate` (a
//! middle click): both toggle the panel. A single left or right click on GNOME shows the menu (the host's behaviour):
//! "Open LinVPN" first (it only shows the panel), then "Quit LinVPN". The icon is ARGB32 (big-endian), as the SNI
//! spec wants; the labels are translated each time the host asks for the menu ([`SniTray::refresh`] after a language
//! change).
//!
//! The host sends `ProvideXdgActivationToken` before each activation and menu click; the event carries that token so
//! the app can pass it to GTK (`gtk_window_set_startup_id`) before presenting the panel. ksni runs on zbus' own
//! executor (`async-io`, no tokio): the callback runs there, so it must only hand the event to the app's main thread.

use crate::pure::pixels::argb;
use macvpn_core::l10n;

/// What a click on the tray asks the app to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayEvent {
    /// `Activate` or `SecondaryActivate`: hide the panel when it is visible, else show it. `at` is the pointer in the
    /// shell's global logical pixels (a hint only; the panel goes to the top-right corner).
    Toggle { at: (i32, i32), token: Option<String> },
    /// The menu's "Open LinVPN": show the panel (never hides it).
    Open { token: Option<String> },
    /// The menu's "Quit LinVPN".
    Quit,
}

type OnEvent = Box<dyn Fn(TrayEvent) + Send>;

struct Item {
    icon: ksni::Icon,
    tooltip: String,
    on_event: OnEvent,
}

impl Item {
    fn toggle(&self, x: i32, y: i32) {
        (self.on_event)(TrayEvent::Toggle { at: (x, y), token: ksni::current_xdg_activation_token() });
    }
}

impl ksni::Tray for Item {
    const MENU_ON_ACTIVATE: bool = false;

    fn id(&self) -> String {
        "linvpn".into()
    }
    fn title(&self) -> String {
        "LinVPN".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![self.icon.clone()]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: self.tooltip.clone(), ..Default::default() }
    }
    fn activate(&mut self, x: i32, y: i32) {
        self.toggle(x, y);
    }
    fn secondary_activate(&mut self, x: i32, y: i32) {
        self.toggle(x, y);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            ksni::menu::StandardItem {
                label: l10n::tr("Open LinVPN", &[]),
                activate: Box::new(|item: &mut Item| {
                    (item.on_event)(TrayEvent::Open { token: ksni::current_xdg_activation_token() })
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            ksni::menu::StandardItem {
                label: l10n::tr("Quit LinVPN", &[]),
                activate: Box::new(|item: &mut Item| (item.on_event)(TrayEvent::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn icon(rgba: &[u8], width: u32, height: u32) -> ksni::Icon {
    debug_assert_eq!(rgba.len() as u64, u64::from(width) * u64::from(height) * 4, "RGBA of width × height");
    ksni::Icon { width: width as i32, height: height as i32, data: argb(rgba) }
}

/// The running tray item; dropping it removes the icon.
pub struct SniTray(ksni::blocking::Handle<Item>);

impl SniTray {
    /// Registers the item with the session's `StatusNotifierWatcher`. A watcher that is not there yet (LinVPN started
    /// at login before the shell's extension) is not an error: ksni registers when it appears.
    pub fn spawn(
        rgba: &[u8],
        width: u32,
        height: u32,
        tooltip: &str,
        on_event: impl Fn(TrayEvent) + Send + 'static,
    ) -> Result<SniTray, String> {
        let item = Item { icon: icon(rgba, width, height), tooltip: tooltip.into(), on_event: Box::new(on_event) };
        ksni::blocking::TrayMethods::assume_sni_available(item, true).spawn().map(SniTray).map_err(|e| e.to_string())
    }

    /// The state's icon (RGBA, `width` × `height`) and tooltip.
    pub fn set_icon(&self, rgba: &[u8], width: u32, height: u32, tooltip: &str) {
        let icon = icon(rgba, width, height);
        let tooltip = tooltip.to_string();
        self.0.update(move |item| {
            item.icon = icon;
            item.tooltip = tooltip;
        });
    }

    /// Re-sends the menu (its labels in the current language).
    pub fn refresh(&self) {
        self.0.update(|_| {});
    }
}

impl SniTray {
    /// Removes the icon and waits until the item has left the bus (never from inside the event callback, which runs
    /// on the item's own executor).
    pub fn shutdown(self) {
        self.0.shutdown().wait();
    }
}

impl Drop for SniTray {
    fn drop(&mut self) {
        // The service thread ends on its own; nothing to wait for.
        drop(self.0.shutdown());
    }
}
