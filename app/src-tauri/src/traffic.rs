//! Live traffic (maintainer request 2026-10-29): the connected tunnels' bytes received and sent since the
//! connection came up, and the current rate, next to the address and the connected time (the menu's cards and the
//! Connections window's detail header). The logic is `macvpn_app_core::traffic`; the platform reads the counters
//! (`HelperClient::traffic`, `NativeController::traffic`) as the user, never through the root layer or the
//! service.
//!
//! The readings: about once a second while a window that shows them is open (the `get_traffic` command the menu
//! and the Connections window call while visible; two windows share one round), and once per status poll otherwise
//! (every 3 s while a connection is active: one cheap counter read per tunnel, no process, no window work), so a
//! counter restart while nothing is shown still keeps the totals. Nothing is read without an active connection.

use macvpn_app_core::manager::TunnelSource;
use macvpn_app_core::traffic::{TrafficBook, texts};
use macvpn_platform_api::HelperTunnel;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

use crate::state::AppState;

/// A shown window's rounds are at least this far apart (seconds): about one per second, shared by two windows.
const SHOWN_GAP: f64 = 0.8;

/// The traffic sessions.
#[derive(Default)]
pub struct TrafficApp {
    book: Mutex<TrafficBook>,
}

impl TrafficApp {
    fn book(&self) -> std::sync::MutexGuard<'_, TrafficBook> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A fresh connect (the user's or the control API's, not an auto-reconnect): the key's totals start again.
    pub fn restart(&self, key: &str) {
        self.book().restart(key);
    }
}

/// The wall clock in Unix seconds (after a sleep the gap is real, so no rate spikes over it).
fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// One round of readings: every connected tunnel's counters, read without the book's lock (the manager's
/// listeners take it under the manager's lock).
pub fn sample(state: &AppState) {
    let tunnels = state.manager.tunnels();
    if tunnels.is_empty() {
        return;
    }
    let readings: Vec<_> = tunnels
        .iter()
        .filter_map(|t| {
            let reading = match &t.source {
                TunnelSource::Helper { id, kind, iface, ip, since } => state.helper.traffic(&HelperTunnel {
                    id,
                    kind: *kind,
                    iface: iface.as_deref(),
                    ip: ip.as_deref(),
                    since: *since,
                }),
                TunnelSource::Native { service_id } => state.manager.native_traffic(service_id),
            };
            reading.map(|r| (t.key.clone(), r))
        })
        .collect();
    // Deleted connections and vanished system VPNs go (a reconnecting one keeps its session).
    let known: Vec<String> = state
        .manager
        .connections()
        .iter()
        .map(|c| macvpn_core::models::uuid_string(&c.id))
        .chain(state.manager.system_services().into_iter().map(|s| s.id))
        .collect();
    let at = now();
    let mut book = state.traffic.book();
    for (key, r) in readings {
        book.observe(&key, at, r);
    }
    book.retain(&known.iter().map(String::as_str).collect::<Vec<_>>());
    book.sampled(at);
}

/// One row's traffic as the UI shows it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficView {
    /// "↓ 12.4 MB  ↑ 1.2 MB".
    pub totals: String,
    /// "↓ 350 kB/s  ↑ 20.0 kB/s"; `null` until a rate is known.
    pub rates: Option<String>,
    /// The whole in words (tooltip, accessible label).
    pub tooltip: String,
}

/// The connected rows' traffic by key; a row without readings (or whose counters never moved) is left out.
pub fn view(state: &AppState) -> HashMap<String, TrafficView> {
    let at = now();
    let keys: Vec<String> = state.manager.tunnels().into_iter().map(|t| t.key).collect();
    let book = state.traffic.book();
    keys.into_iter()
        .filter_map(|key| {
            let t = book.get(&key, at)?;
            let text = texts(&t);
            Some((key, TrafficView { totals: text.totals, rates: text.rates, tooltip: text.tooltip }))
        })
        .collect()
}

/// Read-only, no input: the connected rows' traffic. A round of readings first when a window that shows it is
/// open and the last round is older than [`SHOWN_GAP`]; a hidden window's call reads nothing.
#[tauri::command]
pub async fn get_traffic(state: State<'_, Arc<AppState>>) -> Result<HashMap<String, TrafficView>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let shown = crate::tray::menu_shown() || crate::dock::windows_shown();
        if shown && state.traffic.book().due(now(), SHOWN_GAP) {
            sample(&state);
        }
        view(&state)
    })
    .await
    .map_err(|e| e.to_string())
}
