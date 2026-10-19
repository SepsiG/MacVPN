//! MacVPN app logic without a UI: the connection manager state machine (port of `ConnectionManager.swift`), the
//! serializable view model for the Tauri UI, the MFA prompt broker, and the testable parts of the Swift
//! `AppModel` (polling, launch sequence, the quit guard, update schedule and install, the System Status window,
//! uninstall, notifications).
//!
//! Platform-independent: the system is reached only through the traits in [`deps`]; the app crate implements
//! them over `macvpn-platform-mac`.

#![forbid(unsafe_code)]

pub mod app;
pub mod connections;
pub mod deps;
pub mod editor;
pub mod import_export;
pub mod logs;
pub mod manager;
pub mod notify;
pub mod prompt;
pub mod questions;
pub mod quit;
pub mod setup;
pub mod updates;
pub mod view_model;

pub use manager::{ConnectionEvent, ConnectionItem, ConnectionManager, Dependencies, ManagerSnapshot};
pub use view_model::{LoginItemView, RowState, RowView, TrayIcon, ViewModel};
