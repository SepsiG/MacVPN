//! MacVPN app logic without a UI: the connection manager state machine (port of `ConnectionManager.swift`), the
//! serializable view model for the Tauri UI, the MFA prompt broker, and the testable parts of the Swift
//! `AppModel` (polling, launch sequence, the quit guard, update schedule and install, the System Status window,
//! uninstall, notifications).
//!
//! Platform-independent: the system is reached only through the traits in [`deps`]; the app crate implements
//! them over `macvpn-platform-mac`.

#![forbid(unsafe_code)]

pub mod app;
pub mod backup;
pub mod catalog;
pub mod catalog_file;
pub mod catalog_publish;
pub mod catalog_schedule;
pub mod connections;
pub mod control;
pub mod credential_prompt;
pub mod deps;
pub mod editor;
pub mod folders;
pub mod import_export;
pub mod live;
pub mod logs;
pub mod manager;
pub mod migration;
pub mod notify;
pub mod open_files;
pub mod pairing;
pub mod prompt;
pub mod questions;
pub mod quit;
pub mod setup;
pub mod shared_credentials;
pub mod updates;
pub mod vault;
pub mod vault_setup;
pub mod vault_stores;
pub mod view_model;

pub use manager::{ConnectionEvent, ConnectionItem, ConnectionManager, Dependencies, DisconnectCause, ManagerSnapshot};
pub use view_model::{LoginItemView, RowState, RowView, TrayIcon, ViewModel};
