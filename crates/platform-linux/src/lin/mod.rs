//! The Linux implementation (Linux only). Each module's `unsafe` blocks carry a `SAFETY` comment.

// The D-Bus connections: their first callers are the later L-a tasks (Secret Service, notifications, the portal).
#[allow(dead_code)]
pub mod bus;
pub mod chrome;
pub mod clipboard;
pub mod command;
pub mod control;
pub mod curl_runner;
pub mod instance;
pub mod keystore;
pub mod lifecycle;
pub mod login_item;
pub mod net;
pub mod nm;
pub mod notify;
pub mod package_watch;
pub mod pkcs12;
pub mod platform;
pub mod portal;
pub mod shell;
pub mod supervisor;
pub mod system;
pub mod tray;
pub mod updater;
pub mod xattr;
