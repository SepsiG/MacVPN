//! MacVPN core: platform-independent logic shared by the app and the root layer.
//!
//! No macOS API and no `unsafe` code may be used here (see the port spec, section 2). The reference
//! implementation is the Swift `MacVPNCore` (0.4.0); behaviour, messages and file formats are ported exactly.

#![forbid(unsafe_code)]

pub mod collation;
pub mod control;
pub mod credentials;
pub mod date;
pub mod exporter;
pub mod importer;
pub mod l10n;
pub mod log;
pub mod management;
pub mod mfa;
pub mod mobileconfig;
pub mod models;
pub mod native;
pub mod plist_xml;
pub mod ranking;
pub mod status;
pub mod store;
pub mod swift_base64;
pub mod swift_json;
pub mod swift_str;
pub mod system_otp;
pub mod update;
pub mod url;
pub mod validators;
#[cfg(feature = "vault")]
pub mod vault;

/// The MacVPN version this crate belongs to.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
