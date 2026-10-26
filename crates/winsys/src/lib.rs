//! The few Win32 calls that MacVPN's core (`fsx`) and the Windows platform both need, behind safe functions:
//! SIDs, security descriptors (the private and shared DACLs), what an open handle says about its file (owner, DACL
//! shape, 128-bit id, link count, reparse tag), the system CSPRNG and named pipes (the peer's identity, exact
//! timeouts, clean shutdown), a named mutex with a private DACL, a service's recovery settings, an MSI package's
//! properties ([`msi`]), the machine's user profiles ([`profiles`]) and the Remote Access Service (VPN phonebook entries, dialling, the RAS credential store:
//! [`ras`]).
//!
//! Its own crate because core may not contain `unsafe` and cannot depend on `macvpn-platform-win` (which depends on
//! core). It depends on nothing but `windows-sys` and knows nothing of MacVPN. Windows only: on every other target
//! this crate is empty. Every `unsafe` block says why it is sound.

#![cfg(windows)]
// The crate exists to make these calls (crates/app-core/tests/cfg_rule.rs lists it).
#![allow(unsafe_code)]

pub mod acl_check;
pub mod cert_store;
pub mod dll;
pub mod file;
pub mod known;
pub mod msi;
pub mod mutex;
pub mod net;
pub mod pipe;
pub mod profiles;
pub mod random;
pub mod ras;
pub mod scm;
mod security;
pub mod sid;
pub mod trust;
mod util;
pub mod version;
