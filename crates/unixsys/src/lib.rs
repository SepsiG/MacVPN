//! The Unix system calls macOS and Linux share (LinVPN plan, "Resolved points"): the kernel's randomness
//! ([`random`]) and the control API's Unix socket ([`control_socket`], moved from platform-mac, LinVPN plan Task 10)
//! with its platform-api transport ([`transport`]).
//! Unix only: on Windows the crate is empty.
//!
//! `unsafe` is confined to direct libc calls with plain arguments or stack buffers whose length is passed alongside,
//! each with a `SAFETY` comment; the public API is safe.

#![cfg(unix)]
#![allow(unsafe_code)]

pub mod control_socket;
pub mod random;
pub mod transport;
