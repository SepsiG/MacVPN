//! Helpers shared by the Windows integration tests (each test crate uses a part of them).
#![allow(dead_code)]

#[cfg(all(windows, debug_assertions))]
pub mod console;
