//! The control API's Unix socket: moved to `macvpn-unixsys` (shared with Linux, LinVPN plan Task 10), re-exported
//! here so every caller keeps its path. The macOS behaviour is unchanged (its tests moved with it:
//! `crates/unixsys/tests/control_socket*.rs`).

pub use macvpn_unixsys::control_socket::*;
