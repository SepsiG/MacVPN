//! The helper's logic that every operating system shares: no `cfg`, no `unsafe`, no process or file I/O (the
//! backends read stdin, files and sockets and hand the bytes or streams here).

pub mod bridge;
pub mod cli;
pub mod framing;
pub mod l10n;
pub mod limits;
pub mod mask;
pub mod ovpn_log;
pub mod respond;
pub mod status_json;
pub mod validate;
