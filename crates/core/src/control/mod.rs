//! The local control API (spec `2026-10-19-control-api-design.md`): another local program of the same user pairs
//! with MacVPN over a Unix socket, lists its allowed connections and holds one up through a socket lease.
//!
//! This module is the platform-independent part: the wire protocol, the paired-client registry and the lease
//! table. The socket and the peer identity live in `platform-mac`, the server loop in `app-core`.

pub mod lease;
pub mod protocol;
pub mod registry;
