//! Team catalogs (spec `2026-10-19-team-catalog-design.md`): an administrator publishes connections, their folder
//! tree, credential slots and optional team secrets as one signed and encrypted `<name>.macvpncatalog` file, and
//! every subscribed MacVPN applies it.
//!
//! This module is the platform-independent part: the keys ([`keys`]), the payload with its validation
//! ([`payload`]) and the signed and encrypted file ([`format`]), the sources ([`source`]) and the subscription
//! string ([`subscription`]), the namespaced local ids ([`ids`]), the publish selection ([`selection`]), the
//! apply/diff planner ([`planner`]), the publish builder ([`publish`]) and the admin key file ([`admin_file`]).
//! The vault side (schema v2, the repositories and the executor) lives in [`crate::vault`]. Compiled only with the `vault` feature, which the root layer (`mvpn`) never enables. No
//! `unsafe`; randomness comes in through [`crate::vault::Entropy`]. Nothing in here logs or formats key material.

pub mod admin_file;
pub mod fetch;
pub mod format;
pub mod ids;
pub mod keys;
pub mod payload;
pub mod planner;
pub mod publish;
pub mod selection;
pub mod source;
pub mod subscription;
