//! LinVPN's VPNs through NetworkManager (L-b). One [`engine::Engine`] owns the state; the trait implementations
//! are split by owner task: `helper_impl` (HelperClient: OpenVPN, WireGuard, IKEv2, SSTP; Task 21), `auth`
//! (AuthStateReader; 21), `native_impl` (NativeController + NativeProfiles: L2TP, Cisco, system VPNs; 22),
//! `support_impl` (NativeSupport; 22). The building blocks: `client` (NM D-Bus; 13), `value` (plan → zvariant;
//! 13), `polkit` (13), `agent` (secret agent; 14), `sysfs` + `files` (15), `plugins` + `packagekit` (17),
//! `logd_client` + `connlog` (19), `plan_store` + `system_vpns` (22), `xfrmd_client` (IKEv2 traffic).

pub mod agent;
pub mod auth;
pub mod client;
pub mod connlog;
pub mod engine;
pub mod files;
pub mod helper_impl;
pub mod logd_client;
pub mod native_impl;
pub mod packagekit;
pub mod plan_store;
pub mod plugins;
pub mod polkit;
pub mod support_impl;
pub mod sysfs;
pub mod system_vpns;
pub mod value;
pub mod xfrmd_client;
