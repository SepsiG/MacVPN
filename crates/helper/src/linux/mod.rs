//! The Linux backend of the helper: no `mvpn` (LinVPN drives NetworkManager), LinVPN's root update step
//! ([`install_update`]), the journal reader `linvpn-logd` ([`logd`], not root; L-b Task 18) and the IKEv2 traffic
//! counter reader `linvpn-xfrmd` ([`xfrmd`], not root, `CAP_NET_ADMIN` only). Linux only: elsewhere this module is
//! empty.

#![cfg(target_os = "linux")]

pub mod install_update;
pub mod logd;
pub mod xfrmd;
