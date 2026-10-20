//! What an administrator selected for a publication (spec 7, steps 1–3): plain data, stored in the publication
//! record (`catalog_publications.json`) and used by the publish builder ([`super::publish`]).

use crate::exporter;
use crate::models::{SecretField, VPNKind};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublishSelection {
    /// The publisher's folders (each with its subtree).
    pub folders: BTreeSet<Uuid>,
    /// The publisher's connections.
    pub connections: BTreeSet<Uuid>,
    /// The ticked team secrets: (connection, field), only PSKs and key passwords.
    pub secrets: BTreeSet<(Uuid, SecretField)>,
    /// The publisher's shared credentials published as credential slots (never their values).
    pub slots: BTreeSet<Uuid>,
    /// The inline key material of a selected config the administrator ticked for publishing, one by one (a
    /// config with key material that is not ticked is not published).
    pub inline_secrets: BTreeSet<(Uuid, InlineSecret)>,
}

/// Key material inside a config that every subscriber would get as is: the publish review lists each one for an
/// explicit tick. Inline user names and passwords are never offered: such a config is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InlineSecret {
    /// WireGuard `PrivateKey`: everyone with the catalog uses the same WireGuard key.
    WireGuardPrivateKey,
    /// WireGuard `PresharedKey`.
    WireGuardPresharedKey,
    /// OpenVPN `<key>` or `<pkcs12>`: everyone uses the same client key.
    OpenVpnKey,
    /// OpenVPN `<tls-auth>`.
    TlsAuth,
    /// OpenVPN `<tls-crypt>`.
    TlsCrypt,
    /// OpenVPN `<tls-crypt-v2>`.
    TlsCryptV2,
    /// OpenVPN `<secret>` (a static key).
    StaticKey,
    /// An SSTP config's `user=` without a ticked credential slot: every subscriber connects as that user. (With a
    /// slot it is replaced by [`SSTP_SLOT_USER`] and the slot's user goes in at connect.)
    SstpUser,
}

/// The `user=` an SSTP connection with a credential slot is published with: the publisher's own user name is never
/// published (the validator needs a value; the subscriber's slot user replaces it at connect).
pub const SSTP_SLOT_USER: &str = "slot-user";

impl InlineSecret {
    pub const ALL: [InlineSecret; 8] = [
        InlineSecret::WireGuardPrivateKey,
        InlineSecret::WireGuardPresharedKey,
        InlineSecret::OpenVpnKey,
        InlineSecret::TlsAuth,
        InlineSecret::TlsCrypt,
        InlineSecret::TlsCryptV2,
        InlineSecret::StaticKey,
        InlineSecret::SstpUser,
    ];

    /// The storage and IPC name.
    pub fn as_str(self) -> &'static str {
        match self {
            InlineSecret::WireGuardPrivateKey => "wireguardPrivateKey",
            InlineSecret::WireGuardPresharedKey => "wireguardPresharedKey",
            InlineSecret::OpenVpnKey => "openvpnKey",
            InlineSecret::TlsAuth => "tlsAuth",
            InlineSecret::TlsCrypt => "tlsCrypt",
            InlineSecret::TlsCryptV2 => "tlsCryptV2",
            InlineSecret::StaticKey => "staticKey",
            InlineSecret::SstpUser => "sstpUser",
        }
    }

    pub fn parse(s: &str) -> Option<InlineSecret> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// The inline key material of a config (and an SSTP `user=`), in [`InlineSecret`] order, without duplicates.
    pub fn of(kind: VPNKind, config: &str) -> Vec<InlineSecret> {
        let found: BTreeSet<InlineSecret> = exporter::secret_material(config, kind)
            .iter()
            .filter_map(|name| match (kind, name.as_str()) {
                (VPNKind::Wireguard, "PrivateKey") => Some(InlineSecret::WireGuardPrivateKey),
                (VPNKind::Wireguard, "PresharedKey") => Some(InlineSecret::WireGuardPresharedKey),
                (VPNKind::Openvpn, "<key>" | "<pkcs12>") => Some(InlineSecret::OpenVpnKey),
                (VPNKind::Openvpn, "<tls-auth>") => Some(InlineSecret::TlsAuth),
                (VPNKind::Openvpn, "<tls-crypt>") => Some(InlineSecret::TlsCrypt),
                (VPNKind::Openvpn, "<tls-crypt-v2>") => Some(InlineSecret::TlsCryptV2),
                (VPNKind::Openvpn, "<secret>") => Some(InlineSecret::StaticKey),
                _ => None,
            })
            .collect();
        let mut found: Vec<InlineSecret> = found.into_iter().collect();
        if kind == VPNKind::Sstp && !crate::validators::SSTPConfig::parse(config).user.is_empty() {
            found.push(InlineSecret::SstpUser);
        }
        found
    }
}
