//! `NativeSupport` of the NetworkManager engine: why Linux cannot run a connection (`nm_plan`'s `Unsupported`) and
//! the editor's notes (resolved point 5; L-b Task 22). Asked for every kind at every reload: the plan is pure and
//! cheap, the caps are cached ([`Engine::caps`]), no D-Bus call is made. The runtime paths are placeholders (only
//! the reasons and notes are read); an IKEv2 client certificate imported in the app is known by its form only.

use crate::lin::nm::engine::Engine;
use crate::pure::nm::support;
use macvpn_core::client_cert::Form;
use macvpn_core::models::Connection;
use macvpn_core::nm_plan::{Caps, ImportedCert, Input};
use macvpn_platform_api::{NativeSupport, PlatformNotes};
use std::path::{Path, PathBuf};

impl Engine {
    fn plan_input<'a>(
        &'a self,
        connection: &'a Connection,
        config: &'a [u8],
        caps: &'a Caps,
        dir: &'a Path,
        client_cert: Option<Form>,
    ) -> Input<'a> {
        let client_cert = client_cert.map_or(ImportedCert::None, ImportedCert::Known);
        Input { connection, config, user: &self.user, uid: self.uid, runtime_dir: dir, caps, client_cert }
    }

    /// A placeholder runtime directory (the plan writes it into paths only).
    fn placeholder_dir(&self) -> PathBuf {
        self.runtime.clone().unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", self.uid))).join("linvpn/nm/-")
    }
}

impl NativeSupport for Engine {
    fn unsupported_reason(&self, connection: &Connection, config: &[u8]) -> Option<String> {
        self.unsupported_reason_with_cert(connection, config, None)
    }

    fn editor_notes(&self, connection: &Connection, config: &[u8]) -> PlatformNotes {
        self.editor_notes_with_cert(connection, config, None)
    }

    /// IKEv2 without `certs`: the imported client certificate's form decides (`nm_plan::strongswan`).
    fn unsupported_reason_with_cert(
        &self,
        connection: &Connection,
        config: &[u8],
        client_cert: Option<Form>,
    ) -> Option<String> {
        let caps = self.caps();
        let dir = self.placeholder_dir();
        support::unsupported_reason(&self.plan_input(connection, config, &caps, &dir, client_cert))
    }

    fn editor_notes_with_cert(
        &self,
        connection: &Connection,
        config: &[u8],
        client_cert: Option<Form>,
    ) -> PlatformNotes {
        let caps = self.caps();
        let dir = self.placeholder_dir();
        support::editor_notes(&self.plan_input(connection, config, &caps, &dir, client_cert))
    }

    /// None: NetworkManager's plugins take the PSK at each start, as macOS (nothing is kept for a system VPN).
    fn system_psk_note(&self) -> Option<String> {
        None
    }
}
