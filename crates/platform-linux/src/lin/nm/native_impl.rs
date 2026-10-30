//! `NativeController` and `NativeProfiles` of the NetworkManager engine: L2TP, Cisco IPsec and the system VPNs
//! (resolved points 1, 2 and 14; L-b Task 22).
//!
//! A managed L2TP / Cisco connection has no NM profile: `install` stores its secret-free plan record
//! (`plan_store`), it lists as `linvpn-<UUID>` (its state from the engine's runs), and `start` builds the volatile
//! connection from the record through [`Engine::activate`] (the agent answers its password and PSK). Every other
//! listed id is a system VPN's NM UUID (`system_vpns`): started with `ActivateConnection` after the polkit check;
//! with stored secrets (L2TP, Cisco, as on macOS) LinVPN's agent answers them for that activation only.

use crate::lin::nm::agent::{Answer, Expect, Rules};
use crate::lin::nm::engine::Engine;
use crate::lin::nm::plan_store::{self, PlanRecord};
use crate::lin::nm::system_vpns::{self, connected};
use crate::pure::nm::system_vpn::secret_keys;
use crate::pure::texts;
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::log::{FileLogSource, LogSource};
use macvpn_core::models::{Connection, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_core::nm_plan::{SecretKey, names};
use macvpn_platform_api::{NativeController, NativeProfile, NativeProfiles, SystemVpn, TrafficReading};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// How long a system VPN's secrets stay with the agent while NM does not list its activation yet.
const EXPECT_GRACE: Duration = Duration::from_secs(30);

/// The native kinds' part of the engine's state.
#[derive(Default)]
pub struct NativeState {
    /// The system VPN activations LinVPN started with stored secrets: NM UUID → (started, the agent's
    /// expectation). Dropped at `stop`, and by `list` once NM no longer has the activation.
    expects: Mutex<HashMap<String, (Instant, Expect)>>,
}

impl NativeState {
    fn expects(&self) -> MutexGuard<'_, HashMap<String, (Instant, Expect)>> {
        self.expects.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn record_missing() -> String {
    l10n::tr("This connection's settings are missing on this computer. Open it and save it again.", &[])
}

fn not_native() -> String {
    l10n::tr("This kind of connection is not started this way on Linux.", &[])
}

/// `RunView::state` → `SystemVpn::status`.
fn managed_status(state: &str) -> &'static str {
    match state {
        "connected" => "Connected",
        "connecting" => "Connecting",
        _ => "Disconnected",
    }
}

impl Engine {
    /// `$XDG_DATA_HOME/LinVPN/nm`.
    pub fn plan_dir(&self) -> PathBuf {
        plan_store::dir(&self.data)
    }

    /// The managed connections (`linvpn-<UUID>`) with their states.
    fn managed_list(&self) -> Vec<SystemVpn> {
        let records = plan_store::list(&self.plan_dir());
        if records.is_empty() {
            return Vec::new();
        }
        let runs = self.runs();
        records
            .into_iter()
            .map(|(id, record)| {
                let status = runs
                    .iter()
                    .find(|r| r.id == id && r.kind.is_native())
                    .map_or("Disconnected", |r| managed_status(r.state));
                let service = names::service_id(&id);
                SystemVpn::new(
                    &service,
                    &service,
                    if record.kind == VPNKind::Cisco { "Cisco IPsec" } else { "L2TP" },
                    status,
                )
            })
            .collect()
    }

    /// A managed connection's address while it is connected.
    fn managed_address(&self, id: &Uuid) -> Option<String> {
        self.runs().into_iter().find(|r| r.id == *id && r.kind.is_native() && r.state == "connected")?.ip
    }

    /// A system VPN start with the stored secrets: the agent answers the plugin's password and PSK keys for this
    /// profile (L2TP, Cisco); nothing for other plugins, without `kind` or without secrets.
    fn expect_system_secrets(
        &self,
        uuid: &str,
        profile_path: &str,
        service_type: Option<&str>,
        kind: Option<NativeKind>,
        secrets: &Secrets,
    ) -> Result<(), String> {
        let Some((password_key, psk_key)) = kind.and(secret_keys(service_type)) else { return Ok(()) };
        let items: Vec<(&'static str, SecretKey, Zeroizing<String>)> =
            [(password_key, secrets.password.as_deref()), (psk_key, secrets.psk.as_deref())]
                .into_iter()
                .filter_map(|(key, value)| {
                    let value = value.filter(|v| !v.is_empty())?;
                    Some(("vpn", SecretKey::Plain(key.to_string()), Zeroizing::new(value.to_string())))
                })
                .collect();
        if items.is_empty() {
            return Ok(());
        }
        let (_, agent) = self.nm()?;
        // Only for this profile (its path) and its plugin: another profile with the same UUID gets nothing.
        let rules = Rules { user: None, service_type: service_type.map(String::from) };
        let expect = agent.expect(uuid, rules, Answer { items });
        expect.bind(profile_path);
        let old = self.native.expects().insert(uuid.to_string(), (Instant::now(), expect));
        drop(old);
        Ok(())
    }

    fn start_system(&self, uuid: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        let profile = self.system_profile(uuid)?;
        // The agent (registered by `nm`) must be there before NM asks for the secrets.
        let (client, _) = self.nm()?;
        self.expect_system_secrets(uuid, &profile.path, profile.service_type.as_deref(), kind, secrets)?;
        if let Err(e) = client.activate_profile(&profile.path) {
            let dropped = self.native.expects().remove(uuid);
            drop(dropped);
            return Err(e.message());
        }
        Ok(())
    }

    fn stop_system(&self, uuid: &str) -> Result<(), String> {
        let client = self.nm_client()?;
        let active = client.active().map_err(|e| e.message())?;
        for a in active.iter().filter(|a| a.uuid == uuid) {
            client.deactivate(&a.path).map_err(|e| e.message())?;
        }
        let dropped = self.native.expects().remove(uuid);
        drop(dropped);
        Ok(())
    }

    /// Forgets the secrets of system VPN activations NM no longer has (after the start's grace).
    fn prune_expects(&self, active_uuids: &HashSet<&str>) {
        let mut expects = self.native.expects();
        let gone: Vec<String> = expects
            .iter()
            .filter(|(uuid, (at, _))| !active_uuids.contains(uuid.as_str()) && at.elapsed() >= EXPECT_GRACE)
            .map(|(uuid, _)| uuid.clone())
            .collect();
        let dropped: Vec<_> = gone.iter().filter_map(|u| expects.remove(u)).collect();
        drop(expects);
        drop(dropped);
    }
}

impl NativeController for Engine {
    /// LinVPN's managed connections (`linvpn-<UUID>`), then the user's own NM VPNs (their NM UUIDs as IDs). In the
    /// sandbox NM is not asked.
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        let mut out = self.managed_list();
        if self.sandbox {
            return Ok(out);
        }
        let active = self.nm_client()?.active().map_err(|e| e.message())?;
        let active_uuids: HashSet<&str> = active.iter().map(|a| a.uuid.as_str()).collect();
        self.prune_expects(&active_uuids);
        out.extend(system_vpns::list_with(self, &active)?);
        Ok(out)
    }

    fn remote_address(&self, service_id: &str) -> Option<String> {
        if let Some(id) = names::parse_service_id(service_id) {
            return plan_store::read(&self.plan_dir(), &id).ok().map(|r| r.server);
        }
        if self.sandbox {
            return None;
        }
        let profile = self.system_profile(service_id).ok()?;
        crate::pure::nm::system_vpn::remote_address(profile.service_type.as_deref(), &profile.data)
    }

    /// A managed connection: its record planned and activated (returns once NM accepted the activation); a system
    /// VPN: `ActivateConnection` of its profile.
    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        if self.sandbox {
            return Err(texts::not_yet());
        }
        let Some(id) = names::parse_service_id(service_id) else { return self.start_system(service_id, kind, secrets) };
        let record = plan_store::read(&self.plan_dir(), &id).map_err(|_| record_missing())?;
        self.activate(id, &record.connection(id), b"", secrets, false)
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        if self.sandbox {
            return Err(texts::not_yet());
        }
        match names::parse_service_id(service_id) {
            Some(id) => self.deactivate(&id),
            None => self.stop_system(service_id),
        }
    }

    fn managed_service_id(&self, connection: &Uuid) -> Option<String> {
        Some(names::service_id(connection))
    }

    /// The connection's log (LinVPN's lines and the journal pump's), as for the helper kinds.
    fn log_source(&self, connection: &Uuid) -> Option<Box<dyn LogSource>> {
        Some(Box::new(FileLogSource { path: self.log_file(connection) }))
    }

    fn clear_log(&self, connection: &Uuid, note: &str) -> Result<bool, String> {
        // SAFETY: getuid has no arguments and cannot fail.
        let owner = FileOwner::from_uid(unsafe { libc::getuid() });
        macvpn_core::log::clear_file(&self.log_file(connection), &owner, Some(note))
            .map(|_| true)
            .map_err(|e| e.to_string())
    }

    fn traffic(&self, service_id: &str) -> Option<TrafficReading> {
        if let Some(id) = names::parse_service_id(service_id) {
            return self.traffic_of(&id);
        }
        if self.sandbox {
            return None;
        }
        let active = self.nm_client().ok()?.active().ok()?;
        system_vpns::traffic_of(self, connected(service_id, &active)?)
    }

    fn address(&self, service_id: &str) -> Option<String> {
        if let Some(id) = names::parse_service_id(service_id) {
            return self.managed_address(&id);
        }
        if self.sandbox {
            return None;
        }
        let active = self.nm_client().ok()?.active().ok()?;
        connected(service_id, &active)?.ip4.clone()
    }
}

impl NativeProfiles for Engine {
    /// The secret-free plan record (the PSK and the password never go into it: the agent answers them at connect).
    fn build(&self, connection: &Connection, _psk: &str) -> Result<NativeProfile, String> {
        if !connection.kind.is_native() {
            return Err(not_native());
        }
        let record = PlanRecord::of(connection).ok_or_else(|| l10n::tr("Server and account name are required", &[]))?;
        Ok(NativeProfile { data: Zeroizing::new(record.encode()), file_name: format!("{}.json", connection.id) })
    }

    /// Writes the plan record at once (no NM profile, no approval step); an unchanged one is left as it is.
    fn install(&self, id: &Uuid, profile: &[u8], _file_name: &str, _service_existed: bool) -> Result<(), String> {
        let record = PlanRecord::decode(profile)
            .map_err(|e| l10n::tr("LinVPN could not save the connection's settings: %@", &[Arg::Str(&e)]))?;
        let dir = self.plan_dir();
        if plan_store::read(&dir, id).is_ok_and(|saved| saved == record) {
            return Ok(());
        }
        plan_store::write(&dir, id, &record)
            .map_err(|e| l10n::tr("LinVPN could not save the connection's settings: %@", &[Arg::Str(&e.to_string())]))
    }

    /// Disconnects a managed connection and deletes its record (any kind: nothing happens without a record).
    fn remove(&self, id: &Uuid) {
        let dir = self.plan_dir();
        if plan_store::read(&dir, id).is_ok() {
            let _ = self.deactivate(id);
        }
        let _ = plan_store::remove(&dir, id);
    }

    /// Deletes the records of connections that are no longer in the open vault.
    fn reconcile(&self, known: &HashSet<Uuid>) {
        for id in plan_store::ids(&self.plan_dir()) {
            if !known.contains(&id) {
                self.remove(&id);
            }
        }
    }

    fn removes_profiles(&self) -> bool {
        true
    }

    fn needs_approval(&self) -> bool {
        false
    }
}
