//! Task 22's additions to the fake NetworkManager: saved profiles of any plugin with their `vpn.data` and
//! WireGuard profiles with a peer endpoint (the user's own NM VPNs, listed as system VPNs).

use super::{FakeNm, NmSettings};
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Value};

fn owned(v: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(v).unwrap()
}

fn connection(uuid: &str, id: &str, nm_type: &str, permissions: &[&str]) -> HashMap<String, OwnedValue> {
    HashMap::from([
        ("id".to_string(), owned(Value::from(id))),
        ("uuid".to_string(), owned(Value::from(uuid))),
        ("type".to_string(), owned(Value::from(nm_type))),
        ("permissions".to_string(), owned(Value::from(permissions.iter().map(|p| p.to_string()).collect::<Vec<_>>()))),
    ])
}

impl FakeNm {
    /// A saved `vpn` profile of `service_type` named `id`, with `data` as its `vpn.data`. Returns its path.
    pub fn add_vpn_profile(
        &self,
        uuid: &str,
        id: &str,
        service_type: &str,
        data: &[(&str, &str)],
        permissions: &[&str],
        flags: u32,
    ) -> String {
        let data: HashMap<String, String> = data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let settings: NmSettings = HashMap::from([
            ("connection".to_string(), connection(uuid, id, "vpn", permissions)),
            (
                "vpn".to_string(),
                HashMap::from([
                    ("service-type".to_string(), owned(Value::from(service_type))),
                    ("data".to_string(), owned(Value::from(data))),
                ]),
            ),
        ]);
        self.add_profile_settings(settings, flags)
    }

    /// A saved `wireguard` profile named `id` with one peer at `endpoint`. Returns its path.
    pub fn add_wireguard_profile(&self, uuid: &str, id: &str, endpoint: &str, permissions: &[&str]) -> String {
        let peer: HashMap<String, Value<'_>> = HashMap::from([
            ("public-key".to_string(), Value::from("x8N2c5yQ6wHn0Vt3sYp4G1rK7bJ9mL2dF5hE8aZ0uW4=")),
            ("endpoint".to_string(), Value::from(endpoint.to_string())),
        ]);
        let settings: NmSettings = HashMap::from([
            ("connection".to_string(), connection(uuid, id, "wireguard", permissions)),
            ("wireguard".to_string(), HashMap::from([("peers".to_string(), owned(Value::from(vec![peer])))])),
        ]);
        self.add_profile_settings(settings, 0)
    }

    /// The recorded `ActivateConnection` calls' profile paths, in order.
    pub fn activated_profiles(&self) -> Vec<String> {
        self.calls().into_iter().filter(|c| c.method == "ActivateConnection").map(|c| c.path).collect()
    }
}
