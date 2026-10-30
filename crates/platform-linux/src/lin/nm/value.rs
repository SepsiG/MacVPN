//! `nm_plan::Settings` → the `a{sa{sv}}` NetworkManager takes.
use macvpn_core::nm_plan::{NmAddress, NmRoute, NmValue, NmWgPeer, Settings};
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Value};

pub type DbusSettings = HashMap<String, HashMap<String, OwnedValue>>;

/// Every setting and key of the plan, typed as NetworkManager's D-Bus API expects. The plan holds no secret, so
/// neither does the result.
pub fn to_dbus(settings: &Settings) -> DbusSettings {
    settings
        .iter()
        .map(|(name, keys)| {
            // A peer's `preshared-key-flags` follows the section's `private-key-flags` (the agent owns both or
            // neither).
            let psk_flags = match keys.get("private-key-flags") {
                Some(NmValue::U32(flags)) => *flags,
                _ => 0,
            };
            let keys = keys.iter().map(|(key, value)| (key.clone(), owned(value, psk_flags))).collect();
            (name.clone(), keys)
        })
        .collect()
}

fn owned(value: &NmValue, psk_flags: u32) -> OwnedValue {
    let value = match value {
        NmValue::Str(s) => Value::from(s.as_str()),
        NmValue::Bool(b) => Value::from(*b),
        NmValue::U32(n) => Value::from(*n),
        NmValue::I32(n) => Value::from(*n),
        NmValue::I64(n) => Value::from(*n),
        NmValue::StrList(list) => Value::from(list.clone()),
        NmValue::StrDict(dict) => {
            Value::from(dict.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<HashMap<_, _>>())
        }
        NmValue::Addresses(list) => Value::from(list.iter().map(address).collect::<Vec<_>>()),
        NmValue::Routes(list) => Value::from(list.iter().map(route).collect::<Vec<_>>()),
        NmValue::WgPeers(list) => Value::from(list.iter().map(|p| peer(p, psk_flags)).collect::<Vec<_>>()),
    };
    // Only a file descriptor fails to convert, and no setting holds one.
    OwnedValue::try_from(value).unwrap_or_else(|_| OwnedValue::from(0u32))
}

type Dict = HashMap<String, Value<'static>>;

fn address(a: &NmAddress) -> Dict {
    HashMap::from([
        ("address".to_string(), Value::from(a.address.clone())),
        ("prefix".to_string(), Value::from(a.prefix)),
    ])
}

fn route(r: &NmRoute) -> Dict {
    let mut d: Dict = HashMap::from([
        ("dest".to_string(), Value::from(r.dest.clone())),
        ("prefix".to_string(), Value::from(r.prefix)),
    ]);
    if let Some(hop) = &r.next_hop {
        d.insert("next-hop".into(), Value::from(hop.clone()));
    }
    if let Some(metric) = r.metric {
        d.insert("metric".into(), Value::from(metric));
    }
    d
}

fn peer(p: &NmWgPeer, psk_flags: u32) -> Dict {
    let mut d: Dict = HashMap::from([
        ("public-key".to_string(), Value::from(p.public_key.clone())),
        ("allowed-ips".to_string(), Value::from(p.allowed_ips.clone())),
        ("persistent-keepalive".to_string(), Value::from(p.persistent_keepalive)),
    ]);
    if let Some(endpoint) = &p.endpoint {
        d.insert("endpoint".into(), Value::from(endpoint.clone()));
    }
    if p.has_preshared_key {
        d.insert("preshared-key-flags".into(), Value::from(psk_flags));
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn one(key: &str, value: NmValue) -> DbusSettings {
        let mut s = Settings::new();
        s.entry("x".into()).or_default().insert(key.into(), value);
        to_dbus(&s)
    }

    fn sig(key: &str, value: NmValue) -> String {
        one(key, value)["x"][key].value_signature().to_string()
    }

    #[test]
    fn each_type_has_nm_signature() {
        assert_eq!(sig("k", NmValue::Str("a".into())), "s");
        assert_eq!(sig("k", NmValue::Bool(true)), "b");
        assert_eq!(sig("k", NmValue::U32(1)), "u");
        assert_eq!(sig("k", NmValue::I32(-1)), "i");
        assert_eq!(sig("k", NmValue::I64(-1)), "x");
        assert_eq!(sig("k", NmValue::StrList(vec![])), "as");
        assert_eq!(sig("k", NmValue::StrDict(BTreeMap::from([("a".into(), "b".into())]))), "a{ss}");
        assert_eq!(sig("k", NmValue::Addresses(vec![NmAddress { address: "10.0.0.2".into(), prefix: 24 }])), "aa{sv}");
        assert_eq!(sig("k", NmValue::Routes(vec![])), "aa{sv}");
        assert_eq!(sig("k", NmValue::WgPeers(vec![])), "aa{sv}");
    }

    fn dicts(v: &OwnedValue) -> Vec<HashMap<String, OwnedValue>> {
        Vec::<HashMap<String, OwnedValue>>::try_from(v.try_clone().unwrap()).unwrap()
    }

    fn keys(d: &HashMap<String, OwnedValue>) -> Vec<&str> {
        let mut k: Vec<&str> = d.keys().map(String::as_str).collect();
        k.sort_unstable();
        k
    }

    #[test]
    fn routes_carry_next_hop_and_metric_only_when_set() {
        let s = one(
            "route-data",
            NmValue::Routes(vec![
                NmRoute { dest: "10.99.0.0".into(), prefix: 24, next_hop: None, metric: None },
                NmRoute { dest: "0.0.0.0".into(), prefix: 0, next_hop: Some("10.99.0.1".into()), metric: Some(50) },
            ]),
        );
        let r = dicts(&s["x"]["route-data"]);
        assert_eq!(keys(&r[0]), ["dest", "prefix"]);
        assert_eq!(keys(&r[1]), ["dest", "metric", "next-hop", "prefix"]);
        assert_eq!(r[1]["metric"].value_signature().to_string(), "u");
        assert_eq!(r[1]["prefix"].value_signature().to_string(), "u");
    }

    #[test]
    fn peers_take_the_private_key_flags_for_their_preshared_key() {
        let mut s = Settings::new();
        let wg = s.entry("wireguard".into()).or_default();
        wg.insert("private-key-flags".into(), NmValue::U32(1));
        wg.insert(
            "peers".into(),
            NmValue::WgPeers(vec![
                NmWgPeer {
                    public_key: "pk1".into(),
                    endpoint: Some("vpn.example.com:51820".into()),
                    allowed_ips: vec!["0.0.0.0/0".into()],
                    persistent_keepalive: 25,
                    has_preshared_key: true,
                },
                NmWgPeer {
                    public_key: "pk2".into(),
                    endpoint: None,
                    allowed_ips: vec![],
                    persistent_keepalive: 0,
                    has_preshared_key: false,
                },
            ]),
        );
        let d = to_dbus(&s);
        let p = dicts(&d["wireguard"]["peers"]);
        assert_eq!(
            keys(&p[0]),
            ["allowed-ips", "endpoint", "persistent-keepalive", "preshared-key-flags", "public-key"]
        );
        assert_eq!(u32::try_from(p[0]["preshared-key-flags"].try_clone().unwrap()).unwrap(), 1);
        assert_eq!(p[0]["allowed-ips"].value_signature().to_string(), "as");
        assert_eq!(p[0]["persistent-keepalive"].value_signature().to_string(), "u");
        assert_eq!(keys(&p[1]), ["allowed-ips", "persistent-keepalive", "public-key"]);
    }
}
