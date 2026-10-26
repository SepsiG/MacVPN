//! The debug-mode snapshot of the system (G-6) from winsys' read-only IP Helper calls, and the server's resolution
//! (on a helper thread, bounded like the WireGuard endpoint's). No `unsafe` here.

use crate::windows::diagnostics::{Interface, Route, Snapshot};
use macvpn_winsys::net;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// How long the snapshot waits for the server's name to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// At most this many addresses of the server are written.
const MAX_RESOLVED: usize = 16;

fn resolve(server: &str) -> Vec<IpAddr> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return vec![ip];
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let name = server.to_owned();
    std::thread::spawn(move || {
        let found: Vec<IpAddr> =
            (name.as_str(), 0).to_socket_addrs().map(|it| it.map(|a| a.ip()).collect()).unwrap_or_default();
        let _ = tx.send(found);
    });
    let mut found: Vec<IpAddr> = Vec::new();
    for ip in rx.recv_timeout(RESOLVE_TIMEOUT).unwrap_or_default() {
        if !found.contains(&ip) && found.len() < MAX_RESOLVED {
            found.push(ip);
        }
    }
    found
}

/// What the system looks like now (each part that cannot be read is named in `problems`).
pub(crate) fn snapshot(server: Option<&str>) -> Snapshot {
    let mut s = Snapshot { server: server.map(str::to_string), ..Snapshot::default() };
    if let Some(server) = server {
        s.resolved = resolve(server);
    }
    let adapters = match net::adapters_with_dns() {
        Ok(a) => a,
        Err(e) => {
            s.problems.push(format!("interfaces: {e}"));
            Vec::new()
        }
    };
    let by_luid: HashMap<u64, &net::AdapterDiag> = adapters.iter().map(|a| (a.luid, a)).collect();
    match net::ipv4_routes() {
        Ok(mut routes) => {
            let metric = |r: &net::RawRoute| r.metric.saturating_add(by_luid.get(&r.luid).map_or(0, |a| a.ipv4_metric));
            routes.sort_by_key(|r| (std::cmp::Reverse(r.prefix_len == 0), metric(r), r.destination, r.prefix_len));
            s.routes = routes
                .iter()
                .map(|r| Route {
                    destination: r.destination,
                    prefix_len: r.prefix_len,
                    next_hop: r.next_hop,
                    interface: by_luid.get(&r.luid).map_or_else(|| format!("luid {:#x}", r.luid), |a| a.alias.clone()),
                    metric: metric(r),
                })
                .collect();
        }
        Err(e) => s.problems.push(format!("routes: {e}")),
    }
    s.dns = adapters.iter().filter(|a| !a.dns.is_empty()).map(|a| (a.alias.clone(), a.dns.clone())).collect();
    s.interfaces =
        adapters.iter().map(|a| Interface { name: a.alias.clone(), up: a.up, addresses: a.unicast.clone() }).collect();
    s
}
