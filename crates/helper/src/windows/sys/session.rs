//! Logoff (decision 2 of the 2b plan): the connections of a user who has no session left go down. Locking the
//! screen or switching users keeps the session (active or disconnected), so it keeps the connections. That holds
//! for the user's WinVPN RAS connections too (2c plan, Task 10): the app dials them in the user's context and
//! Windows normally ends them at logoff; when it does not (`KeepRasConnections`), the service hangs up every one
//! that `ras_logoff` attributes to a user without a session, from HKLM's profile list and the RAS connection list
//! only (no request, no user input).

use super::service_log::ServiceLog;
use crate::windows::ras_logoff::{self, Profile, RasConn};
use crate::windows::service::{Host, Service};
use macvpn_winsys::profiles;
use macvpn_winsys::ras;
use macvpn_winsys::sid::Sid;
use std::collections::HashSet;
use std::io;
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_CTX_WINSTATION_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_NO_TOKEN, HANDLE};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
};

/// The pauses before each look at the sessions after a logoff: the ending session can take a few seconds to leave
/// the list (a user still listed then keeps the connections until the next look).
const PAUSES: [Duration; 3] = [Duration::from_secs(2), Duration::from_secs(3), Duration::from_secs(5)];

/// How long one logoff may wait in total for RAS connections to be released (every pass together).
const RAS_BUDGET: Duration = Duration::from_secs(10);

/// After a logoff: every owner SID without a session left loses its connections, and its WinVPN RAS connections.
pub fn after_logoff<H: Host>(service: &Service<H>, log: &ServiceLog) {
    let mut budget = RAS_BUDGET;
    for pause in PAUSES {
        std::thread::sleep(pause);
        let present = user_sids();
        if let Ok(present) = &present {
            let spent = hang_up_absent_ras(present, budget, &mut |l| log.line(l));
            budget = budget.saturating_sub(spent);
        }
        drop_absent(service, present);
    }
}

/// Hangs up the WinVPN RAS connections of every profile without a session in `present`, waiting at most `budget`
/// for them to be released; returns the time spent. Nothing when the profiles or the connections cannot be read.
fn hang_up_absent_ras(present: &HashSet<String>, budget: Duration, line: &mut dyn FnMut(&str)) -> Duration {
    let (Ok(profiles), Ok(conns)) = (profiles::list(), ras::connections()) else { return Duration::ZERO };
    let pairs: Vec<(String, String)> =
        conns.iter().map(|c| (c.entry.clone(), c.phonebook.to_string_lossy().into_owned())).collect();
    let profiles: Vec<(String, String)> =
        profiles.into_iter().filter_map(|p| Some((p.key, p.dir.into_os_string().into_string().ok()?))).collect();
    let mut hang = |i: usize, wait: Duration| ras::hang_up(conns[i].handle, wait).map_err(|e| e.to_string());
    hang_up_owned(&profiles, present, &pairs, budget, &mut hang, line)
}

/// [`hang_up_absent_ras`] over what Windows listed: `profiles` as (key, folder), `conns` as (entry, phonebook);
/// `hang(index, wait)` hangs one up and waits up to `wait` for its release (it is called for every connection, with
/// a zero wait once the budget is spent). One `service.log` line per hang-up.
fn hang_up_owned(
    profiles: &[(String, String)],
    present: &HashSet<String>,
    conns: &[(String, String)],
    budget: Duration,
    hang: &mut dyn FnMut(usize, Duration) -> Result<(), String>,
    line: &mut dyn FnMut(&str),
) -> Duration {
    let start = Instant::now();
    let profiles: Vec<Profile<'_>> = profiles.iter().map(|(sid, dir)| Profile { sid, dir }).collect();
    let views: Vec<RasConn<'_>> = conns.iter().map(|(entry, phonebook)| RasConn { entry, phonebook }).collect();
    for i in ras_logoff::to_hang_up(&profiles, present, &views) {
        let wait = budget.saturating_sub(start.elapsed());
        let result = hang(i, wait);
        line(&ras_logoff::hang_up_line(&conns[i].0, result.as_ref().err().map(String::as_str)));
    }
    start.elapsed()
}

/// Takes down the connections of every owner not in `present`. Unreadable sessions drop nothing: dropping is the
/// convenience, keeping is safe (the connection still belongs to its owner, only its owner can use it).
pub(crate) fn drop_absent<H: Host>(service: &Service<H>, present: io::Result<HashSet<String>>) {
    let Ok(present) = present else { return };
    for sid in service.owners() {
        if !present.contains(&sid) {
            service.drop_user(&sid);
        }
    }
}

/// The users of every session that has one (`WTSEnumerateSessionsW`, then `WTSQueryUserToken` per session, which
/// needs SYSTEM's `SeTcbPrivilege`), as SID strings, whatever the session's state: a locked, disconnected or
/// shadowed session still has its user. A session without a user (session 0, the logon screen, one that ended
/// meanwhile) is skipped; any other failure is an error (nothing is dropped).
pub(crate) fn user_sids() -> io::Result<HashSet<String>> {
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: the local server's pseudo handle; reserved 0 and version 1 as documented; valid out pointers.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) } == 0 {
        return Err(io::Error::last_os_error());
    }
    struct Free(*mut WTS_SESSION_INFOW);
    impl Drop for Free {
        fn drop(&mut self) {
            // SAFETY: the array WTSEnumerateSessionsW allocated, freed once, after its last use.
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
    let _free = Free(info);
    if info.is_null() && count != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no session list"));
    }
    let ids: Vec<u32> = if count == 0 {
        Vec::new()
    } else {
        // SAFETY: the call succeeded: `info` points to `count` structures, alive until `_free` drops.
        unsafe { std::slice::from_raw_parts(info, count as usize) }.iter().map(|s| s.SessionId).collect()
    };
    let mut users = HashSet::new();
    for id in ids {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: a session id from the list; `token` is a valid out pointer.
        if unsafe { WTSQueryUserToken(id, &mut token) } == 0 {
            let e = io::Error::last_os_error();
            let gone = [ERROR_NO_TOKEN, ERROR_CTX_WINSTATION_NOT_FOUND, ERROR_FILE_NOT_FOUND];
            if e.raw_os_error().is_some_and(|c| gone.iter().any(|&g| g as i32 == c)) {
                continue;
            }
            return Err(e);
        }
        if token.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no token"));
        }
        // SAFETY: a primary token handle the call just returned; nobody else owns it; closed on drop.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        users.insert(Sid::of_token(token.as_handle())?.to_string());
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::service::{Caller, Engine, EngineState, UpRequest};
    use crate::windows::sys::{NoLogs, RealHost, facts_fn};
    use macvpn_core::service_proto::Request;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";

    #[derive(Default)]
    struct Up(std::sync::Arc<Mutex<HashSet<String>>>);

    impl Engine for Up {
        fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
            self.0.lock().unwrap().insert(req.id.to_string());
            Ok(())
        }
        fn down(&self, id: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
        fn state(&self, _id: &str) -> Option<EngineState> {
            None
        }
    }

    #[test]
    fn only_owners_without_a_session_lose_their_connections() {
        let running = std::sync::Arc::new(Mutex::new(HashSet::new()));
        let host = RealHost {
            openvpn: Box::new(Up(running.clone())),
            wireguard: Box::new(Up(running.clone())),
            logs: Box::new(NoLogs),
            problem: None,
            facts: facts_fn(None),
        };
        let service = Service::new(host);
        let up = |sid: &str, id: &str| {
            let body = format!("config {}\n{WG}", WG.len()).into_bytes();
            let req = Request {
                args: ["up", "wireguard", id].iter().map(|s| s.to_string()).collect(),
                body: Zeroizing::new(body),
            };
            assert_eq!(service.handle(&Caller { sid: sid.into() }, &req).code, 0);
        };
        let (a, b) = ("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        up("S-1-5-21-1-2-3-1001", a);
        up("S-1-5-21-1-2-3-1002", b);
        // Unreadable sessions: nothing goes down.
        drop_absent(&service, Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert_eq!(running.lock().unwrap().len(), 2);
        // Only the user with no session left loses the connection.
        drop_absent(&service, Ok(HashSet::from(["S-1-5-21-1-2-3-1001".to_string()])));
        assert_eq!(*running.lock().unwrap(), HashSet::from([a.to_string()]));
        assert_eq!(service.owners(), HashSet::from(["S-1-5-21-1-2-3-1001".to_string()]));
    }

    #[test]
    fn only_winvpn_connections_of_absent_profiles_are_hung_up_within_the_budget() {
        let me = Sid::current_user().unwrap().to_string();
        let home = std::env::var("USERPROFILE").unwrap();
        let other = "S-1-5-21-1111-2222-3333-1002".to_string();
        let profiles = vec![(me.clone(), home.clone()), (other.clone(), r"C:\Users\winvpn-gone".to_string())];
        let book = |dir: &str| format!(r"{dir}\AppData\Local\WinVPN\ras\WinVPN.pbk");
        let conns = vec![
            ("WinVPN-0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".to_string(), book(&home)),
            ("WinVPN-1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".to_string(), book(r"C:\Users\winvpn-gone")),
            ("Work VPN".to_string(), r"C:\Users\winvpn-gone\AppData\Roaming\rasphone.pbk".to_string()),
        ];
        let (mut hung, mut lines) = (Vec::new(), Vec::new());
        let mut hang = |i: usize, wait: Duration| {
            hung.push((i, wait));
            Err("RasHangUpW failed: 5".to_string())
        };
        let present = HashSet::from([me]);
        hang_up_owned(&profiles, &present, &conns, Duration::ZERO, &mut hang, &mut |l| lines.push(l.to_string()));
        assert_eq!(hung, vec![(1, Duration::ZERO)]);
        assert_eq!(
            lines,
            vec!["RAS connection of a logged-off user could not be ended: WinVPN-1F1E2D3C (RasHangUpW failed: 5)"]
        );
    }

    #[test]
    fn the_real_lists_hang_up_nothing_while_this_user_is_present() {
        // Over SSH this process sees no RAS connection (the RAS spike); at the desktop any WinVPN connection is this
        // user's, who is present. Either way nothing is hung up and nothing is waited for.
        let present = HashSet::from([Sid::current_user().unwrap().to_string()]);
        let mut lines = Vec::new();
        hang_up_absent_ras(&present, Duration::ZERO, &mut |l| lines.push(l.to_string()));
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn a_standard_user_cannot_read_the_sessions_users() {
        // WTSQueryUserToken needs SeTcbPrivilege (SYSTEM): elsewhere the answer is an error, so nothing is dropped.
        if Sid::current_user().unwrap() != Sid::local_system() {
            assert!(user_sids().is_err());
        }
    }
}
