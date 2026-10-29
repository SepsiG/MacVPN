//! Who is on the other end of a loopback TCP connection: the IPv4 TCP table with owning PIDs
//! (`GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)`). The management interface of `openvpn.exe` is a
//! loopback port any local process could have bound first (Windows even lets a second socket bind an address in
//! use with `SO_REUSEADDR`), so before the service sends the management password it checks that the socket that
//! accepted *its* connection belongs to the `openvpn.exe` it started.
//!
//! The row's state is not used: Windows 11 reports a wrong `dwState` for some live connections, most often one a
//! listener accepted on a SYN retry (the connect came while nobody listened yet, as the service's does while OpenVPN
//! starts): one end of an established connection shows as CLOSED, LISTEN, FIN_WAIT1 or 0 for a second or more,
//! while the other end's row says ESTABLISHED and data flows. The connection is found by its two ends instead (no
//! other live connection has them), and a row without an owner (PID 0: TIME_WAIT) never counts.

use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// One IPv4 connection of the table: local end, remote end, state, owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub state: u32,
    pub pid: u32,
}

fn endpoint(addr: u32, port: u32) -> SocketAddrV4 {
    // The address is in network byte order in memory; the port in network byte order in the low 16 bits.
    SocketAddrV4::new(Ipv4Addr::from(addr.to_ne_bytes()), u16::from_be((port & 0xFFFF) as u16))
}

/// The IPv4 TCP table with owning PIDs; any failure is an error (never a partial table).
pub fn rows() -> io::Result<Vec<Row>> {
    let mut size = 0u32;
    for _ in 0..8 {
        // u32 elements: the table is a u32 count followed by rows of u32 fields.
        let mut buf = vec![0u32; (size as usize).div_ceil(4).max(1)];
        let mut len = (buf.len() * 4) as u32;
        // SAFETY: `buf` is valid for writes of `len` bytes and 4-byte aligned; `len` is a valid in/out pointer.
        let status = unsafe {
            GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut len, 0, u32::from(AF_INET), TCP_TABLE_OWNER_PID_ALL, 0)
        };
        if status == ERROR_INSUFFICIENT_BUFFER {
            size = len.max(size + 4);
            continue;
        }
        if status != NO_ERROR {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let count = buf[0] as usize;
        let row_words = size_of::<MIB_TCPROW_OWNER_PID>() / 4;
        let needed = count.checked_mul(row_words).and_then(|n| n.checked_add(1));
        if needed.is_none_or(|n| n > buf.len() || n * 4 > len as usize) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a TCP table larger than its buffer"));
        }
        return Ok(buf[1..1 + count * row_words]
            .chunks_exact(row_words)
            .map(|w| Row { state: w[0], local: endpoint(w[1], w[2]), remote: endpoint(w[3], w[4]), pid: w[5] })
            .collect());
    }
    Err(io::Error::other("the TCP table kept growing"))
}

/// The PID owning the other end of `stream`, a connected IPv4 socket (see [`owner_of`]). `None`: no owner, or the
/// table could not be read (fail closed).
pub fn peer_pid(stream: &TcpStream) -> Option<u32> {
    let (SocketAddr::V4(me), SocketAddr::V4(peer)) = (stream.local_addr().ok()?, stream.peer_addr().ok()?) else {
        return None;
    };
    owner_of(&rows().ok()?, me, peer)
}

/// The owner of the other end of the connection `me` → `peer`: the rows whose local end is `peer` and whose remote
/// end is `me`, whatever their state (see the module comment), with an owner. `None`: no such row, or more than one
/// with different owners.
fn owner_of(rows: &[Row], me: SocketAddrV4, peer: SocketAddrV4) -> Option<u32> {
    let mut owners = rows.iter().filter(|r| r.local == peer && r.remote == me && r.pid != 0).map(|r| r.pid);
    let first = owners.next()?;
    owners.all(|p| p == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn the_other_end_of_a_loopback_connection_is_found_with_its_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert_eq!(peer_pid(&client), Some(std::process::id()));
        assert_eq!(peer_pid(&server), Some(std::process::id()));
        // The table has both ends with this process as the owner.
        let SocketAddr::V4(c) = client.local_addr().unwrap() else { panic!() };
        assert!(rows().unwrap().iter().any(|r| r.local == c && r.pid == std::process::id()));
    }

    #[test]
    fn the_owner_is_found_by_the_two_ends_whatever_the_state() {
        let a = |port| SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let (me, peer) = (a(40001), a(50001));
        let row = |local, remote, state, pid| Row { local, remote, state, pid };
        // Windows' wrong states of a live connection (CLOSED, LISTEN, FIN_WAIT1, 0) do not hide its owner.
        for state in [0, 1, 2, 5, 6] {
            assert_eq!(owner_of(&[row(peer, me, state, 7), row(me, peer, 5, 9)], me, peer), Some(7));
        }
        // Not the other end: our own row, another connection's, the listener.
        assert_eq!(owner_of(&[row(me, peer, 5, 9), row(peer, a(40002), 5, 7), row(peer, a(0), 2, 7)], me, peer), None);
        // Without an owner (TIME_WAIT, a closed socket), or two different owners: none.
        assert_eq!(owner_of(&[row(peer, me, 11, 0)], me, peer), None);
        assert_eq!(owner_of(&[row(peer, me, 5, 7), row(peer, me, 11, 0)], me, peer), Some(7));
        assert_eq!(owner_of(&[row(peer, me, 5, 7), row(peer, me, 5, 8)], me, peer), None);
    }

    /// Connections accepted on a SYN retry (the connect came before the listener, as the service's does while
    /// OpenVPN starts): Windows reported a wrong state for one end of some of them, and the old check (ESTABLISHED
    /// rows only) found no owner.
    #[test]
    fn the_owner_of_a_connection_accepted_on_a_syn_retry_is_found() {
        let me = std::process::id();
        let tries: Vec<_> = (0..6)
            .map(|_| {
                std::thread::spawn(move || {
                    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
                    let late = std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
                        listener.accept().unwrap().0
                    });
                    let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
                    let server = late.join().unwrap();
                    (peer_pid(&client), peer_pid(&server))
                })
            })
            .collect();
        for t in tries {
            assert_eq!(t.join().unwrap(), (Some(me), Some(me)));
        }
    }
}
