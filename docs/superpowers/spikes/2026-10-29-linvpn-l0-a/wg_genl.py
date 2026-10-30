#!/usr/bin/python3 -I
"""WG_CMD_GET_DEVICE over generic netlink as the calling user; prints the kernel's answer for each ifname given."""
import errno, os, socket, struct, sys

def nla(t, data):
    ln = 4 + len(data)
    return struct.pack("HH", ln, t) + data + b"\0" * ((4 - ln % 4) % 4)

def genl(fam, cmd, flags, attrs, seq):
    body = struct.pack("BBH", cmd, 1, 0) + attrs
    return struct.pack("IHHII", 16 + len(body), fam, flags, seq, 0) + body

def messages(buf):
    off = 0
    while off + 16 <= len(buf):
        ln, typ, flags, seq, pid = struct.unpack("IHHII", buf[off:off + 16])
        yield typ, seq, buf[off:off + ln]
        off += (ln + 3) & ~3

nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
nl.send(genl(0x10, 3, 0x1, nla(2, b"wireguard\0"), 1))  # CTRL_CMD_GETFAMILY, no ACK
fam = None
for typ, seq, m in messages(nl.recv(65536)):
    off = 20
    while off < len(m):
        alen, atyp = struct.unpack("HH", m[off:off + 4])
        if atyp == 1:
            fam = struct.unpack("H", m[off + 4:off + 6])[0]
        off += (alen + 3) & ~3
print("uid", os.getuid(), "wireguard family id", fam)
for i, name in enumerate(sys.argv[1:], start=10):
    nl.send(genl(fam, 0, 0x1 | 0x4 | 0x300, nla(2, name.encode() + b"\0"), i))  # WG_CMD_GET_DEVICE dump + ACK
    for typ, seq, m in messages(nl.recv(65536)):
        if typ == 2:
            err = struct.unpack("i", m[16:20])[0]
            print(f"ifname={name!r}: NLMSG_ERROR {err} ({errno.errorcode.get(-err, 'ok')}: {os.strerror(-err) if err else 'ack'})")
        else:
            print(f"ifname={name!r}: message type {typ} ({len(m)} bytes)")
