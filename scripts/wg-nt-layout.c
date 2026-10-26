/* The layout of wireguard-nt's configuration structs as MSVC lays them out (2b plan, Task 14, Step 1). Compiled
 * on Windows against the pinned SDK's include/wireguard.h; the numbers must equal the offsets documented in
 * crates/helper/src/windows/wg_nt.rs (INTERFACE 80, PEER 136, ALLOWED_IP 24). Prints one `name value` per line. */
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <stddef.h>
#include <stdio.h>
#include "wireguard.h"

#define SIZE(t) printf("sizeof(%s) %u\n", #t, (unsigned)sizeof(t))
#define OFF(t, f) printf("%s.%s %u\n", #t, #f, (unsigned)offsetof(t, f))

int main(void)
{
    SIZE(WIREGUARD_INTERFACE);
    OFF(WIREGUARD_INTERFACE, Flags);
    OFF(WIREGUARD_INTERFACE, ListenPort);
    OFF(WIREGUARD_INTERFACE, PrivateKey);
    OFF(WIREGUARD_INTERFACE, PublicKey);
    OFF(WIREGUARD_INTERFACE, PeersCount);
    SIZE(WIREGUARD_PEER);
    OFF(WIREGUARD_PEER, Flags);
    OFF(WIREGUARD_PEER, Reserved);
    OFF(WIREGUARD_PEER, PublicKey);
    OFF(WIREGUARD_PEER, PresharedKey);
    OFF(WIREGUARD_PEER, PersistentKeepalive);
    OFF(WIREGUARD_PEER, Endpoint);
    OFF(WIREGUARD_PEER, TxBytes);
    OFF(WIREGUARD_PEER, RxBytes);
    OFF(WIREGUARD_PEER, LastHandshake);
    OFF(WIREGUARD_PEER, AllowedIPsCount);
    SIZE(WIREGUARD_ALLOWED_IP);
    OFF(WIREGUARD_ALLOWED_IP, Address);
    OFF(WIREGUARD_ALLOWED_IP, AddressFamily);
    OFF(WIREGUARD_ALLOWED_IP, Cidr);
    OFF(WIREGUARD_ALLOWED_IP, Flags);
    SIZE(SOCKADDR_INET);
    return 0;
}
