---
title: Constants and Limits
description: Every fixed value in resolvd, the NSS shim and resolv, with the article that describes it, and the paths and addresses they use.
---

The articles cited are authoritative; this appendix collects their
values in one place.

## Limits and timers

| Bound | Value | Described in |
|---|---|---|
| Native request size ceiling (payload) | 65 536 bytes | §5.1 |
| Maximum buffered native frame | 65 540 bytes | §5.1 |
| Native connection read chunk | 4 096 bytes | §5.1 |
| Native request delivery bound | 5 s | §5.1 |
| Native connections still sending a request | 256 | §5.1 |
| Queued native replies | 256 | §2.5 |
| Queued stub TCP replies | 256 | §2.5 |
| Native reply write deadline | 1 s total | §5.1 |
| Stub TCP connections still sending a query | 256 | §6.1 |
| Stub TCP query delivery bound | 10 s | §6.1 |
| Stub TCP message buffer | 65 537 bytes | §6.1 |
| Stub TCP read chunk | 4 096 bytes | §6.1 |
| Stub UDP read buffer | 4 096 bytes | §6.1 |
| Stub TCP reply write deadline | 1 s total | §6.2 |
| Classic UDP reply limit, no `OPT` | 512 bytes | §6.2 |
| EDNS0 payload size advertised, upstream and stub | 1 232 bytes | §4.7, §6.2 |
| Transaction timeout | 2 s | §4.6 |
| Attempts per question (all candidates and transports) | 3 | §4.6 |
| Demotion period | 30 s | §4.6 |
| Service descriptor limit | 16 384 | §2.1 |
| Listener retry delay after accept error | 250 ms | §2.5, §9.1 |
| Upstream transactions in flight | 4 096 | §4.6 |
| Upstream UDP read buffer | 4 096 bytes | §4.7 |
| Cache entries | 8 192 | §4.5 |
| Positive lifetime cap | 86 400 s | §4.5 |
| Negative lifetime cap | 300 s | §4.5 |
| CNAME chase depth in `lookup` | 16 | §4.9 |
| netd reconnect backoff | 0.5 s doubling to 10 s | §3.2 |
| netd channel write timeout | 2 s | §3.1 |
| netd frame ceiling | 65 536 bytes | §3.1 |
| netd channel read chunk | 8 192 bytes | §3.1 |
| Registry watch event buffer | 16 384 bytes | §2.3 |
| Kernel hostname read buffer | 256 bytes | §3.3 |
| Unknown-value nesting depth, native requests | 32 | §5.1 |
| NSS shim read and write timeout | 10 s | §7.1 |
| DNS label | 63 bytes | §4.1 |
| DNS name on the wire | 255 bytes | §4.1 |

## Rights

| Right | Value | Described in |
|---|---|---|
| `RESOLVER_QUERY` | `0x00000001` | §5.2 |
| `RESOLVER_CONTROL` | `0x00000002` | §5.2 |
| `RESOLVER_ALL_ACCESS` | `0x000F0003` | §5.2 |

## Paths, addresses and identities

| Item | Value | Described in |
|---|---|---|
| Daemon | `/usr/sbin/resolvd` | §2.1 |
| Operator command | `/usr/bin/resolv` | §8.1 |
| NSS shim | `/usr/lib/x86_64-linux-peios/libnss_peios_net.so.2` | §7.1 |
| Runtime directory | `/run/resolvd`, mode `0755` | §2.4 |
| Native socket | `/run/resolvd/resolv.sock`, mode `0666` | §2.4 |
| Stub listener | `127.0.0.53:53`, UDP and TCP | §2.4 |
| netd control socket | `/run/netd/control.sock` | §3.1 |
| Upstream port | 53 | §4.7 |
| Constant resolver configuration | `/usr/etc/resolv.conf` | §2.1 |
| Service definition seed | `/usr/share/regim/resolvd-service.reg` | §2.1 |
| Port reservation seed | `/usr/share/regim/resolvd-port.reg` | §2.1 |
| Registry reference | `/usr/share/regman/resolvd.regman` | §2.1 |
| Service SID | `S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966` | §2.1 |
| Fallback scope key | `fallback` | §4.4 |
