---
title: What This Manual Covers
description: The daemon, the operator command and the NSS shim as built, and where the contract, netd's side of the channel and the kernel mechanisms are described instead.
---

This manual covers the resolvd source tree as of release 0.1.5:

| Component | Package | Installed as |
|---|---|---|
| The daemon | `dev.peios.resolvd` | `/usr/sbin/resolvd` [*coverage.daemon-installed-path] |
| The operator command | `dev.peios.resolv` | `/usr/bin/resolv` [*coverage.resolv-installed-path] |
| The NSS shim | `dev.peios.resolvd-nss` | `/usr/lib/x86_64-linux-peios/libnss_peios_net.so.2` [*coverage.shim-installed-path] |

## Other packaged files [*coverage.packaged-files]

`dev.peios.resolvd` also ships the constant `/usr/etc/resolv.conf`, the
service definition and port reservation seeds under `/usr/share/regim/`,
the registry reference `/usr/share/regman/resolvd.regman`, and the
`resolvd(8)` page; `dev.peios.resolv` ships `resolv(1)`.

Each package has a matching `-debuginfo` package, and
`dev.peios.resolvd-debugsource` carries the sources for all three.

## The source tree

The source is one workspace of five crates, and the split is visible in
what each part of the system can do:

| Crate | What it is |
|---|---|
| `dns` | The DNS wire codec: names, messages, records. No I/O and no policy. |
| `libresolv` | The native channel's types, MessagePack codec and framing. No I/O beyond framing. |
| `resolvd` | The engine, the cache, the stub door's DNS rendering, and the daemon around them. |
| `resolv` | The operator command. |
| `nss` | The shim. Built on `libresolv` and libc, without libpeios (§7.1). |

## Covered elsewhere

**The contract.** What any resolver standing in resolvd's place has to
do is PSPU §6: the doors (PSPU §6.3), the native channel's framing and
control object (PSPU §6.4), the requests (PSPU §6.5), outcomes and
validation (PSPU §6.6), the resolution model (PSPU §6.7), the stub door
(PSPU §6.8), the network manager channel (PSPU §6.9), the shim
(PSPU §6.10), and the limits (PSPU §6.B). Where
a chapter here touches the contract it cites it and adds only what
resolvd does.

**netd's side of the channel.** Which interfaces appear in a snapshot,
how their servers and domains are merged from profile and lease, and
when a snapshot is sent, are netd's, and are described in the netd TRM.
This manual covers what resolvd does with a snapshot once it has one.

**Kernel mechanisms.** Registry watches, access checks, file
descriptors and port reservations are described in the Peios Kernel
TRM. This manual says which of them resolvd uses and how.
