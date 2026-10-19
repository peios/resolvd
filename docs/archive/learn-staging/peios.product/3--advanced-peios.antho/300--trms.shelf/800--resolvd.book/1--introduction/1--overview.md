---
title: Overview
description: resolvd is the one process on a Peios machine that answers names — three doors in front of one engine — and the handful of decisions that would not be guessed from its name.
---

**resolvd** is the Peios stub resolver. It is the one process on a
machine that answers names: a DNS client that answers from what it knows
about the machine, from its cache, or by forwarding to an upstream
server. It is not a recursive resolver and not an authoritative server.

The contract it implements is the Name Resolution Interface, PSPU §6.
This manual describes resolvd 0.1.5 as built: the order it does things
in, the limits it applies, and what it does where the contract leaves a
choice.

## Three doors, one engine

A question reaches resolvd by one of three doors (PSPU §6.3):

| Door | Where | Who uses it |
|---|---|---|
| Native socket | `/run/resolvd/resolv.sock` | The `resolv` command, the NSS shim, Peios tools |
| Stub listener | `127.0.0.53:53`, UDP and TCP | Programs that speak DNS themselves |
| NSS shim | `libnss_peios_net.so.2`, loaded into every glibc process | `getaddrinfo`, `gethostbyname` and friends |

The shim is not a separate resolver: it is a client of the native
socket. The native socket and the stub listener both hand their
questions to the same engine inside the daemon, and the engine is the
only thing that decides an answer.

## What is surprising about it

**It owns no network configuration.** The servers, search domains and
addresses of each interface arrive from netd over netd's control socket,
as a whole snapshot each time anything changes. The registry holds only
the fallbacks — servers to use when no interface offers any, extra
search domains — and the static names that replace `/etc/hosts`. resolvd
never writes `/etc/resolv.conf`; the file it ships is a constant that
points at the stub listener.

**A question goes to one interface.** Each interface's contribution is
a *scope*, and every name is routed to exactly one of them. Nothing is
ever asked of every interface's servers at once. A single-label name is
never sent upstream bare, and the cache is partitioned by scope, so an
answer learned through a VPN disappears when the VPN's servers change or
the VPN goes away.

**One thread, and an engine with no I/O.** The daemon is a single
`poll` loop. The engine inside it is a pure state machine: it takes
questions, upstream replies and the passage of time, and returns actions
— bytes to send, transactions to abandon, answers to deliver. Every
socket is the loop's. Everything is therefore serialised, which is why a
reply that cannot be written promptly holds up every other client
(§9.4).

**It holds no privilege.** resolvd runs under its own virtual service
account. Port 53 is reached through a port reservation granted to its
service SID, not through a capability.

**It does not wait for the network.** resolvd reports itself ready as
soon as its two listening doors are open. `localhost`, the machine's own
name and the registry's static names are answered with no network and no
netd at all.

**It does not validate.** No DNSSEC validation is performed, and every
answer from every door is reported `unvalidated`.
