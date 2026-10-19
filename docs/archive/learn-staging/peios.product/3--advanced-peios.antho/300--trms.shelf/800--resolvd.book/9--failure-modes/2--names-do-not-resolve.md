---
title: Names Do Not Resolve
description: The common ways resolution fails while resolvd is running — no scopes, unreachable servers, single labels that never leave the machine, an exclusive scope, overload, stale answers — what each looks like and how to get back to a known state.
---

## Everything needing the network is `unavailable`

**Looks like:** `resolv query example.com` exits 3; the stub answers
`SERVFAIL`; `getaddrinfo` returns `EAI_AGAIN`. `localhost`, the
hostname and static names still answer.

**Check `resolv status`:**

- **`netd not connected` and `scopes (none)`.** resolvd has never had a
  snapshot. Without fallback servers nothing can be asked (§4.4). Start
  netd; resolvd reconnects within ten seconds of netd's socket appearing
  (§3.2) and the first snapshot brings the scopes.
- **Scopes listed, but none has a server.** Interfaces with no servers
  take no part in routing (§4.4). Either the profiles and leases supply
  no servers, or the offered addresses or explicit zones were invalid
  (§4.7). Configure `FallbackServers`
  (§2.3), or give the profile servers.
- **Servers listed and marked `(demoted)`.** Every server's last failure
  was less than 30 seconds ago (§4.6). `upstream_failed` rising shows
  it. Questions are still sent to demoted servers, so service returns as
  soon as one answers.
- **The servers listed are link-local (`fe80::…`).** Check that the
  scope names the intended interface and that it still exists. resolvd
  sends through that interface for UDP and TCP (§4.7). Link-local servers
  belong in an interface profile, not the unscoped fallback list.

## A single label is `notfound` at once

**Looks like:** `resolv query printer` exits 2 without delay, with
source `local`.

No search domain applies (§4.3). Check the `domain` lines in `status`.
A scope's domains count only while it has a server; while an exclusive
scope takes every question (§4.4), only its domains apply and
`ExtraSearchDomains` is ignored.
A single label is never sent bare, so with no domain it is answered
locally.

## Names meant for the VPN go elsewhere

An exclusive scope takes every question only while it is at `addressed`
or better and has at least one server (§4.4). A VPN interface whose
servers have not arrived yet, or are missing from its profile, is not
exclusive for routing, and names go to the other interfaces' servers in
the meantime. `status` shows the VPN scope with `exclusive` and no
`server` lines.

## An answer is wrong or stale

Cached answers live up to a day (§4.5). They are discarded for a scope
when its server list changes, and for everything by
`resolv flush` (§5.3), which needs `RESOLVER_CONTROL`. A static name in
`Hosts\` overrides DNS at once, with no flush (§4.2).

To see what the network says now, use
`resolv query <name> --no-cache`. It skips the cache lookup, but the
answer it gets is still stored, replacing the cached one (§4.5).

## Answers are slow

Each candidate can take up to six seconds of timeouts before it is
`unavailable`, longer with truncated replies retried over TCP (§4.6).
A dead first server costs two seconds per question until it is demoted;
after that it is asked last, for 30 seconds, and the cycle repeats if
it is still dead.

A UDP reply that does not match its query — a server that does not echo
the question's case exactly, for instance — is ignored (§4.8). A later
matching reply can still answer the transaction. Only if none arrives by
the original two-second deadline does the attempt time out, demote the
server, and add to `upstream_failed` without adding to `upstream_answered`.

## `refused` is rising

At least 4 096 transactions are outstanding (§4.6), and new questions that need
the network are answered `unavailable` at once. Cached and synthetic
answers are unaffected. The ceiling clears as transactions complete,
within two seconds of each being sent.

## Getting back to a known state

A new resolvd discards the cache, the demotions and the counters,
re-reads the registry, and takes a fresh snapshot from netd; nothing is
persisted. `svctl restart resolvd` is enough: the new process replaces
the socket its predecessor left (§2.4).

The exception is the first start after an upgrade from a resolvd whose
DACL did not name its own account (§2.4). That older resolvd's directory
and socket shut the new one out, and it exits with `native socket:
Permission denied (os error 13)` until they are gone. Remove them once
as SYSTEM, or reboot:

```sh
svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd
```
