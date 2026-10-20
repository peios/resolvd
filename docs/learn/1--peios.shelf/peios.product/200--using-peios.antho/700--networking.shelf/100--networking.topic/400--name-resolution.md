---
title: Diagnosing Name Resolution
type: how-to
description: Identify why a name fails and verify the resolver's chosen path.
related:
  - peios/networking/the-net-command
  - peios/networking/configuring-profiles
  - peios/reference/resolvd/the-nss-shim/the-module
---

Use `resolv` to identify whether a name is missing, resolution is unavailable,
or an unexpected interface is being used. Interface DNS policy belongs to
netd. resolvd applies that policy and machine-wide fallback and static-name
settings.

## Before you start

- Install resolvd and the `resolv` operator command.
- Identify the failing name and the network it should use.
- Obtain registry write access before changing policy. Queries use the
  resolver's separate query permission, granted publicly by default.

`resolv(1)` owns command syntax and exit statuses. The regman entry for
`Machine\System\Network\Dns` owns machine-wide settings. Do not edit
`/etc/hosts`, `/etc/resolv.conf`, or `nsswitch.conf` to change this policy.

## Check a name first

1. Read the effective state:

   ```sh
   resolv status
   ```

2. Query the failing name. For example:

   ```sh
   resolv query example.org
   resolv lookup example.org
   ```

3. Compare an answer obtained without consulting the cache:

   ```sh
   resolv query example.org --no-cache
   ```

The final command bypasses cache lookup but can store the resulting answer.
Read the reported outcome, source, server, and interface. If connecting to
an address also fails, investigate
[connectivity](~peios/reference/netd/failure-modes/failure-modes).

## Where the servers come from

netd sends resolvd each interface's servers, domains, and addresses as a
**scope**. Compare the scopes in `resolv status` with `net status` and the
intended interface profile.

Use [Configuring
Profiles](~peios/networking/configuring-profiles#taking-the-offer-with-adjustments)
to change offered or explicit interface DNS settings. A profile change can
restart address clients; follow that guide's recovery checks.

Machine-wide fallback servers, extra search domains, and static names live
under `Machine\System\Network\Dns`. They apply after a successful complete
configuration read. A read failure retains the previous configuration and is
logged. A lost registry watch can prevent later changes from being observed.

### Verify which interface gets a name

A query selects one scope. The order is exclusive scope, longest matching
search domain, matching reverse subnet, default route, then lowest metric
among up scopes with servers. Fallback servers are considered only when no
earlier step chooses a scope.

An exclusive scope must be at `addressed` or better. It still wins without
servers; upstream work then becomes unavailable rather than using another
interface. At `link` alone, the exclusive rule does not apply. Verify the
interface state as well as its flags when diagnosing VPN name routing.

A bare name such as `printer` requires a search domain. All up scopes can
contribute domains, including scopes without servers. A qualifying exclusive
scope supplies only its own domains. With no applicable domain, a bare name
is answered locally as not found and is never sent upstream unchanged.

See the [routing](~peios/reference/resolvd/the-engine/scope-routing) and
[search
expansion](~peios/reference/resolvd/the-engine/single-label-expansion)
chapters for tie-breaking and failure behavior.

## Static names

With registry write access, add a static name when this machine should answer
it without DNS. Replace the sample address with the intended host:

```sh
reg new Machine/System/Network/Dns/Hosts
reg set Machine/System/Network/Dns/Hosts printer sz:10.0.2.9
resolv query printer
resolv reverse 10.0.2.9
```

Verify both directions. Static names apply without a cache flush after the
configuration is read. Synthetic localhost names take precedence over static
names. The [synthetic-name
chapter](~peios/reference/resolvd/the-engine/synthetic-names)
describes hostname, reverse, and `.local` handling.

## The `resolv` command

`resolv query` reports individual records and where the answer came from.
`resolv lookup` returns addresses and a canonical name. `resolv reverse`
queries names for an address. `resolv status` reports scopes and counters.

`resolv flush` clears the shared cache and requires the resolver control
right. Registry editing has separate permissions. Every command exchange
has a ten-second deadline; a failed exchange is not evidence that a name
is absent. See `resolv(1)` for scripting contracts.

## Not found versus unavailable

| Observation | Next check |
|---|---|
| `notfound` from DNS or cache | Check spelling and compare a query without cache lookup. |
| `notfound` locally for a bare name | Check applicable search domains. |
| `unavailable` | Check the selected scope, its servers, and reachability. |
| netd disconnected, no scopes | Check netd; only local answers and configured fallbacks are available. |
| netd disconnected, scopes listed | These are the last snapshot, not a fresh view of the links. |
| A demoted server | Check its failures; healthy servers are tried before demoted ones. |
| A stale answer | Check static overrides, then compare a query without cache lookup. |
| Access denied | Inspect the native control permission separately from stub reachability. |

Read the service log when startup or updates fail:

```sh
evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 40'
```

A restart replaces resolvd's stale socket and clears transient state.
Do not remove its runtime directory as a routine diagnostic step. Inspect
permissions and the exact startup error using the
[failure
guide](~peios/reference/resolvd/failure-modes/resolvd-cannot-be-reached).

## Three doors

Programs reach the same resolver engine through the native socket, the local
DNS stub at `127.0.0.53`, or glibc's Name Service Switch (NSS) module.
Native applications can use `libresolvd.so`; other DNS clients use the
constant resolver configuration pointing at the stub.

A direct query to another server tests that server and bypasses normal scope
selection. It does not establish how Peios applications resolve the name.

## Implementation boundaries {#what-is-not-there-yet}

resolvd does not implement DNSSEC validation, DNS over TLS, multicast DNS,
or per-program resolution policy. Answers report `unvalidated`. Allowed
callers use the same policy; native query access controls permission to ask.

## Going deeper

- PSPU, Name Resolution Interface, defines the protocol contract.
  defines request and outcome contracts.
- [resolvd TRM](~peios/reference/resolvd/introduction/overview)
  explains the implementation and its limits.
- [netd's resolver
channel](~peios/reference/netd/what-netd-publishes/the-resolver-channel)
  describes the live network information sent to resolvd.
