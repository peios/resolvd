---
title: Name resolution
type: guide
description: Check a failing name, configure interface DNS or static names, verify the server and scope used, and distinguish missing names from unavailable resolution.
related:
  - peios/networking/overview
  - peios/networking/configuring-profiles
  - peios/linux-compatibility/name-service-switch
  - peios/name-resolution-interface/scope-and-roles
---

Use `resolv` to check which DNS settings Peios is using and where an answer
came from. On the desktop, use **DNS** in
[Network Manager](https://learn.peios.org/peios/system-tools/network-manager/#finding-the-right-view).

Network-supplied DNS belongs to an interface's profile. Machine-wide
fallback servers, extra search domains and static names live under
`Machine\System\Network\Dns`. Do not edit `/etc/hosts`,
`/etc/resolv.conf` or `nsswitch.conf` to configure Peios name resolution.

## Check a name first

```sh
resolv status
resolv query example.org
resolv lookup example.org
```

Replace `example.org` with the name that fails. `query` shows the outcome,
source, server and interface; `lookup` shows addresses as `getaddrinfo`
sees them. For a fresh network answer, use:

```sh
resolv query example.org --no-cache
```

This skips cache lookup but still stores the new answer. If only an IP
connection works, use the result to choose the next check under
[Not found versus unavailable](#not-found-versus-unavailable). If the IP
connection also fails, start with [connectivity](~peios/networking/diagnostic-tools#start-with-the-symptom).

## Where the servers come from

`resolv status` shows netd's connection and the scopes currently in use.
A **scope** is an interface's servers, domains and addresses:

```text
hostname   workshop
netd       connected
cache      12 entries

eth0  metric 100  [default-route]
  server   10.0.2.3
  domain   lan
  subnet   10.0.2.15/24
```

netd sends that live information to resolvd; offered server lists are not
written to a resolver configuration file. Match the scope against the
interface and profile in `net status`.

To change an interface's DNS, use its profile's `Dns.Offered`,
`Dns.Servers`, `Dns.Domains`, `Dns.Default` and `Dns.Exclusive` settings in
[Configuring profiles](~peios/networking/configuring-profiles#taking-the-offer-with-adjustments).
A profile edit can restart address clients, so use that guide's recovery
checklist even for a DNS change.

For machine-wide settings, use `FallbackServers` and `ExtraSearchDomains`
on `Machine\System\Network\Dns`, or Network Manager's DNS **Settings**:

- `FallbackServers` is used only when no up interface supplies a server.
  It is not failover for an interface whose servers time out.
- `ExtraSearchDomains` adds domains after the applicable interface domains.
  It is not applied while an exclusive scope takes all queries.
- These registry changes apply live to later questions. Check the new
  fallback-server list in `resolv status` and repeat the lookup. Extra
  search domains are not listed in that status output: verify them with a
  lookup of the intended bare name. No restart is normally needed. A failed
  registry watch or a malformed value can prevent the
  expected change; the [registry chapter](~peios/reference/resolvd/startup-and-configuration/registry-configuration)
  describes the log messages.

### Verify which interface gets a name

A query goes to one interface's servers, never to all interfaces at once.
The operator-relevant order is:

1. An exclusive scope, if it has a server and is at least `addressed`.
2. The scope with the most-specific matching search domain.
3. For a reverse lookup, a scope whose subnet contains the address.
4. A scope that claims the default route, otherwise the lowest-metric
   eligible scope.
5. Fallback servers only when no up scope has a server.

> [!WARNING]
> `Dns.Exclusive = 1` alone is not a guarantee against DNS going through
> another network. An exclusive interface with no server, or one only at
> `link`, does not qualify. Verify its address and `server` lines before
> relying on it for VPN name privacy.

A single-label name such as `printer` is asked only after a search domain
is appended. With no applicable domain it is not found locally and no
query leaves the machine. A name with a dot between labels is not
expanded. Use a fully qualified name to check whether the problem is the
search list. The [scope-routing](~peios/reference/resolvd/the-engine/scope-routing)
and [single-label expansion](~peios/reference/resolvd/the-engine/single-label-expansion)
chapters contain the full selection and tie-breaking algorithms.

## Static names

For a name that this machine should answer without DNS, add a value under
`Hosts`. You need registry write access. Replace this example name and
address with the intended host:

```sh
reg new Machine/System/Network/Dns/Hosts
reg set Machine/System/Network/Dns/Hosts printer 10.0.2.9
```

Then verify both directions:

```sh
resolv query printer
resolv reverse 10.0.2.9
```

An exact static name wins over DNS at every resolver entry point, including
programs using the DNS stub. Static-name changes are live and need no cache
flush. `localhost`, the machine's own hostname and their reverses are
answered without configuration. The [synthetic-name chapter](~peios/reference/resolvd/the-engine/synthetic-names)
documents precedence, record types and reverse-name collisions.

`.local` names are not sent upstream. mDNS is not implemented and LLMNR
is never used. An explicitly configured static `.local` name can still
answer locally.

## The `resolv` command

| Command | What to check |
|---|---|
| `resolv status` | Scopes, servers (including those demoted after failures), fallback servers, cache size and counters. |
| `resolv query <name> [type] [--no-cache]` | One question, default type A; outcome, source (`synthetic`, `hosts`, `cache`, `dns` or `local`), server, interface and records. |
| `resolv lookup <name>` | The addresses and canonical name as `getaddrinfo` sees them. |
| `resolv reverse <address>` | The names for an address. |
| `resolv flush` | Clear the cache; requires `RESOLVER_CONTROL`. |

Queries and status need `RESOLVER_QUERY`, granted to everyone by the
default control descriptor. Flush is granted to SYSTEM and Administrators
by default. `Machine\System\Network\Dns ControlSecurity` can change those
grants. Registry edits require separate write access.

Exit 0 means found or a successful status/flush, 2 means `notfound`, and 3
means `unavailable`. Exit 1 includes an unreachable daemon, access denial,
protocol error or bad type/address; unrecognized usage exits 64. See the
[command reference](~peios/reference/resolvd/the-resolv-command/the-resolv-command)
for accepted record types and exact output.

Unlike `dig`, `resolv query` reports cache use and the chosen interface.
Every network answer currently says `unvalidated`; this version performs
no DNSSEC validation.

## Not found versus unavailable

| Result or symptom | Meaning and next check |
|---|---|
| `notfound` with source `dns` or `cache` | The server said the name does not exist. Negative answers may be cached for a few minutes. Check spelling and use `--no-cache` if the record just changed. |
| `notfound` with source `local` for a bare name | Check search-domain lines in `resolv status`. A scope without servers contributes no search domains. |
| `unavailable` | No usable DNS path, or attempts failed. It is never cached as a missing host; programs get a retryable failure. Check scopes, server reachability and policy. |
| `netd not connected`, no scopes | resolvd has not received a snapshot. Check `net status` and netd's service; without fallbacks only local/static names can answer. |
| `netd not connected`, scopes still listed | These are the last received scopes and remain in use. Do not assume they describe the current links. |
| Server marked `(demoted)` | It recently failed. It is tried after healthy servers, not permanently disabled. Check the server and network path. |
| Wrong or stale answer | Compare a `--no-cache` query. A static name can override DNS; administrators can flush the cache if needed. |
| `resolv: access denied` | Check the native control object's query right. It is separate from reachability of the DNS stub. |
| Daemon unreachable or repeated failures | Read `evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 40'` and the [failure-mode guide](~peios/reference/resolvd/failure-modes/resolvd-cannot-be-reached). |

On restart, resolvd removes its stale socket and binds a new one. Its
directory and socket descriptors retain full access for its own service
identity so this replacement can succeed. See the
[socket chapter](~peios/reference/resolvd/startup-and-configuration/sockets).
If startup reports a permission error, inspect the actual descriptors and
logs; do not delete the runtime directory merely because a restart occurred.

For comparison with the local DNS stub, Experimental includes
`dig @127.0.0.53 example.org A`. A direct query to some other server tests
that server, not Peios's normal scope selection. All DNS traffic still
meets PNP.

## Three doors

resolvd is Peios's stub resolver: a DNS client forwarding to upstream
servers, not a recursive or authoritative server. Its shared policy and
cache are reached through libc's `getaddrinfo`, DNS on `127.0.0.53`, or the
native socket `/run/resolvd/resolv.sock` used by `resolv`.

The glibc hosts database is fixed to `libnss_peios_net.so.2`, without
`files` or `dns` fallbacks. The constant `/etc/resolv.conf` points other
DNS clients, including Go and musl programs, at the stub. A bare name gets
the same search-domain treatment through each route. Native replies also
carry TTLs, source and validation state. See the
[resolver overview](~peios/reference/resolvd/introduction/overview)
and [name-resolution interface](~peios/reference/pspu/name-resolution-interface/scope-and-roles)
for the entry-point contracts.

## What is not there yet

DNSSEC validation, DNS over TLS, mDNS and per-program resolution policy
are not implemented in this version. Native query access is checked, but
allowed callers use the same resolution policy.

## Going deeper

- [Name resolution interface](~peios/reference/pspu/name-resolution-interface/scope-and-roles):
  requests, outcomes and entry-point contracts.
- [resolvd technical reference manual](~peios/reference/resolvd/introduction/overview):
  cache behavior, routing, server demotion, retries, wire handling and limits.
- [netd's resolver channel](~peios/reference/netd/what-netd-publishes/the-resolver-channel):
  which profile and offered DNS facts reach resolvd.
