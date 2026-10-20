---
title: Reading resolvd's State
description: The signals available when names stop resolving — what resolv status, the counters, the log, and each door's error shape tell you — and the log lines resolvd writes.
---

## Where to look

| Signal | Tells you |
|---|---|
| `resolv status` | Whether netd is connected, the scopes in use, which servers are demoted, the fallback servers, cache size, counters (§5.3, §8.1) |
| `resolv query <name> --no-cache` | Where a fresh answer comes from: source, server, interface, response code (§4.1) |
| `evctl 'LOGS FROM resolvd SINCE 1h ago'` | Every log line (§2.1) |
| The exit status of `resolv` | 2 for `notfound`, 3 for `unavailable`, 1 when resolvd could not be asked (§8.1) |
| The door's own error | `NXDOMAIN` or `SERVFAIL` at the stub; `HOST_NOT_FOUND`, `TRY_AGAIN`, or `NO_RECOVERY` from `getaddrinfo` (§6.2, §7.1) |

Two readings of the counters are worth knowing. `upstream_failed` rising
with `upstream_answered` flat means no matching reply is arriving: the
servers are not answering, their replies do not match (§4.8), or the
transactions cannot be sent at all (§4.7), which the log shows as
`upstream <server>: <error>` lines. Both rising together means servers
answer with failure codes. `refused` counts rejection at the in-flight ceiling
or a failure to obtain
randomness for a new transaction (§4.6).

## Log lines

Every line resolvd writes, with the level it is written at:

| Line | Level | Meaning |
|---|---|---|
| `native socket: <error>` | error | Startup failed at the native socket; resolvd exits (§2.2) |
| `stub listener on 127.0.0.53:53: <error>` | error | Startup failed at port 53; resolvd exits (§2.2) |
| `poll: <error>` | error | The loop failed; resolvd exits (§2.2) |
| `could not set a descriptor on <path> (<error>); …` | error | The native socket is reachable only by SYSTEM and administrators (§2.4) |
| `removed a stale /run/resolvd/resolv.sock` | warn | A previous instance left its socket behind and this one removed it; expected on every restart of the service (§2.4) |
| `could not build a descriptor: <error>` | warn | As `could not set a descriptor …`, but before writing was attempted (§2.4) |
| `registry watch unavailable (<error>); configuration is read once` | warn | Configuration changes will not be seen (§2.3) |
| `registry watch: <error>; re-arming` | warn | The watch failed and is being replaced (§2.3) |
| `Dns FallbackServers: ignoring malformed address "<s>"` | warn | §2.3 |
| `Dns ExtraSearchDomains: ignoring malformed domain "<s>"` | warn | §2.3 |
| `Dns Hosts: ignoring malformed name "<s>"` | warn | §2.3 |
| `Dns Hosts: ignoring malformed address "<s>"` | warn | §2.3 |
| `ControlSecurity is not a valid descriptor (<error>); using the default` | warn | §2.3 |
| `readiness notify: <error>` | warn | peinit was not told resolvd is ready (§2.1) |
| `netd not reachable (<error>); retrying` | warn | First failure to reach netd (§3.2) |
| `netd refused the subscription: <message>` | warn | netd answered `subscribe` with an error (§3.1) |
| `netd sent something unreadable: <error>` | warn | §3.1 |
| `lost the netd channel; reconnecting` | warn | §3.1 |
| `upstream <server>: <error>` | warn | A transaction could not be sent (§4.7) |
| `control: no peer token: <error>` | warn | A native request was denied because its token could not be read (§5.2) |
| `control: reply failed: <error>` | warn | A native reply could not be written (§5.1) |
| `stub udp: <error>`, `stub tcp accept: <error>`, `native accept: <error>` | warn | A listener read or accept failed. Accept errors pause that listener for 250 ms before retrying; other descriptors continue to be serviced [*failure-signals.listener-errors-logged-and-survived] |
| `listening on /run/resolvd/resolv.sock and 127.0.0.53:53` | info | Startup reached readiness (§2.2) |
| `subscribed to netd` | info | §3.1 |
| `netd: <summary>` | info | A snapshot was applied (§3.3) |
| `configuration changed` | info | A registry change was applied (§2.3) |
| `cache flushed` | info | A `flush` request was carried out (§5.3) |
| `/dev/kmsg mirror unavailable (<error>): log lines go to stdout/stderr only` | warn | The kernel log mirror could not be opened, which for resolvd is always; written once, directly after the first line logged (§2.1) |

## What a question logs [*failure-signals.no-per-question-logging]

Answering a question writes no log line, however it is answered —
synthetic, from the cache, by a server, or `unavailable` after timeouts —
and a timeout or a demotion writes none either. The only lines a single
question or request can cause are `upstream <server>: <error>`, for a
transaction that could not be sent (§4.7), and, for a native request,
`control: no peer token: <error>` (§5.2) and
`control: reply failed: <error>` (§5.1).
