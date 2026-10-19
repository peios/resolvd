---
title: Requests
description: What resolvd does with each native request — resolve, lookup, reverse, status, flush — and what it puts in each reply field.
---

The requests, their fields and their reply shapes are PSPU §6.5. This
article covers what resolvd accepts and what it fills in.

## Common to every request

A request that passes the access check (§5.2) is handled at once:

- `status` and `flush` are answered within the same loop iteration; [*native-requests.status-and-flush-answered-at-once]
- the other three become engine questions (§4.1), and the connection is
  held until the engine answers; the reply is written then. [*native-requests.questions-held-until-answered]

## `resolve`

| Field | Accepted |
|---|---|
| `name` | Any string: no `name` is refused at decoding. It is handed to the engine as it is, which parses it (§4.1). [*native-requests.resolve-name-accepted] |
| `type` | Any value from 0 to 65 535, forwarded as it is — `ANY` (255), `OPT` (41) and types resolvd has no parser for included. [*native-requests.resolve-type-forwarded-as-is] |
| `no_cache` | Boolean; absent means `false`. Skips the cache lookup (§4.5). [*native-requests.resolve-no-cache-default-false] |

The reply's `outcome`, `source`, `server`, `interface` and `rcode` are
as §4.1 describes. Each record carries:

| Key | Content |
|---|---|
| `name` | The owner name in presentation form, without a trailing dot; the root is `.`. A dot or backslash inside a label is written `\.` or `\\`, and any byte outside `!` to `~` as a backslash and three decimal digits. [*native-requests.record-name-presentation] |
| `type` | The record type number |
| `ttl` | As sent by the server, lowered on a cache hit (§4.5); 0 for a synthetic record |
| `data` | The record data in uncompressed wire form [*native-requests.record-data-uncompressed-wire] |
| `text` | The record data in presentation form (below) [*native-requests.record-text-forms] |

| Type | `text` |
|---|---|
| `A`, `AAAA` | The address |
| `CNAME`, `PTR`, `NS` | The target name, written as `name` is |
| `SOA` | `mname rname serial refresh retry expire minimum` |
| `MX` | `preference exchange` |
| `SRV` | `priority weight port target` |
| `TXT` | Each string in double quotes, separated by spaces; inner quotes are escaped as `\"`, backslashes are not escaped, and bytes that are not UTF-8 become U+FFFD |
| Anything else | `\# <length> <hex>`, the hex in lower case |

## The `lookup` family [*native-requests.lookup-unknown-family-is-any]

`family` takes `any`, `inet` or `inet6`. Absent, or any other string,
means `any`. The reply is built as §4.9 describes.

## The `reverse` address [*native-requests.reverse-bad-address-is-error]

`address` is an IPv4 or IPv6 address in textual form; anything else is
the error `missing or malformed field address`. The question is built as
§4.9 describes.

## `status`

| Key | Content |
|---|---|
| `hostname` | The hostname in use (§3.3), or an empty string when there is none [*native-requests.status-hostname] |
| `netd` | Whether the netd channel is connected at this moment [*native-requests.status-netd] |
| `scopes` | Every scope in the latest snapshot, in snapshot order — including scopes with no servers and scopes that take no part in routing [*native-requests.status-scopes-every-scope] |
| `fallback_servers` | `FallbackServers` as parsed (§2.3) [*native-requests.status-fallback-servers] |
| `cache_entries` | The number of entries held, expired ones included (§4.5) |
| `counters` | §4.10 |

### Each scope in `status`

Each scope carries `interface` (the interface name), `servers` and
`domains` as parsed from the snapshot (§3.3), `default_route`,
`exclusive`, `metric`, `subnets`, and `demoted`:

- `subnets` holds the interface's addresses as `address/prefix` — the
  address itself, not the network it is in; [*native-requests.status-subnets-are-interface-addresses]
- `demoted` holds those of the scope's servers that are demoted at this
  moment (§4.6); [*native-requests.status-demoted-servers]
- a scope's `level` is not reported. [*native-requests.status-level-not-reported]

## `flush`

- Every cache entry, for every scope, is discarded, resolvd logs
  `cache flushed` at info level, and the reply is `ok: true` with no
  `kind`. [*native-requests.flush-discards-everything]
- Demotions and counters are left as they are. [*native-requests.flush-keeps-demotions-and-counters]
