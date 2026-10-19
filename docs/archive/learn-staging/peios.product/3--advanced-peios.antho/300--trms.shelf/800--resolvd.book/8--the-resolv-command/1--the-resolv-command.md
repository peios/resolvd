---
title: The resolv Command
description: The operator command — its verbs and arguments, the request each sends, its output formats, and its exit statuses.
---

`resolv` (`/usr/bin/resolv`, package `dev.peios.resolv`) owns no state.

## One request per verb [*resolv.one-request-per-verb]

Every verb but `version` is one request on the native socket, on one
connection, and its output is a rendering of the reply.

## Verbs

| Command | Request |
|---|---|
| `resolv status` | `status` |
| `resolv query <name> [<type>] [--no-cache]` | `resolve` |
| `resolv lookup <name>` | `lookup`, family `any` |
| `resolv reverse <address>` | `reverse` |
| `resolv flush` | `flush` |
| `resolv version`, `resolv --version` | none: prints `resolv <version>` [*resolv.version-needs-no-daemon] |

### The command line

- `--no-cache` is recognised anywhere on the command line and removed
  before the rest is matched; it affects only `query`. [*resolv.no-cache-anywhere]
- Any other argument list prints a usage line to standard error and
  exits 64. [*resolv.usage-exit-64]

### Arguments checked before contacting resolvd

- The `<type>` of `query` is `A` when omitted. It is one of `A`, `NS`,
  `CNAME`, `SOA`, `PTR`, `MX`, `TXT`, `AAAA`, `SRV` or `ANY`, in any
  case, or `TYPE<n>` for any type number from 0 to 65 535. [*resolv.query-type-names]
- Any other `<type>` prints `resolv: unknown record type "<type>"` and
  exits 1 without contacting resolvd. [*resolv.unknown-type-exits-1]
- The `<address>` of `reverse` is checked in the same way: anything
  that is not an IPv4 or IPv6 address prints
  `resolv: "<address>" is not an address` and exits 1 without
  contacting resolvd. [*resolv.bad-address-exits-1]

### No timeout in `resolv` [*resolv.no-timeout]

`resolv` sets no timeout on the connection. It waits for as long as
resolvd takes to answer.

## Output

### `query` output [*resolv.query-output]

`query` prints a summary line, then one line per record:

```text
<outcome>  <source>[ via <server>][ on <interface>]  validation <validation>
<name>	<ttl>	<type>	<text>
```

with `via` present when the reply names a server and `on` when it names
an interface, and fields on record lines separated by tabs. A line
`rcode <name>` follows the summary when the outcome is `found` and the
response code is not zero. resolvd answers `found` only with response
code zero (§4.8), so against resolvd the line does not appear.

### `lookup` output [*resolv.lookup-output]

`lookup` prints `<outcome>  <source>  canonical <name>`, then
`<address>	<ttl>`, tab-separated, for each address.

### `reverse` output [*resolv.reverse-output]

`reverse` prints `<outcome>  <source>`, then the `text` of every record
in the answer, whatever its type.

### `status` output [*resolv.status-output]

`status` prints three lines:

```text
hostname   <name, or (unset)>
netd       <connected | not connected>
cache      <n> entries
```

then `scopes     (none)` when there are no scopes, or, for each scope, a
blank line and

```text
<interface>  metric <n>[  [default-route, exclusive]]
  server   <address>[  (demoted)]
  domain   <domain>
  subnet   <address/prefix>
```

with the bracketed flags present as they apply and one line per server,
domain and subnet. When fallback servers are configured, a blank line
and a `fallback   <servers>` line follow, the servers separated by single
spaces. Last come a blank line and the counters, on one line:

```text
queries <n>  synthetic <n>  cache-hits <n>  upstream sent <n> answered <n> failed <n>  refused <n>
```

### `flush` output [*resolv.flush-silent]

`flush` prints nothing on success.

## Exit status

| Status | Meaning |
|---|---|
| 0 | `found`, or `status`, `flush` or `version` succeeded [*resolv.exit-0] |
| 1 | resolvd unreachable, a protocol failure, an error reply (including `access denied`), or a bad type or address argument; a reply of the wrong kind exits 1 with no message [*resolv.exit-1] |
| 2 | `notfound` [*resolv.exit-2] |
| 3 | `unavailable` [*resolv.exit-3] |
| 64 | A command line `resolv` does not recognise |

### The unreachable message [*resolv.unreachable-message]

Errors are printed to standard error prefixed `resolv: `. resolvd
unreachable reads
`resolv: resolvd is not reachable at /run/resolvd/resolv.sock: <error>`.
