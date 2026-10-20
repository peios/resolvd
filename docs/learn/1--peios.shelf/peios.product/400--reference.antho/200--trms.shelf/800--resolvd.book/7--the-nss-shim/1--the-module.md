---
title: The Module
description: libnss_peios_net.so.2 as built — what it links, how each call talks to resolvd, its timeout, and the status, errno and h_errno it returns for every result.
---

The shim's obligations are PSPU §6.10. This chapter describes the module
resolvd's source tree builds.

## The object

- `libnss_peios_net.so.2` is installed by `dev.peios.resolvd-nss` at
  `/usr/lib/x86_64-linux-peios/libnss_peios_net.so.2`.
  [*nss-module.installed-path]
- It is built from the `nss` crate, with the native channel codec
  compiled in. Its only shared-object dependencies are `libc.so.6` and
  the dynamic loader, `ld-linux-x86-64.so.2`. The GCC unwinder required by
  Rust is linked statically, with its symbols private to the module; name
  lookups do not load `libgcc_s.so.1`. The identity shim, `libnss_peios.so.2`,
  uses the same static-unwinder arrangement. Neither shim links libpeios.
  [*nss-module.link-dependencies]

### The entry points [*nss-module.entry-points]

The module exports six entry points:

| Entry point | Asks |
|---|---|
| `_nss_peios_net_gethostbyname4_r` | `lookup`, family `any` |
| `_nss_peios_net_gethostbyname3_r` | `lookup`, family from `af` |
| `_nss_peios_net_gethostbyname2_r` | as `gethostbyname3_r`, with no TTL or canonical name out |
| `_nss_peios_net_gethostbyname_r` | as `gethostbyname3_r`, with `af` `AF_INET` |
| `_nss_peios_net_gethostbyaddr2_r` | `reverse` |
| `_nss_peios_net_gethostbyaddr_r` | as `gethostbyaddr2_r`, with no TTL out |

## One connection per call

- Every call that needs resolvd opens a new connection to
  `/run/resolvd/resolv.sock`, sends one request, reads one reply, and
  closes the connection. [*nss-module.one-connection-per-call]
- Nothing is kept between calls: no connection, no cache, no
  configuration. The module reads no file. [*nss-module.no-state-no-files]

### The ten-second socket timeouts [*nss-module.ten-second-socket-timeouts]

Connection creation is nonblocking. A full local listener queue returns
`UNAVAIL` instead of waiting indefinitely. Once connected, the socket
is given ten-second read and write timeouts, which
apply to each read and write on the socket. Ten seconds is longer than
the six seconds a question's three timed-out attempts take in resolvd,
TCP retries included (§4.6), so a slow upstream normally reaches the
caller as `unavailable` from resolvd rather than as a timeout here. A
question can still reach the timeout when many search candidates each
answer `NXDOMAIN` slowly, since those answers do not spend the attempt
budget; that is reported as the table below shows.

## Results

| Result | NSS status | `errno` | `h_errno` |
|---|---|---|---|
| Addresses, or names, found | `SUCCESS` | — | — [*nss-module.found-is-success] |
| `found`, but no address of the asked family | `NOTFOUND` | `ENOENT` | `NO_DATA` [*nss-module.found-without-family-is-host-not-found] |
| `notfound` | `NOTFOUND` | `ENOENT` | `HOST_NOT_FOUND` [*nss-module.notfound-is-host-not-found] |
| `unavailable` | `TRYAGAIN` | `EAGAIN` | `TRY_AGAIN` [*nss-module.unavailable-is-try-again] |
| No reply within ten seconds | `TRYAGAIN` | `EAGAIN` | `TRY_AGAIN` [*nss-module.timeout-is-try-again] |
| resolvd cannot be connected to | `UNAVAIL` | `ENOENT` | `NO_RECOVERY` [*nss-module.unreachable-is-unavail] |
| An error reply, including `access denied` | `UNAVAIL` | `ENOENT` | `NO_RECOVERY` [*nss-module.error-reply-is-unavail] |
| A reply of the wrong kind, a reply that does not decode, or any other I/O error | `UNAVAIL` | `ENOENT` | `NO_RECOVERY` [*nss-module.other-failures-are-unavail] |
| The caller's buffer is too small | `TRYAGAIN` | `ERANGE` | `NETDB_INTERNAL` (`-1`), required for retry [*nss-module.small-buffer-is-erange] |
| `gethostbyname3_r` or `2_r` with an `af` other than `AF_INET` or `AF_INET6` | `UNAVAIL` | `EAFNOSUPPORT` | `NO_DATA` [*nss-module.unsupported-family-forward] |
| `gethostbyaddr2_r` or `_r` with an `af` and length other than `AF_INET`/4 or `AF_INET6`/16 | `UNAVAIL` | `EAFNOSUPPORT` | `NO_RECOVERY` [*nss-module.unsupported-family-reverse] |
| A null name, a name that is not UTF-8, or a null address | `NOTFOUND` | `ENOENT` | `HOST_NOT_FOUND` [*nss-module.null-or-non-utf8-input-is-notfound] |

A found reply without a usable address of the requested family returns
`NOTFOUND`, `ENOENT`, and `NO_DATA`. A found reverse reply without a PTR
record has the same result. Explicit `notfound` remains `HOST_NOT_FOUND`.
[*nss-module.found-without-family-is-no-data]

<!-- Keep the published reference identifier. -->
<!-- lint-disable-next-line spelling -->
### `AF_UNSPEC` [*nss-module.af-unspec-only-via-gethostbyname4]

`AF_UNSPEC` is accepted only by `gethostbyname4_r`, which always asks
for both families.

## The caller's buffer [*nss-module.results-placed-in-caller-buffer]

Every string, pointer array, and address the module returns is placed in
the buffer glibc passes in; the module allocates nothing that outlives
the call. When the buffer cannot hold the result, the call returns as in
the table, and nothing written to the buffer is valid.
