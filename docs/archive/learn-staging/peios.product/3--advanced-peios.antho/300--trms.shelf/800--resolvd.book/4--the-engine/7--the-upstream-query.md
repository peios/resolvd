---
title: The Upstream Query
description: What resolvd puts on the wire for each transaction — sockets and source ports, the message identifier and 0x20 case pattern, EDNS0, link-local servers, and the TCP retry.
---

PSPU §6.7 sets the upstream behaviour. This article is what resolvd puts
on the wire to meet it.

## Sockets

### One socket per transaction [*engine-query.socket-per-transaction]

Every transaction has its own socket, opened when the transaction is
sent and closed when it ends.

### The UDP socket

- A new socket is bound to the unspecified address of the server's
  family, port 0, so the kernel picks the source address and a fresh
  ephemeral source port. [*engine-query.udp-fresh-ephemeral-port]
- The socket is connected to the server's port 53, so the kernel
  delivers only datagrams from that address and port. [*engine-query.udp-socket-connected-to-server]
- Each datagram is read into a 4 096-byte buffer; a longer datagram is
  truncated by the read. [*engine-query.udp-read-buffer-4096]

The query is sent with one `send`.

### The TCP connection [*engine-query.tcp-one-query-per-connection]

A new nonblocking socket is connected to the server's port 53. When the
connection completes, the query is written with its two-byte length
prefix; once it is all written, the socket is read until the two-byte
length and that many bytes of reply have arrived. Bytes after the first
message are ignored. One query is sent per connection, and the
connection is closed when the transaction ends.

### A transaction that cannot be sent [*engine-query.send-failure-logged]

A failure found while a transaction is being sent — opening or binding
its socket, connecting it, or, for UDP, sending the query — fails the
attempt at once (§4.6) and is logged at warn level as
`upstream <server>: <error>`. A TCP failure found later, once the
connection is under way, is not logged, and neither is a timeout or a
UDP receive error.

## Link-local servers [*engine-query.link-local-server-uses-scope]

A link-local IPv6 server from netd is reached through the interface named
by its DNS scope. Both UDP and TCP upstream sockets carry that interface’s
index in `sin6_scope_id`; a truncated UDP answer keeps it on the TCP retry.
An address such as `fe80::1` can therefore be advertised in RDNSS without a
zone suffix. Failures of that address on one scope do not demote the same
address on another scope.

A snapshot may also spell it `fe80::1%eth0` or use a numeric interface
index. An explicit zone must match the containing scope’s interface;
invalid or mismatched zones are logged and ignored. Global addresses
continue to use ordinary unscoped sockets.
[*engine-query.snapshot-zone-matches-interface]

`FallbackServers` has no containing interface scope and continues to accept
plain IP addresses only: a `%zone` value is logged and skipped. Configure
link-local DNS on the interface profile instead. A bare link-local
fallback cannot be sent; it fails as a local address error, without
marking a remote server unhealthy.
[*engine-query.fallback-zone-unsupported]

## The message

| Field | Value |
|---|---|
| ID | 16 bits from the kernel CSPRNG, fresh for every transaction [*engine-query.id-fresh-per-transaction] |
| Flags | `RD` set; `CD` clear; everything else clear [*engine-query.rd-set-other-flags-clear] |
| Question | The candidate, case-randomised; the record type asked; class `IN` [*engine-query.question-is-randomised-candidate-in-class-in] |
| Additional | One `OPT` record: payload size 1 232, `DO` clear, extended response code 0, version 0, no options [*engine-query.opt-record-advertises-1232] |

Authority and answer sections are empty.

### Query entropy [*engine-query.cryptographic-entropy-per-transaction]

Every transaction obtains 34 fresh bytes through `getrandom` with
`GRND_NONBLOCK`: two bytes for the message ID, interpreted little-endian,
and 32 bytes of case bits, enough for every letter in a DNS name. This
uses the kernel CSPRNG without a predictable userspace generator or a
clock fallback.

If entropy is unavailable, including before the kernel CSPRNG is ready,
resolvd logs the error, increments `refused`, and settles the affected
question as `unavailable` without sending it. The event loop does not wait
for entropy readiness; later requests can try again. Synthetic and cached
answers do not need upstream entropy. [*engine-query.entropy-failure-is-unavailable]

### Case randomisation

- Every ASCII letter in the candidate is flipped between upper and lower
  case when its random bit is 1. Digits, hyphens and
  other bytes are unchanged. [*engine-query.letters-flipped-on-generator-bits]
- Case bytes follow the ID bytes. Bits are taken lowest first from each
  byte in order. A bit is used only for a letter. [*engine-query.case-bits-consumed-per-letter]
- Each transaction — a retry to the same server, and the TCP retry after
  truncation, included — gets a new pattern and a new ID. [*engine-query.new-pattern-every-transaction]

## No fallback without EDNS0 [*engine-query.no-fallback-without-edns]

Every query carries the `OPT` record. resolvd does not fall back to a
query without EDNS0: a server that answers an EDNS0 query with
`FORMERR` has failed the attempt (§4.6).

## The TCP retry

- A matching UDP reply with `TC` set is not used. The same candidate is
  sent to the same server over TCP as a new transaction, with a new ID,
  a new case pattern and its own two-second deadline, if an attempt
  remains in the question budget. The TCP transaction spends one attempt
  (§4.6); without budget the question is `unavailable`. [*engine-query.truncated-udp-retried-over-tcp-same-server]
- A TCP reply with `TC` set is used as it is. [*engine-query.truncated-tcp-reply-used-as-is]
