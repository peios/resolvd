---
title: Receiving Queries
description: How the stub listener reads queries over UDP and TCP — source checks, connection limits, the per-connection bound, the queries it refuses at the door, and what it ignores in a query it accepts.
---

The stub listener's address, its loopback-only rule and its rendering
are PSPU §6.8. This article covers how resolvd reads queries; the
replies are §6.2.

## UDP

When the UDP socket is readable, at most 64 datagrams are read per
event-loop iteration, including malformed or dropped datagrams. For each:

1. A datagram whose source address is not a loopback address — anything
   outside `127.0.0.0/8` — is dropped without a reply.
   [*stub-receive.udp-non-loopback-source-dropped]
2. It is checked as a query (below). A refused query gets its error
   reply, or nothing.
3. A valid query is admitted if fewer than 16 UDP questions from its
   source address **and port**, and fewer than 256 UDP questions in total,
   are waiting for engine answers. Otherwise it gets `SERVFAIL`, with no
   upstream transaction, and increments both `queries` and `refused`.
   This admission check precedes synthetic and cache lookup.
   [*stub-receive.udp-pending-budgets]
4. An admitted query becomes an engine question (§4.1). Its slot is
   released when the engine completes it, including timeout completion.

The endpoint is an accounting key, not an authenticated process identity.
Changing source ports can consume the aggregate UDP allowance but cannot
consume the separate native or TCP admission allowances. These bounds
limit retained work; they do not promise fairness between local processes.

### The UDP read buffer [*stub-receive.udp-read-buffer-4096]

Each datagram is read into a 4 096-byte buffer; a longer datagram is
truncated by the read to its first 4 096 bytes.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### A UDP query longer than the buffer [*stub-receive.udp-oversized-query-formerr]

A query longer than 4 096 bytes therefore arrives cut short. When the
cut falls inside the DNS message, the message does not decode and,
being at least 12 bytes long, is answered `FORMERR` (below). Bytes after
the end of the message are ignored by decoding, so a query whose message
fits in 4 096 bytes and is only padded beyond them is answered as usual.

### Where UDP replies go [*stub-receive.udp-reply-to-source]

Replies are sent to the source address and port the query came from.

## TCP

When the TCP listener is readable, at most 64 waiting connections are
accepted per event-loop iteration.
A connection is closed at once, without a reply:

- when 256 stub TCP connections are still sending queries or waiting for
  engine answers; [*stub-receive.tcp-pending-cap-256]
- when its source is not a loopback address.
  [*stub-receive.tcp-non-loopback-source-closed]

A connection that cannot be made nonblocking is closed the same way.

### Reading a TCP query

Each held connection is read as it becomes readable, everything
available each time, in 4 096-byte chunks. A message is a two-byte
big-endian length and that many bytes.

- When more than 65 537 bytes are buffered, the connection is closed
  without a reply. [*stub-receive.tcp-buffer-ceiling]
- When a whole message has arrived, it is checked as a query, and the
  connection leaves the set of connections still sending, but continues
  to occupy its admission slot while the engine works.
- A connection carries one query. Anything sent after the first message
  is ignored, and the connection is closed once the answer, or the
  error reply, has been written. [*stub-receive.tcp-one-query-per-connection]
- A connection that closes, or fails to read, before its message is
  whole is closed without a reply.
- A client that sends a complete query and then shuts down its writing
  side is still answered. This also applies when the read finds end of
  file immediately after the buffered query. The connection closes
  after its one reply. A partial frame followed by end of file is dropped
  immediately, without waiting for the delivery timeout.
  [*stub-receive.tcp-query-then-half-close-dropped]
- A connection that has not delivered a whole message ten seconds after
  it was accepted is closed without a reply.
  [*stub-receive.tcp-ten-second-delivery-bound]
- Once its query has arrived the ten-second bound does not apply; the
  connection is held until the engine answers or a definite hangup/error
  abandons its question (§4.1). Reply writers use a separate bounded queue
  (§2.5). [*stub-receive.tcp-bound-ends-once-query-arrives]

## Checking a query

| The message | Result |
|---|---|
| Does not decode, and is at least 12 bytes long | `FORMERR`: the query's ID, `QR` set, every other header bit clear, no sections [*stub-receive.undecodable-long-message-formerr] |
| Does not decode, and is shorter than 12 bytes | Dropped without a reply [*stub-receive.undecodable-short-message-dropped] |
| Has `QR` set | Dropped without a reply [*stub-receive.response-dropped] |
| Has an opcode other than `QUERY` | `NOTIMP` [*stub-receive.non-query-opcode-notimp] |
| Has no question, or more than one | `FORMERR` [*stub-receive.question-count-formerr] |
| Has a question class other than `IN` | `NOTIMP`; the question is echoed unchanged and no upstream query is made [*stub-receive.unsupported-class-notimp] |
| Otherwise | Accepted |

### The `NOTIMP` and question-count `FORMERR` replies

These two replies are built from the query:

- the header copies the query's ID, opcode, `RD` and `CD` bits, and
  sets `QR` and `RA`; every other bit is clear;
  [*stub-receive.error-reply-header]
- the question section is the query's, whatever it holds;
  [*stub-receive.error-reply-question]
- when the query carried an `OPT` record, the reply carries one whose
  payload size is the size the query advertised, with `DO` clear and no
  options; without one, the reply has none.
  [*stub-receive.error-reply-opt-size]

## What an accepted query contributes

- Only `IN` questions are accepted. Their decoded name and type reach the
  engine; unsupported classes are rejected at the stub door over both
  UDP and TCP.
- `RD`, `CD`, the `DO` bit, and any EDNS options are not looked at.
  [*stub-receive.flags-and-edns-options-ignored]
- Stub queries always consult the cache (§4.5).

### Wire names

The decoded name reaches the engine directly, without conversion to
presentation text and reparsing. Label boundaries and bytes, including
embedded dots, backslashes, NUL and other binary bytes, are preserved.
The usual upstream ASCII case randomization still applies (§4.3).
[*stub-receive.wire-labels-preserved]

Names are subject to DNS wire limits, not the length of a displayed escape
sequence. A valid 63-byte binary label or a valid name whose display form
would exceed 255 bytes can therefore be resolved normally.
[*stub-receive.wire-lengths-preserved]

Search expansion (§4.1) uses the number of wire labels: a single label
containing a literal dot remains a single-label name.

## Which stub queries are counted [*stub-receive.refused-queries-not-counted]

Every valid query counts in `queries` (§4.10), including a UDP query
refused by the pending budgets (which also increments `refused`). Queries
rejected by syntax, opcode, question count, or class checks do not count.
