---
title: Servers, Attempts and Timeouts
description: Which server each attempt goes to, what counts as a failure, how demotion works, how many attempts a question gets and how long it can take, and the in-flight ceiling.
---

Server order, demotion and the attempt limit are set by PSPU §6.7, and
the contract's mainline values are in PSPU §6.B. resolvd's values are:

| Bound | Value |
|---|---|
| Transaction timeout | 2 s [*engine-servers.transaction-timeout] |
| Attempts per question (all candidates and transports) | 3 [*engine-servers.attempts-per-candidate] |
| Demotion period | 30 s [*engine-servers.demotion-period] |
| Upstream transactions in flight | 4 096 [*engine-servers.in-flight-ceiling-value] |

## Choosing the server

- For each attempt, the scope's servers — or the fallback servers — are
  put in order: the servers not currently demoted, in their configured
  order, followed by the demoted ones, in their configured order. [*engine-servers.healthy-first-then-demoted]
- The attempt goes to the first server in that order not yet asked for
  this candidate. When every server has been asked, it goes to the
  server at position *n* mod *count* in that order, where *n* is the
  number of attempts already made for the candidate. [*engine-servers.server-choice-rule]
- With one server, all three attempts go to it. [*engine-servers.single-server-gets-every-attempt]
- The order is computed afresh for each attempt, so a server demoted by
  the previous attempt is already behind its peers for the next. [*engine-servers.order-recomputed-each-attempt]
- Attempts for one candidate are made one at a time; a transaction is
  sent only after the previous one for the same candidate has ended. [*engine-servers.attempts-sequential]

With two healthy servers `A` and `B`, the attempts go to `A`, `B`, then
whichever of them is first in the order at that moment — `A` if both
have since been demoted, since demotion keeps configured order within
the demoted group.

## What fails an attempt

Each of the following ends the transaction, adds one to
`upstream_failed`, demotes the server, and moves to the next attempt:

- no matching reply within 2 seconds of the transaction being sent; [*engine-servers.timeout-fails-attempt]
- an error opening, binding, connecting or sending on the transaction's
  socket, except the local resource and permission errors below — an
  unreachable network is known at once, not after the timeout; [*engine-servers.send-error-fails-attempt-at-once]
- an error receiving on a UDP socket, such as the refusal that follows
  an ICMP port-unreachable; [*engine-servers.udp-receive-error-fails-attempt]
- for TCP, the connection failing to complete: an error or hang-up
  while it is being established; [*engine-servers.tcp-connect-failure-fails-attempt]
- for TCP, an error, a hang-up or a failed write before the whole query
  has been sent; [*engine-servers.tcp-error-before-query-sent-fails-attempt]
- for TCP, the connection closing, or a read error, before a whole matching reply
  has arrived; [*engine-servers.tcp-incomplete-reply-fails-attempt]
- a matching reply whose response code is neither `NOERROR` nor
  `NXDOMAIN` — `SERVFAIL`, `REFUSED`, `FORMERR`, `NOTIMP`, and every
  other code, including EDNS extended codes. [*engine-servers.failure-rcodes-fail-attempt]

A synchronous failure to open or send a transaction caused by exhausted
local descriptors (`EMFILE`, `ENFILE`), memory or buffers (`ENOMEM`,
`ENOBUFS`), local address allocation (`EADDRNOTAVAIL`, `EADDRINUSE`), or
permission (`EACCES`, `EPERM`) still adds one `upstream_failed` and advances
the bounded retry sequence, but does not demote the server. A different
configured address or address family may still be usable. If all attempts
fail, the result is `unavailable` and is not cached.

A reply that does not match the transaction is ignored while the socket
remains open for a matching reply until the original deadline (§4.8).

## Demotion

- Demoting a server marks its address until 30 seconds from now; a
  further failure moves that mark forward. [*engine-servers.demotion-marks-address-for-30-seconds]
- A matching reply with response code `NOERROR` or `NXDOMAIN` that
  resolvd uses — a UDP reply without `TC`, or a TCP reply — removes the
  server's mark at once. A UDP reply with `TC` set does not remove it,
  whatever its response code; the reply to the TCP retry decides. [*engine-servers.good-reply-clears-demotion]
- The mark belongs to the address, so a server listed by two scopes is
  demoted in both. [*engine-servers.demotion-is-per-address]
- A demoted server is still asked, after the healthy ones. [*engine-servers.demoted-servers-still-asked]
- `status` lists, for each scope, which of its servers are demoted at
  that moment (§5.3); demotion of the fallback servers is not reported. [*engine-servers.fallback-demotion-not-reported]

## The attempt limit

- A question gets three upstream attempts across all search candidates and
  transports. Failures spend them: a timeout, a failure response code, or
  a transport failure. When its last attempt fails, the question is
  `unavailable` (§4.1). [*engine-servers.third-failure-is-unavailable]
- The budget is not reset when the question moves to another candidate,
  but a candidate's `NXDOMAIN` that moves it on is an answer, not a
  failure, and does not spend an attempt. Every search candidate is
  therefore asked, however many there are. Cached answers spend no
  attempt. [*engine-servers.limit-is-per-question]
- The TCP retry following a truncated UDP reply (§4.7) spends one attempt
  and gets its own two-second deadline. A truncated reply on the final
  attempt cannot start TCP: the question is `unavailable`.
  [*engine-servers.tcp-retry-spends-an-attempt]

The three attempts allow at most six seconds of upstream timeout waiting
in total, including TCP and search-domain expansion. Each `NXDOMAIN` that
moves to another candidate adds one round trip. Loop scheduling and local
I/O can add elapsed time; the attempt limit does not give those
operations a separate deadline.

## The in-flight ceiling

- When 4 096 or more transactions are outstanding, a question about to
  allocate an upstream transaction is answered `unavailable` at once, and the
  `refused` counter goes up by one. A question whose scope has no
  servers left is answered `unavailable` before the ceiling is looked
  at, and is not counted as refused. [*engine-servers.in-flight-ceiling-refuses-new-transactions]
- Every send checks this ceiling, including later attempts and TCP
  retries. A retry is normally sent after its previous transaction has
  ended and been removed, so it can reuse that slot even at capacity.
  Exhausting the three-attempt budget is checked before allocating a
  transaction, and is not counted as a capacity refusal. [*engine-servers.retries-checked-against-ceiling]
- Synthetic names and cache hits are answered as usual whatever the
  count. [*engine-servers.local-answers-unaffected-by-ceiling]
