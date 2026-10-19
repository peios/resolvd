---
title: Reconnection and Backoff
description: When resolvd tries to reach netd again, the exact backoff sequence, what it logs, and what it keeps answering with while netd is away.
---

Failure and reconnection are covered by PSPU §6.9. resolvd's backoff
starts at 0.5 seconds and doubles to a ceiling of 10 seconds.

## The backoff sequence [*netd-reconnect.backoff-sequence]

The first attempt is made during startup, before readiness (§2.2). Each
failed attempt schedules the next one the current backoff later, then
doubles the backoff up to 10 seconds. Measured from a first attempt that
fails, attempts are made at:

| Attempt | Time after the first |
|---|---|
| 2 | 0.5 s |
| 3 | 1.5 s |
| 4 | 3.5 s |
| 5 | 7.5 s |
| 6 | 15.5 s |
| 7 and later | every 10 s |

## The unreachable warning [*netd-reconnect.first-failure-logged-once]

A failed attempt made before any connection has succeeded is logged as
`netd not reachable (<error>); retrying` when it is the first failure,
and not logged otherwise. Together with the rule after a loss (below),
the warning is written at most once in the life of the process: for the
first failure, when that failure comes before the first successful
connection. A resolvd whose first attempt succeeds never writes it.

## A good snapshot resets the backoff [*netd-reconnect.success-resets-backoff]

A successfully decoded snapshot resets the backoff to 0.5 seconds.
Connecting, writing the subscription, or receiving another reply kind
does not reset it. A partial snapshot does not reset it until complete.

## After a loss

When an established channel is dropped (§3.1):

- the next attempt is due after the current backoff, then the delay
  doubles up to 10 seconds. After a channel that delivered a snapshot,
  successive gaps are 0.5, 1, 2, 4, 8, then 10 seconds. A connection
  lost before its first snapshot continues the existing sequence;
  [*netd-reconnect.sequence-after-loss]
- the `netd not reachable` warning is not logged for the failures that
  follow, however many there are; the `lost the netd channel;
  reconnecting` line that preceded them is the record.
  [*netd-reconnect.no-unreachable-warning-after-loss]

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### A refused subscription also backs off [*netd-reconnect.refusal-reconnects-every-half-second]

A netd that accepts the connection and then answers the subscription
with an error has not delivered a snapshot. Its retries follow the same
growing delay, up to ten seconds, as other failures. Each connection
still logs `subscribed to netd` at info level and two warnings (§9.4).
An accept-then-close or malformed reply likewise preserves the growing
delay until a good snapshot arrives.

## Disconnected from netd [*netd-reconnect.state-kept-while-disconnected]

Losing netd changes nothing in the engine. The scopes from the last
snapshot, the hostname taken from it, and every cached answer stay in
use until the next snapshot replaces them; questions are answered
exactly as before, and the servers in those scopes are still asked.
`status` reports `netd` as `false` (§5.3).

<!-- Keep the published reference identifier. -->
<!-- lint-disable-next-line spelling words -->
## Before the first snapshot [*netd-reconnect.no-snapshot-yet-behaviour]

When resolvd has never received a snapshot it has no scopes. It answers
synthetic and static names, uses the fallback servers if any are
configured, and answers everything else `unavailable` (§4.4).
