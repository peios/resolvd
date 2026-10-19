---
title: Subscription
description: How resolvd subscribes to netd's DNS snapshots, reads the stream, and what ends the subscription.
---

The channel is the `subscribe` request of PSPU §6.9, on netd's control
socket. This chapter describes resolvd's end of it; what netd puts in a
snapshot and when it sends one is described in the netd TRM.

## Connecting

### The subscribe request [*netd-subscribe.connect-and-send-subscribe]

When a connection attempt is due (§3.2), resolvd:

1. connects to `/run/netd/control.sock`;
2. sets a two-second write timeout and writes the `subscribe` request in
   netd's framing — a four-byte little-endian length and a MessagePack
   map;
3. switches the socket to nonblocking mode.

The request needs netd's `NETWORK_QUERY` right for resolvd's account;
whether that is granted is netd's decision.

### A failed attempt [*netd-subscribe.any-step-failure-is-failed-attempt]

A failure at any of the three steps is a failed attempt, and the next
one is scheduled by the backoff of §3.2.

### A successful attempt [*netd-subscribe.success-logged]

On success resolvd logs `subscribed to netd` at info level, discards
anything buffered from an earlier connection, and waits for the first
snapshot as an ordinary read on the channel. Only a successfully decoded
snapshot resets its backoff (§3.2); connection success alone does not.

### Nothing else is written to netd [*netd-subscribe.writes-only-the-request]

resolvd writes nothing more on the channel after the request.

## Reading the stream

When the channel is readable, resolvd reads everything available, in
8 192-byte chunks, and then takes every complete frame from what it
holds, in order:

| Frame | What resolvd does |
|---|---|
| A `snapshot` reply | Applies it (§3.3), once the whole read has been taken. Several in one read are applied one after another, so the last wins. [*netd-subscribe.snapshots-applied-in-order] |
| An error reply | Logs `netd refused the subscription: <message>`, and drops the channel once the whole read has been taken. [*netd-subscribe.error-reply-drops-channel] |
| Any other well-formed reply | Ignores it. [*netd-subscribe.other-replies-ignored] |
| A payload that does not decode | Logs `netd sent something unreadable: <error>`, and drops the channel once the whole read has been taken. [*netd-subscribe.undecodable-payload-drops-channel] |
| A length above 65 536 bytes | Stops taking frames: the rest of the buffer is discarded and the channel dropped. [*netd-subscribe.oversized-frame-drops-channel] |

### Frames behind an error are still taken [*netd-subscribe.frames-after-error-still-taken]

An error reply or an unreadable payload does not stop the frames behind
it. Every complete frame already read is still taken, in order, and any
snapshot among them is applied. The same holds when the read ended at
end of file or a read error: the frames read before it are all taken.
Only a length above 65 536 stops the taking, and the frames before it
have been taken by then.

### The channel is dropped before the read's snapshots are applied [*netd-subscribe.drop-logged-before-snapshots-applied]

When a read ends with the channel to be dropped, it is dropped — and
`lost the netd channel; reconnecting` logged — after every frame has
been taken and before any snapshot from that read is applied. In the
log, the `lost …` line therefore comes before the `netd: …` summary
lines (§3.3) of the snapshots read with it, and `status` then shows
`netd` as `false` together with the scopes of those snapshots, until
the channel is reconnected.

### A partial frame [*netd-subscribe.partial-frame-buffered]

A partial frame stays buffered until the rest arrives.

### End of file or a read error [*netd-subscribe.eof-or-read-error-drops-channel]

End of file, or any read error other than `EINTR` or `EAGAIN`, drops the
channel. `EINTR` is retried, and `EAGAIN` ends the read.

### Dropping the channel [*netd-subscribe.drop-logged-and-reconnect-scheduled]

Dropping the channel closes the socket, discards the buffer, logs
`lost the netd channel; reconnecting` at warn level — once, however many
of the causes above occurred in the read — and schedules a reconnection
(§3.2).
