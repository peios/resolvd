---
title: resolvd Cannot Be Reached
description: What each door does when resolvd is not running, will not start, or refuses a caller — and the failures that leave one door working and another not.
---

## resolvd is not running

| Door | What a client sees |
|---|---|
| NSS shim | `localhost` and loopback reverses still answer; everything else is `UNAVAIL` with `NO_RECOVERY` (§7.1) |
| Stub listener | Nothing listens on `127.0.0.53`; UDP queries go unanswered or are refused by the kernel, TCP connections are refused |
| `resolv` | Exit 1, `resolv: resolvd is not reachable at /run/resolvd/resolv.sock: <error>` |

peinit restarts resolvd whenever it exits (§2.1). The new process removes
the socket the old one left and binds a fresh one (§2.4), so an outage
after a crash lasts only until the restart completes. If resolvd keeps
exiting, the cause is one of the startup failures below.

## resolvd will not start

The startup failures are fatal and logged before the exit (§2.2):

- **`stub listener on 127.0.0.53:53: <error>`:** either the port
  reservation for `tcp,udp:53` is not in the registry — its seed is
  inert until the image applies it (§2.1) — or something else already
  holds `127.0.0.53:53`. The error text says which.
- **`native socket: <error>`:** `/run/resolvd` could not be created or
  given its mode, a stale socket file could not be removed, or the
  socket could not be bound or set up.

Because the restart policy is Always, a failure that persists is a
restart loop: the same line in the log each time.

## The native door is closed to ordinary programs

**Looks like:** `getaddrinfo` fails with `NO_RECOVERY` for every name
but `localhost`, for every user but SYSTEM and administrators, while
programs that send DNS to `127.0.0.53` themselves work.

Two causes:

- The socket's descriptor could not be written at startup (§2.4), and
  the log has the `could not set a descriptor` line. Ordinary programs
  cannot reach the socket at all.
- `ControlSecurity` holds a valid descriptor that does not grant
  `RESOLVER_QUERY` to them (§5.2). They reach the socket and are denied:
  `resolv query` prints `resolv: access denied`. Deleting the value
  restores the compiled default without a restart (§2.3).

The stub listener is not governed by either, which is why direct DNS
clients are unaffected.
