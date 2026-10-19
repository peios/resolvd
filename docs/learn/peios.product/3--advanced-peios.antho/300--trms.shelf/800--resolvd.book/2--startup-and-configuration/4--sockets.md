---
title: Sockets and Descriptors
description: The native socket and its directory and their descriptors, the stub listener's sockets, and every other descriptor resolvd holds.
---

## The native socket

The native door is a `SOCK_STREAM` Unix socket at
`/run/resolvd/resolv.sock` (PSPU §6.4), inside resolvd's runtime
directory rather than directly in `/run`, which resolvd's account cannot
write.

At startup resolvd:

1. creates `/run/resolvd` if peinit has not, and sets its mode to
   `0755`; [*sockets.runtime-directory-mode-0755]
2. replaces the directory's DACL (below);
3. removes any existing `/run/resolvd/resolv.sock`, logging
   `removed a stale /run/resolvd/resolv.sock` at warn level when there
   was one, and a removal that fails is fatal (§2.2);
4. binds the socket, sets its mode to `0666`, and replaces its DACL in
   the same way; [*sockets.socket-mode-0666]
5. makes the listener nonblocking.

### A socket left by a previous run [*sockets.stale-socket-removed-on-restart]

resolvd leaves its socket behind when it ends (§2.2), so a start that
follows an earlier run finds one unless something else has removed it.
The previous run gave its own account full access to the directory and
the socket (below), so the new process removes the file in step 3, logs
the `removed a stale …` line, and binds a fresh socket. This holds for
every restart of the service: `svctl restart`, a stop and a start, and
a restart by the policy after resolvd exits or is killed.

### The DACL on the directory and socket [*sockets.directory-and-socket-dacl]

The DACL written to both the directory and the socket is:

| Trustee | Access |
|---|---|
| SYSTEM | `GENERIC_ALL` |
| resolvd's own account (its token's user) | `GENERIC_ALL` |
| Everyone | `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE` |

resolvd's own entry is what lets the next run start. Everyone's read,
write and execute include neither `DELETE` nor deleting a child, so
without it the next start could not remove the stale socket: it would
exit with `native socket: Permission denied (os error 13)`, and the
restart policy would loop on that until the file was removed by hand.
If resolvd cannot read its own identity it logs at warn level

```text
could not read resolvd's own identity (<error>); a restart may not be able to replace <path>
```

and writes the DACL without that entry.

### The owner of the directory and socket [*sockets.owner-left-as-resolvd]

Only the DACL is written, so each object keeps the owner it was created
with. peinit creates `/run/resolvd` before resolvd starts (§2.1), so the
directory is owned by SYSTEM; resolvd creates the socket, which is owned
by resolvd's account. Reaching the socket grants nothing: every request
is checked against the control object (§5.2).

### A descriptor that cannot be written

If the descriptor cannot be written, resolvd logs at error level

```text
could not set a descriptor on <path> (<error>); programs other than SYSTEM and administrators will not be able to reach the socket
```

and carries on. The socket then keeps whatever descriptor it was created
with, and for ordinary processes the native door — and with it the NSS
shim — is unreachable while the stub listener still works (§9.3).

## The stub listener

- Two sockets, a UDP socket and a TCP listener, are both bound to
  `127.0.0.53` port 53 and both nonblocking (PSPU §6.8).
  [*sockets.stub-udp-and-tcp-on-127-0-0-53]
- Nothing is bound on `::1` or on any other address.
  [*sockets.nothing-bound-on-other-addresses]

Binding port 53 depends on the port reservation (§2.1).

## Other descriptors

| Descriptor | Count | Lifetime |
|---|---|---|
| The registry watch on `Machine\System\Network` | 0 or 1 | From startup; replaced on a watch error (§2.3) |
| The netd channel | 0 or 1 | While subscribed (§3.1) |
| Native connections reading or awaiting resolution | up to 256 total | Reading: at most 5 s (§5.1); resolving: until completion or definite departure (§4.1) |
| Stub TCP connections reading or awaiting resolution | up to 256 total | Reading: at most 10 s (§6.1); resolving: until completion or definite departure (§4.1) |
| Queued native reply writers | up to 256 | Until written, failed, or the one-second write deadline (§2.5) |
| Queued stub TCP reply writers | up to 256 | Until written, failed, or the one-second write deadline (§2.5) |
| Upstream sockets | one per transaction, at most 4 096 including retries | One transaction (§4.7) |

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Connections whose request has been read [*sockets.resolving-connections-keep-their-slot]

A connection whose request has been read keeps occupying a slot in its
door's 256-connection allowance until resolution completes or a definite
hangup/error abandons it. The engine's attempts and timeouts (§4.6) govern
this phase; the request-delivery deadline does not apply. A completed
answer that cannot be written immediately moves to the separate bounded
reply-writer queue (§2.5).

UDP questions share the one listener socket, but retain at most 256
waiting origins in total and 16 per source address and port (§6.1).
