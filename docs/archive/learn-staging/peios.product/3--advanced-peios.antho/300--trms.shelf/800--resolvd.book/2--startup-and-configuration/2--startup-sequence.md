---
title: Startup Sequence
description: What resolvd does between exec and READY=1, in order, which steps are fatal, and the only ways the process exits.
---

## The sequence

1. **The native socket.** The runtime directory and the socket are
   created and given their modes and descriptors (§2.4). A failure to
   create the directory, set a mode, remove a stale socket file, bind,
   or make the listener nonblocking is fatal: resolvd logs `native socket: <error>` at error level and
   exits with status 1. A failure to write a descriptor is not fatal
   (§2.4). [*startup.native-socket-failure-is-fatal]
2. **The stub listener.** A UDP socket and then a TCP listener are bound
   to `127.0.0.53:53`. A failure of either is fatal: resolvd logs
   `stub listener on 127.0.0.53:53: <error>` and exits with status 1. [*startup.stub-listener-failure-is-fatal]
3. **The registry.** `Machine\System\Network\Dns` is read whole (§2.3).
   A missing or unreadable key is not an error; every value takes its
   default. [*startup.missing-dns-key-is-not-an-error]
4. **The registry watch.** A subtree watch is armed on
   `Machine\System\Network` (§2.3). If it cannot be armed, resolvd logs
   `registry watch unavailable (<error>); configuration is read once`
   and runs on the configuration it read in step 3 until it restarts. [*startup.watch-failure-reads-configuration-once]
5. **Query entropy.** The engine is given a kernel-randomness provider.
   Every upstream transaction obtains fresh bytes through nonblocking
   `getrandom`; startup does not seed a userspace generator or read
   `/dev/urandom`. There is no clock fallback. [*startup.entropy-from-kernel-per-query]
6. **The engine's inputs.** The engine is given the kernel's hostname,
   the fallback servers and search domains, and the static names. A
   kernel hostname that is empty or `(none)` counts as no hostname. [*startup.kernel-hostname-none-is-no-hostname]
7. **The control object** is built from `ControlSecurity` (§5.2).
8. **netd.** The first attempt to subscribe is made immediately (§3.1).
   Its failure is not fatal and is retried with backoff (§3.2). [*startup.first-netd-attempt-immediate-and-not-fatal]
9. **The listening line.** resolvd logs
   `listening on /run/resolvd/resolv.sock and 127.0.0.53:53` at info
   level. [*startup.listening-log-line]
10. **Readiness.** `READY=1` is sent (§2.1).
11. **The loop** is entered (§2.5).

## Answering from the moment of readiness [*startup.answers-before-first-snapshot]

Both doors are open, and answering, before readiness is reported, and
neither waits for netd. A question asked the moment resolvd is ready is
answered at once: synthetic and static names are answered, and anything
that needs a server is answered `unavailable` until either a snapshot
arrives or fallback servers are configured (§3.2).

## Exiting

resolvd has no shutdown path of its own. Apart from the startup failures
above, nothing a client or an upstream server sends makes it exit.

### Ending on a signal [*startup.no-signal-handlers-socket-left-behind]

resolvd installs no signal handlers, so it ends when peinit signals it,
with the default disposition, and leaves `/run/resolvd/resolv.sock`
behind. The next start removes the stale socket file before binding
(§2.4).

### A poll failure exits [*startup.poll-failure-exits]

When `poll` fails with anything other than `EINTR`, resolvd logs
`poll: <error>` at error level and exits with status 1. `EINTR` is
retried.
