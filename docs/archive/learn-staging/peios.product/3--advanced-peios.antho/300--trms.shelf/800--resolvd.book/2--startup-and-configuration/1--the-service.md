---
title: The Service
description: How peinit runs resolvd — the service definition, the identity it runs under, the port reservation that lets it bind port 53, readiness, restart, and where its log lines go.
---

## The service definition seed [*service.definition-seed-inert-until-applied]

resolvd is started by peinit from `Machine\System\Services\resolvd`. The
package ships the definition as a registry seed,
`/usr/share/regim/resolvd-service.reg`, which is inert until an image
names it in its `[registry] autoapply` list.

## The service definition values

| Value | Type | Data | Effect |
|---|---|---|---|
| `ImagePath` | `REG_SZ` | `/usr/sbin/resolvd` | The binary. resolvd reads no command-line arguments. [*service.image-path-no-arguments] |
| `Triggers` | `REG_MULTI_SZ` | `boot` | Started at boot. [*service.triggered-at-boot] |
| `Identity` | `REG_SZ` | `Service` | Runs under its own virtual service account. [*service.identity-is-own-virtual-account] |
| `Readiness` | `REG_DWORD` | `0` | Notify: ready when resolvd says so. [*service.readiness-is-notify] |
| `RuntimeDirectories` | `REG_MULTI_SZ` | `resolvd` | peinit creates `/run/resolvd`. [*service.runtime-directory] |
| `RestartPolicy` | `REG_DWORD` | `2` | Always restarted. [*service.restart-policy-always] |
| `LimitNOFILE` | `REG_DWORD` | `16384` | Descriptor headroom for 4 096 upstream transactions, their client waiters, 512 pending clients and daemon descriptors. |
| `ErrorControl` | `REG_DWORD` | `0` | |
| `DisplayName` | `REG_SZ` | `Stub resolver` | |
| `Description` | `REG_SZ` | (one sentence) | |

## Identity and privilege

resolvd holds no privilege and needs none. Its one claim on the machine
that an ordinary process could not make — binding UDP and TCP port 53 —
is met by a port reservation rather than a capability (PSPU §6.8).

Without the reservation applied, the stub listener cannot bind and
resolvd exits at startup (§2.2, §9.3).

### The port reservation seed [*service.port-reservation-seed]

The reservation is a second seed, `/usr/share/regim/resolvd-port.reg`,
also inert until an image applies it. It writes one value:

| Key | Value | Type |
|---|---|---|
| `Machine\System\Network\TcpIp\PortReservations` | `tcp,udp:53` | `REG_BINARY` |

### Who holds the reservation [*service.reservation-granted-to-system-and-service-sid]

The data is a security descriptor granting the reservation to SYSTEM and
to resolvd's service SID,
`S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966`, so it
follows the service rather than whichever account the service happens to
run as.

The selector `tcp,udp:53` is more specific than the kernel package's
`tcp,udp:1-1023` and so decides port 53 alone. The descriptor bytes are
generated from the SID by a tool in the source tree, not written by
hand.

## Readiness

With `Readiness` 0 peinit waits for a notification. resolvd:

- sends the datagram `READY=1` to the socket named by the
  `NOTIFY_SOCKET` environment variable once the native socket and both
  stub sockets are open and the registry has been read; [*service.ready-after-doors-open]
- does not wait for netd: readiness is sent after the first attempt to
  reach netd whether that attempt succeeded or not; [*service.ready-does-not-wait-for-netd]
- sends nothing when `NOTIFY_SOCKET` is unset, and logs a failure to
  send as `readiness notify: <error>` and carries on starting. [*service.notify-failure-not-fatal]

## Restart

`RestartPolicy` 2 restarts resolvd whenever it exits. A restarted
resolvd removes the socket file its predecessor left, logs
`removed a stale /run/resolvd/resolv.sock`, and binds a fresh one
(§2.4). Everything resolvd holds is in memory, so a restarted resolvd
has:

- an empty cache; [*service.restart-empties-cache]
- no demoted servers; [*service.restart-clears-demotions]
- every counter at zero (§4.10);
- no scopes, and the kernel's hostname, until the first snapshot after
  netd is reached again (§3.3). [*service.restart-starts-without-scopes]

## Log lines

### The log line format [*service.log-line-format]

Every line resolvd logs has the form

```text
resolvd: <level>: <text>
```

where the level is `info`, `warn` or `error`. Informational lines go to
standard output; warnings and errors go to standard error. peinit forwards
both streams to eventd, marking only standard error as `is_error=true`.
The lines are read with:

```sh
evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 40'
```

### The kernel log mirror [*service.kmsg-mirror-fails-once]

Each line is also offered to `/dev/kmsg`, at kernel priority 6, 4 or 3
for info, warn and error. The mirror is opened when the first line is
logged, after that line has been written to its output stream, and the open
is never retried.

`/dev/kmsg` is writable by SYSTEM only, so for resolvd the open fails,
and resolvd writes one line to standard error saying so, directly after
the first log line:

```text
resolvd: warn: /dev/kmsg mirror unavailable (<error>): log lines go to stdout/stderr only
```

The mirror warning follows the first log call. That first line may be on
stdout or stderr, so readers must not assume a cross-stream ordering.
On a start that fails, the first logged line is the fatal one, such as
`native socket: <error>` (§2.4).
On a start that succeeds, it is a warning from earlier in startup when
there is one, such as `removed a stale /run/resolvd/resolv.sock` (§2.4)
or a `Dns …` warning (§2.3), and otherwise the result of
the first attempt to reach netd, `subscribed to netd` or
`netd not reachable (<error>); retrying`, which comes before
`listening on …` (§2.2). The mirror line is written once, and nothing
further about the mirror is written. resolvd's lines never reach the console or
`dmesg`.
