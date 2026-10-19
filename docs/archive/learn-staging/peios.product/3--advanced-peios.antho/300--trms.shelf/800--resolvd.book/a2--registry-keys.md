---
title: Registry Keys
description: Every registry key and value resolvd reads or its package seeds, with types, defaults and the article that describes each.
---

The articles cited are authoritative; this appendix collects the keys in
one place.

## Read by resolvd

| Key | Value | Type | Default | Described in |
|---|---|---|---|---|
| `Machine\System\Network\Dns` | `FallbackServers` | `REG_MULTI_SZ` (or one `REG_SZ` or `REG_EXPAND_SZ`) | none | §2.3 |
| `Machine\System\Network\Dns` | `ExtraSearchDomains` | `REG_MULTI_SZ` (or one `REG_SZ` or `REG_EXPAND_SZ`) | none | §2.3 |
| `Machine\System\Network\Dns` | `ControlSecurity` | `REG_BINARY` | the compiled default of §5.2 | §2.3, §5.2 |
| `Machine\System\Network\Dns\Hosts` | any name: a static name | `REG_SZ`, `REG_EXPAND_SZ` or `REG_MULTI_SZ` | none | §2.3, §4.2 |

resolvd watches `Machine\System\Network` and everything under it, and
re-reads `Machine\System\Network\Dns` whole on any change (§2.3). It
reads no other key.

## Seeded by the package

Both seeds are installed under `/usr/share/regim/` and are inert until
an image applies them (§2.1).

| Seed | Key | Values |
|---|---|---|
| `resolvd-service.reg` | `Machine\System\Services\resolvd` | `ImagePath`, `Triggers`, `Identity`, `Readiness`, `RuntimeDirectories`, `RestartPolicy`, `ErrorControl`, `DisplayName`, `Description` |
| `resolvd-port.reg` | `Machine\System\Network\TcpIp\PortReservations` | `tcp,udp:53` |
