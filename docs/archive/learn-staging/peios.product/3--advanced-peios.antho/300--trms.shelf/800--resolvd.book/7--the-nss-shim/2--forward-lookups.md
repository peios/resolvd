---
title: Forward Lookups
description: How the shim answers a host name — localhost in-process, everything else through a lookup — and how the reply is laid out as gaih_addrtuple and hostent.
---

## `localhost` in the shim

- A name that, with trailing dots removed, is `localhost` or ends in
  `.localhost`, compared case-insensitively, is answered inside the
  calling process without contacting resolvd — whether resolvd is
  running or not. [*nss-forward.localhost-answered-in-process]
- The answer is `127.0.0.1` for IPv4, `::1` for IPv6, or both, IPv4
  first, with canonical name `localhost` and TTL 0. [*nss-forward.localhost-answer]

## Other names

- Any other name is sent as a `lookup` (§4.9), with the family the
  entry point asks for. The addresses in the reply are filtered to that
  family, and an empty result is `NOTFOUND` (§7.1). [*nss-forward.addresses-filtered-to-family]
- Addresses are returned in the order resolvd's reply lists them. [*nss-forward.reply-order-kept]

resolvd does not fix which family comes first (§4.9); glibc's own
sorting of `getaddrinfo` results is what callers normally see.

## `gethostbyname4_r`

The result is a linked list of `gaih_addrtuple`, and the pointer glibc
passes is overwritten with the head of the list:

| Field | Content |
|---|---|
| `next` | The next tuple: one tuple per address, in reply order [*nss-forward.gaih-addrtuple-order] |
| `name` | One copy of the canonical name, shared by every tuple [*nss-forward.gaih-addrtuple-name-shared] |
| `family` | `AF_INET` or `AF_INET6`, per address [*nss-forward.gaih-addrtuple-family] |
| `addr` | The address |
| `scopeid` | 0, so an IPv6 link-local address is returned without the interface it belongs to [*nss-forward.gaih-addrtuple-scopeid-zero] |

### The `gethostbyname4_r` TTL [*nss-forward.gethostbyname4-ttl-least]

When `ttlp` is given it receives the least TTL among the addresses.

## The forward `hostent` [*nss-forward.hostent-layout]

`gethostbyname3_r`, `2_r` and `_r` return a `hostent`:

| Field | Content |
|---|---|
| `h_name` | The reply's `canonical` name |
| `h_aliases` | Empty |
| `h_addrtype` | The `af` asked for |
| `h_length` | 4 or 16 |
| `h_addr_list` | Every address, in reply order |

## The `gethostbyname3_r` TTL and canonical name [*nss-forward.gethostbyname3-ttl-and-canon]

When `ttlp` is given it receives the least TTL among the addresses, and
when `canonp` is given it is pointed at `h_name`.
