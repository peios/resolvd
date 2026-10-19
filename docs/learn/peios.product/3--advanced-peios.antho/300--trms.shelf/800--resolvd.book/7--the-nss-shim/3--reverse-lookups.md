---
title: Reverse Lookups
description: How the shim answers an address — loopback in-process, everything else through a reverse — and which records become h_name and h_aliases.
---

## Loopback addresses in the shim [*nss-reverse.loopback-answered-in-process]

An address in `127.0.0.0/8`, or `::1`, is answered inside the calling
process without contacting resolvd: `h_name` is `localhost`, with no
aliases and TTL 0.

## Other addresses

- Any other address is sent as a `reverse` (§4.9). A `found` reply with
  no records is `NOTFOUND` (§7.1).
  [*nss-reverse.found-without-records-is-notfound]
- A found reply without a PTR record returns `NOTFOUND`, `ENOENT`, and
  `NO_DATA`. Explicit `notfound` returns `HOST_NOT_FOUND`; transient failures
  retain their separate results (§7.1).
  [*nss-reverse.no-ptr-record-is-notfound]

## The reverse `hostent` [*nss-reverse.hostent-layout]

Otherwise the reply's `PTR` records are taken in order, each record's
`text` with any trailing dots removed:

| Field | Content |
|---|---|
| `h_name` | The first `PTR` record's name |
| `h_aliases` | The remaining `PTR` records' names |
| `h_addrtype` | The `af` asked for |
| `h_length` | 4 or 16 |
| `h_addr_list` | The address asked about, alone |

## The reverse TTL [*nss-reverse.ttl-least-of-all-records]

When `ttlp` is given it receives the least TTL among all the reply's
records, `PTR` or not.
