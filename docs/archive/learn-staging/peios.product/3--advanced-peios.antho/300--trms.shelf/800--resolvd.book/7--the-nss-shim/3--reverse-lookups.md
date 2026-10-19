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
  no records is `NOTFOUND` (§7.1). [*nss-reverse.found-without-records-is-notfound]
- In [source `b4f7085`](https://github.com/peios/resolvd/blob/b4f70857729069952762f8e2a2b56357b15d4760/nss/src/lib.rs),
  a reply whose records include no `PTR` record — only `CNAME`s, for
  instance — is `NOTFOUND` with `HOST_NOT_FOUND`. [*nss-reverse.no-ptr-record-is-notfound]

The [proposed source correction](https://github.com/peios/resolvd/blob/6d23bf920c60e3695781fc960e292a139d77b044/nss/src/lib.rs) returns
`NOTFOUND` / `ENOENT` / `NO_DATA` for a `found` reply with no records or
no `PTR` record. Explicit `notfound` remains `HOST_NOT_FOUND`; this does
not turn transient failures into negative answers. The source and
installed-module qualification in §7.1 applies here too.

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
