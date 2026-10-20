---
title: Rendering Replies
description: How an engine answer becomes a DNS reply at the stub listener — header bits, the CNAME for an expanded name, negative replies, EDNS, and truncation.
---

The outcome-to-response-code table and the rules for `CNAME`, `RA`, `AA`
and `AD` are PSPU §6.8. This article is how resolvd builds each reply.

## The header and question

- The reply copies the query's ID, opcode, `RD` and `CD` bits and its
  question section. [*stub-render.copied-header-fields]
- `QR` and `RA` are set. `AA`, `AD` and `TC` are clear, except that `TC`
  is set on a truncated UDP reply (below).
  [*stub-render.qr-ra-set-aa-ad-clear]
- No bit from an upstream server's reply reaches the stub reply.
  [*stub-render.no-upstream-bits]

## By outcome

### `found` replies

- The response code is `NOERROR`, and the answer section holds the
  engine's records in the order the engine has them (§4.8).
  [*stub-render.found-records-in-engine-order]
- When the answer was found at a candidate other than the question's
  name — compared case-insensitively — the section begins with a
  `CNAME` from the question's name, in
  the query's case, to the candidate. Its TTL is the least TTL among the
  records when any are present. [*stub-render.expansion-cname]
- A `found` with no records at an expanded name is `NOERROR` with only
  that leading `CNAME`. Its TTL is the negative cache lifetime: the lesser
  of the enclosing upstream `SOA` record's TTL and minimum field, capped at
  300 seconds and at the TTL of any `CNAME` path the reply followed (§4.5).
  A cache hit uses the remaining lifetime, rounded down to whole seconds.
  With no enclosing `SOA`, the TTL is zero; no lifetime is invented. The
  authority section remains empty. An unexpanded empty `found` has no
  `CNAME`. [*stub-render.expanded-nodata-has-no-cname]

### `notfound` replies [*stub-render.nxdomain-without-soa]

`NXDOMAIN`, with empty answer and authority sections. No `SOA` is
supplied, so a client has nothing from which to cache the absence.

### `unavailable` replies [*stub-render.servfail-empty]

`SERVFAIL`, with empty sections.

## EDNS in stub replies [*stub-render.opt-echoed-with-1232]

When the query carried an `OPT` record, the reply carries one
advertising a payload size of 1 232 bytes, with `DO` clear and no
options. A query without `OPT` gets a reply without one.

## Size and truncation

- Over UDP the reply's size limit is the payload size the query's `OPT`
  advertised, or 512 bytes when that is smaller or there is no `OPT`.
  [*stub-render.udp-size-limit]
- A reply over the limit is replaced by a truncated one, which keeps the
  same header with `TC` set, and the question.
  [*stub-render.truncated-reply-header-and-question]
- The truncated reply keeps the `OPT` record when the reply has one.
  [*stub-render.truncated-reply-keeps-opt]
- The truncated reply carries no records: nothing is partially
  included. [*stub-render.truncated-reply-has-no-records]
- A reply that cannot be encoded at all is not sent.
  [*stub-render.unencodable-reply-not-sent]
- Over TCP the whole reply is sent, whatever its size up to the 65 535
  bytes a DNS message can hold. [*stub-render.tcp-sends-whole-reply]
- A TCP reply is written with its two-byte length, without blocking.
  Unfinished writes are queued with a fixed one-second deadline and a cap
  of 256 queued TCP replies (§2.5); a failed or expired write is not logged.
  [*stub-render.tcp-write-failure-not-logged]
