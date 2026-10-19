---
title: Reply Validation
description: How resolvd decides a reply belongs to its transaction, what happens to one that does not, and what it takes from one that does — outcome, records, case and lifetime.
---

## Matching

A reply is matched against the transaction it arrived for. It matches
when all of these hold:

1. it decodes as a DNS message — bytes after its last section are
   tolerated; [*engine-reply.match-decodes]
2. its ID equals the transaction's; [*engine-reply.match-id]
3. its `QR` bit is set; [*engine-reply.match-qr-set]
4. it has exactly one question; [*engine-reply.match-one-question]
5. that question's type and class equal those sent; [*engine-reply.match-type-and-class]
6. that question's name is byte-for-byte identical to the name sent,
   case pattern included. [*engine-reply.match-name-case-exact]

### A non-matching reply is ignored [*engine-reply.non-matching-reply-ignored]

A reply that fails any of these is ignored: the transaction is not ended
by it, nothing is counted, and the server is not demoted for it.

### A non-matching datagram on UDP [*engine-reply.non-matching-udp-datagram-becomes-timeout]

A datagram that does not match is discarded while the transaction's
socket stays open. A later matching datagram can answer the same
transaction. Ignoring a datagram does not extend the original two-second
deadline: if no matching reply arrives, the attempt times out and the
server is demoted (§4.6).

### An undecodable or cut-short datagram [*engine-reply.undecodable-or-cut-short-datagram-becomes-timeout]

The same holds for a datagram that does not decode. A datagram longer
than the 4 096-byte read buffer arrives cut short. If the cut falls
inside the DNS message, it cannot decode and is discarded; the socket
remains available for another reply until the original deadline.

### A non-matching TCP reply [*engine-reply.non-matching-tcp-reply-becomes-timeout]

An undecodable or non-matching TCP message is discarded while the
connection remains open. Later complete frames on that connection are
checked, including frames already buffered and a matching frame followed
by EOF. Partial frames remain buffered for the next read. Ignoring a
frame does not extend the original deadline. If the peer closes before a
matching frame completes, the attempt fails; if it stays open without a
matching reply, the attempt times out (§4.6).

## A matching reply

A matching reply adds one to `upstream_answered` and ends the
transaction. Then:

| Reply | Result |
|---|---|
| UDP, `TC` set | TCP retry to the same server (§4.7) |
| Response code `NOERROR` | `found` [*engine-reply.noerror-is-found] |
| Response code `NXDOMAIN` | `notfound` [*engine-reply.nxdomain-is-notfound] |
| Any other response code | The attempt fails (§4.6) |

A `NOERROR` or `NXDOMAIN` reply that is used removes the server's
demotion; a UDP reply with `TC` set does not (§4.6).

### Extended response codes [*engine-reply.extended-rcode-combined]

The response code is the header's four bits combined with the extended
bits of an `OPT` record in the reply, so an extended code is never
mistaken for `NOERROR` or `NXDOMAIN`.

## What is taken from it

### Records

- Relevant answer records of class `IN`, in the order the server
  sent them. [*engine-reply.answer-records-of-class-in]
- For `NXDOMAIN` none are taken, even if the server sent some. [*engine-reply.nxdomain-records-discarded]
- Start at the candidate. Keep records of the requested type at that
  owner; otherwise follow the first `IN` CNAME there, retaining it, and
  repeat at its target. Stop after sixteen aliases, on a repeated name,
  or when no matching record remains. Records unrelated to that path or
  of an unrequested type are discarded before rendering or caching.
  Their TTLs cannot shorten the cache lifetime. [*engine-reply.records-match-question]
- An explicit CNAME question returns CNAME records at the queried owner.
  ANY accepts all `IN` types at that owner and does not follow aliases.
  Owner comparisons are case-insensitive and use DNS label boundaries.
- The authority and additional sections are not returned. [*engine-reply.authority-and-additional-not-returned]

### The case of returned records [*engine-reply.candidate-case-restored]

A record whose owner name equals the candidate, case-insensitively, is
given the candidate's case — the case of the question as asked, not the
randomised case sent. Other records keep the case the server used.

### Lifetime

The cache lifetime of §4.5, computed from the answer records or from the
authority section's `SOA`.

### Upstream flags [*engine-reply.upstream-flags-not-carried]

The server's `AA`, `AD`, `RA` and `CD` bits are not used and are not
carried into any answer.

### An empty `NOERROR` [*engine-reply.empty-noerror-is-nodata]

A `NOERROR` reply with no relevant answer records of class `IN` — including a
referral from a server that does not recurse — is `found` with no
records.

A `notfound` with further candidates moves to the next one (§4.3);
everything else answers the question.
