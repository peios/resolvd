---
title: The Cache
description: What resolvd caches and for how long, the key, the capacity and how entries are evicted, what a hit reports, and every event that flushes it.
---

The cache's key and lifetimes are set by PSPU §6.7. This article is how
resolvd computes them and what it does at the edges.

## The cache key

- An entry is keyed by the candidate in lower case, the record type, and
  the scope key (§1.3). The class is not part of the key; every question
  resolvd asks is class `IN`. The stub rejects other classes before
  consulting the cache (§6.1), even when a matching `IN` answer is held.
  [*engine-cache.key-is-lowercase-candidate-type-scope]
- The same name asked through two scopes is two entries, and a single
  label's expansions are each cached under the expanded name.
  [*engine-cache.expansions-cached-under-expanded-name]

## What is stored

Only replies a server sent with response code `NOERROR` or `NXDOMAIN`
are stored, under the candidate and the scope the candidate was routed
to:

| Reply | Stored as | Lifetime |
|---|---|---|
| `NOERROR` with relevant answer records of class `IN` (§4.8) | `found` with those records | The least TTL among those records, capped at 86 400 s [*engine-cache.positive-lifetime] |
| `NOERROR` with no relevant answer records of class `IN` | `found` with none | Negative lifetime [*engine-cache.nodata-uses-negative-lifetime] |
| `NXDOMAIN` | `notfound` | Negative lifetime [*engine-cache.nxdomain-uses-negative-lifetime] |

### The negative lifetime

- The negative lifetime comes from the first `IN` `SOA` record in the
  reply's authority section whose owner is the effective name or an
  enclosing domain. The effective name is the candidate after following
  its relevant CNAME path (§4.8); suffix matching respects label boundaries.
  Use the lesser of the SOA's `MINIMUM` field and its own TTL, capped at
  300 s. When an alias leads to NXDOMAIN, also cap the lifetime at the
  least TTL of that alias path. [*engine-cache.negative-lifetime-from-soa]
- A reply with no qualifying `SOA` in its authority section has a negative
  lifetime of zero. [*engine-cache.no-soa-negative-lifetime-zero]

### A zero lifetime is not stored [*engine-cache.zero-lifetime-not-stored]

An entry whose lifetime is zero is not stored. A positive answer with a
zero TTL, and a negative answer without an `SOA`, are therefore never
cached.

### What is never stored [*engine-cache.never-stored]

Never stored: synthetic answers, `unavailable`, transport failures, a
UDP reply with `TC` set (the reply to its TCP retry is the one
considered), and
replies with any other response code.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### The TTLs inside an entry [*engine-cache.record-ttls-kept-entry-lifetime-capped]

The records in an entry are kept with the TTLs the server sent. Only the
entry's lifetime is capped.

## Hits

- An entry is live while its expiry is in the future. A live entry is
  returned with each record's TTL lowered to the whole number of seconds
  the entry has left, rounded down, when that is less than the record's
  own. [*engine-cache.hit-ttl-lowered-to-remaining-seconds]
- A `notfound` hit with further candidates waiting moves to the next
  candidate, as a `notfound` from a server would (§4.1).

## Bypassing the cache

- A `resolve` request with `no_cache` set skips the lookup for each of
  its candidates. The reply it gets is still stored.
  [*engine-cache.no-cache-skips-lookup-still-stores]
- Stub queries, `lookup`, and `reverse` always consult the cache.
  [*engine-cache.other-doors-always-consult-cache]

## Capacity and eviction

- The cache holds at most 8 192 entries. [*engine-cache.capacity]
- Expiry alone does not remove an entry. Looking up an expired key
  removes it immediately, before any replacement answer arrives. Otherwise
  it stays until overwritten, flushed, or removed during admission at
  capacity. The `cache_entries` count in `status` includes expired entries
  that have not yet been removed.
  [*engine-cache.expired-entries-linger-and-are-counted]

### Eviction

Storing an entry under a key the cache does not already hold, when it
already holds 8 192 entries, first evicts:

1. every entry whose expiry is at or before the current time;
   [*engine-cache.eviction-sweeps-expired-entries]
2. then, if the cache still holds 8 192 entries, the one entry with the
   earliest expiry — any one of them, when several share it.
   [*engine-cache.eviction-then-earliest-expiry]

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### A long-lived answer preserves other live entries [*engine-cache.long-lived-entry-preserves-live-entries]

The sweep compares against the current time, independently of the new
answer's lifetime. A day-long answer arriving at a full cache of live,
shorter-lived answers replaces only the entry with the earliest expiry;
the cache still holds 8 192 entries. If removing expired entries makes
room, no live entry is evicted.

Older builds compared against the incoming answer's expiry and could
empty a cache of live answers.

### Overwriting a held key [*engine-cache.overwrite-evicts-nothing]

Storing under a key the cache already holds replaces that entry, live
or expired, and evicts nothing else.

## Flushes

| Event | Discards |
|---|---|
| A snapshot in which a scope is new, has a different server list, or is missing (§3.3) | That scope's entries |
| A registry change to `FallbackServers` in content or order (§2.3) | The fallback scope's entries |
| A `flush` request (§5.3) | Everything |
| A restart | Everything |

Nothing else discards entries. Changes to static names, search domains,
the hostname, `ControlSecurity`, scope flags, and metrics leave the cache
as it is.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### A reply after its scope was flushed [*engine-cache.late-reply-stored-after-flush]

A flush also invalidates pending tasks' permission to store answers.
A global `flush` affects every pending task. Removing an interface scope
or changing its servers affects tasks associated with that scope; changing
the fallback list affects tasks associated with the fallback scope.
[*engine-cache.invalidated-task-does-not-store]

An invalidated task still completes its original requester normally,
but cannot store any further answers. This restriction persists through
UDP-to-TCP fallback, timeout retries and later search candidates, even
if a later attempt uses a new server list. Removing and re-adding a
scope does not restore the task's permission. Fresh requests can cache
normally.

Changes only to metrics, search domains, or other scope properties with
unchanged server lists do not invalidate admission; unrelated scopes'
pending tasks are unaffected. This changes cache admission, not request
cancellation or routing. Cache keys, TTLs, and eviction policy are
unchanged.
