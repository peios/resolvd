---
title: Lookup and Reverse
description: How a lookup becomes one task per family and how their results are combined — outcome, CNAME chasing, the canonical name, address order and source — and how a reverse becomes a PTR question.
---

## `lookup`

A `lookup` (PSPU §6.5) asks for `A`, `AAAA`, or both:

| `family` | Tasks |
|---|---|
| `any` | `A` and `AAAA`, started together [*engine-lookup.any-starts-both-families] |
| `inet` | `A` [*engine-lookup.inet-asks-a] |
| `inet6` | `AAAA` [*engine-lookup.inet6-asks-aaaa] |

### Each task is an ordinary question [*engine-lookup.tasks-independent-reply-after-last]

Each task is an ordinary question (§4.1): it has its own synthetic
check, its own expansion, its own routing per candidate, its own cache
lookups and its own attempts. The two tasks of an `any` lookup run at
the same time and can be answered from different sources. The reply is
built when the last of them is done.

### The outcome

| Tasks' outcomes | `outcome` |
|---|---|
| At least one `found`, with or without records | `found` [*engine-lookup.any-found-is-found] |
| None `found`, at least one `unavailable` | `unavailable` [*engine-lookup.unavailable-without-found] |
| Every one `notfound` | `notfound` [*engine-lookup.all-notfound-is-notfound] |

An `A` answer and an `AAAA` that is `unavailable` is `found`, with IPv4
addresses only.

### Chasing CNAMEs

For each `found` task, resolvd looks for addresses in that task's
answer records, starting at the candidate the answer was found at.
Names are compared case-insensitively.

1. If the first record at the current name is a `CNAME`, and no record
   of the asked type is at the current name, the chase moves to the
   `CNAME`'s target. [*engine-lookup.cname-chase-follows-first-cname]
2. This repeats at most 16 times; a loop stops there. [*engine-lookup.cname-chase-depth-16]
3. The addresses are the `A` (for the `A` task) or `AAAA` (for the
   `AAAA` task) records at the name the chase ended at, in answer order,
   each with its record's TTL. [*engine-lookup.cname-chase-addresses-at-final-name]

### The chase asks nothing further [*engine-lookup.chase-asks-no-further-question]

Only the records in the task's own answer are used. A chain that leaves
them — a `CNAME` whose target's addresses the server did not include —
ends with no addresses, and no further question is asked.

### The reply fields

- `addresses` lists each finished task's addresses in turn, in the order
  the tasks finished, so whether IPv4 or IPv6 addresses come first
  depends on which family was answered first. [*engine-lookup.address-order-follows-completion]
- `canonical` and `source` come from the same selected `found` task.
  Prefer a task that produced addresses; when both or neither did, prefer
  `A` over `AAAA`. Completion order does not affect this choice.
  `canonical` is the name that task's CNAME chase ended at, after search
  expansion. Without a `found` task it is the name asked, as parsed, in
  presentation form without a trailing dot (the root is `.`).
  [*engine-lookup.canonical-name-rule]
- A `found` with no addresses still reports the expanded or chased name.
  [*engine-lookup.canonical-expanded-without-addresses]
- A name that does not parse is answered at once with `outcome`
  `notfound`, `canonical` `.`, no addresses and `source` `local`; no
  task is started. [*engine-lookup.unparseable-name-canonical-root]
- `source` is the source of the selected task, and `local` when no task
  was `found`. It describes that task; the other family's records can
  have a different source. [*engine-lookup.deterministic-source]
- `validation` is `unvalidated`.
- A `lookup` adds one to `queries` however many tasks it makes. [*engine-lookup.counts-one-query]

## `reverse` becomes a `PTR` question [*engine-lookup.reverse-is-ptr-resolve]

A `reverse` turns its address into the reverse-mapping name — the four
octets reversed under `in-addr.arpa` for IPv4, the 32 nibbles reversed,
in lower-case hexadecimal, under `ip6.arpa` for IPv6 — and resolves that
name for `PTR` exactly as a `resolve` without `no_cache` would. The
reply is an ordinary `answer` (§5.3).
