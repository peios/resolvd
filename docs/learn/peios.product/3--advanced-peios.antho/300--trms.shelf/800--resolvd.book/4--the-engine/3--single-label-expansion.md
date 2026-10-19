---
title: Single-Label Expansion
description: Which search domains resolvd applies to a single-label name, in what order, how the candidates are built and asked, and what never gets expanded.
---

PSPU §6.7 sets the search expansion rules. This article is how resolvd
builds and asks the list of candidates.

## What counts as a single label

- A name is single-label when it parses to exactly one label. The
  trailing dot plays no part: `printer.` is single-label and is expanded
  exactly as `printer` is.
  [*engine-expansion.trailing-dot-does-not-suppress-expansion]
- A top-level domain such as `com` is a single label too, and cannot be
  asked for directly: it is asked only as its expansions.
  [*engine-expansion.top-level-domain-cannot-be-asked]
- Any other name — a multi-label name, or the root — has one candidate,
  itself. [*engine-expansion.multi-label-single-candidate]

## The applicable domains

An exclusive scope at `addressed` or better supplies only its own search
domains, whether or not it has servers. Otherwise, all up scopes contribute
their domains in metric order, followed by `ExtraSearchDomains`.
[*engine-expansion.exclusive-scope-domains-only]
[*engine-expansion.routable-scope-domains-then-extra]

An up scope without servers still contributes domains. Equal metrics keep
snapshot order, and each scope retains its domain order.
[*engine-expansion.scope-without-servers-contributes-no-domains]
[*engine-expansion.up-scope-domains]

An exclusive scope excludes other scopes' domains and extra domains.
With no domains, a single-label question has no candidates and is
`notfound` without a network query. A candidate selecting a serverless
scope is `unavailable` if upstream work is needed; it does not move to
another scope. [*engine-expansion.extra-domains-ignored-under-exclusive]

## Building the candidates

Each domain in turn is appended to the label.

- A candidate already in the list, compared case-insensitively, is not
  added again. [*engine-expansion.duplicate-candidates-removed]
- A candidate longer than 255 bytes on the wire is left out.
  [*engine-expansion.overlong-candidates-left-out]

With no candidates left the name is `notfound` without a query (§4.1).

## The case of a candidate [*engine-expansion.candidate-case-preserved]

A candidate keeps the case of the label as asked and of the domain as
configured; that is the case its records are reported at (§4.8).

## Asking the candidates

- Candidates are asked one at a time, in order. Each is routed on its
  own (§4.4) and shares the question's attempt budget (§4.6).
  [*engine-expansion.candidates-asked-one-at-a-time]
- A `notfound` — from a server or from the cache — moves to the next
  candidate (§4.1).
- `found`, with records or without, is the answer, and later candidates
  are not asked. [*engine-expansion.found-or-nodata-ends-expansion]
- `unavailable` is the answer, and later candidates are not asked.
  [*engine-expansion.unavailable-ends-expansion]
- When the last candidate is `notfound`, the question is `notfound`
  (§4.1).
