---
title: Single-Label Expansion
description: Which search domains resolvd applies to a single-label name, in what order, how the candidates are built and asked, and what never gets expanded.
---

PSPU §6.7 sets the search expansion rules. This article is how resolvd
builds and asks the list of candidates.

## What counts as a single label

- A name is single-label when it parses to exactly one label. The
  trailing dot plays no part: `printer.` is single-label and is expanded
  exactly as `printer` is. [*engine-expansion.trailing-dot-does-not-suppress-expansion]
- A top-level domain such as `com` is a single label too, and cannot be
  asked for directly: it is asked only as its expansions. [*engine-expansion.top-level-domain-cannot-be-asked]
- Any other name — a multi-label name, or the root — has one candidate,
  itself. [*engine-expansion.multi-label-single-candidate]

## The applicable domains

The table and serverless exclusion below describe
[source `b4f7085`](https://github.com/peios/resolvd/blob/b4f70857729069952762f8e2a2b56357b15d4760/resolvd/src/engine.rs).

| When | Domains, in order |
|---|---|
| Routing's step 1 applies: a routable exclusive scope is at `addressed` or better (§4.4) | That scope's search domains, and nothing else [*engine-expansion.exclusive-scope-domains-only] |
| Otherwise | The search domains of every routable scope (§1.3), scopes ordered by metric, then `ExtraSearchDomains` [*engine-expansion.routable-scope-domains-then-extra] |

The exclusive scope is the one routing would choose (§4.4).

- An up scope that has search domains and no servers is not routable,
  and contributes none of them. [*engine-expansion.scope-without-servers-contributes-no-domains]
- Scopes with equal metrics keep their snapshot order, and each scope's
  domains keep their own order.
- `ExtraSearchDomains` is not applied while routing's step 1 applies. [*engine-expansion.extra-domains-ignored-under-exclusive]

### Proposed serverless-scope correction [*engine-expansion.up-scope-domains]

The [proposed source correction](https://github.com/peios/resolvd/blob/f5190f8bd47ae74da73e0c1ffa405f86eb782acf/resolvd/src/engine.rs) uses all
scopes at `link` or better, including scopes with no DNS servers. Without
a qualifying exclusive scope, their domains are ordered by metric and
then followed by `ExtraSearchDomains`; equal metrics retain snapshot
order and each scope keeps its domain order.

An exclusive scope at `addressed` or better supplies only its own domains,
even without servers: other scopes' domains and `ExtraSearchDomains` are
not used. For a name not already answered synthetically, if that scope
has no domains, a bare single-label name has no candidates and remains
`notfound` without a query. If expansion produces a candidate
that selects a serverless scope and needs upstream work, it is
`unavailable`; later candidates are not tried. Synthetic-answer and
cache handling remain unchanged.

This describes proposed source behavior, not a released package or an
installed resolver. The source-revision qualification in §4.4 applies.

## Building the candidates

Each domain in turn is appended to the label.

- A candidate already in the list, compared case-insensitively, is not
  added again. [*engine-expansion.duplicate-candidates-removed]
- A candidate longer than 255 bytes on the wire is left out. [*engine-expansion.overlong-candidates-left-out]

With no candidates left the name is `notfound` without a query (§4.1).

## The case of a candidate [*engine-expansion.candidate-case-preserved]

A candidate keeps the case of the label as asked and of the domain as
configured; that is the case its records are reported at (§4.8).

## Asking the candidates

- Candidates are asked one at a time, in order. Each is routed on its
  own (§4.4) and has its own attempt budget (§4.6). [*engine-expansion.candidates-asked-one-at-a-time]
- A `notfound` — from a server or from the cache — moves to the next
  candidate (§4.1).
- `found`, with records or without, is the answer, and later candidates
  are not asked. [*engine-expansion.found-or-nodata-ends-expansion]
- `unavailable` is the answer, and later candidates are not asked. [*engine-expansion.unavailable-ends-expansion]
- When the last candidate is `notfound`, the question is `notfound`
  (§4.1).
