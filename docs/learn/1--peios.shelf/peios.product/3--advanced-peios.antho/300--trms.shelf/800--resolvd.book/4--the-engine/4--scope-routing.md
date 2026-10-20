---
title: Scope Routing
description: How resolvd picks the one scope a candidate goes to — which scopes take part at all, each step of the order as implemented, and how ties are broken.
---

PSPU §6.7 gives the routing order. resolvd applies it to each candidate
separately, when the candidate is first asked, and the candidate's
retries stay with the scope it chose.

## Which scopes take part [*engine-routing.only-routable-scopes-take-part]

A scope at `link` or better is up. Server availability does not exclude it
from explicit routing decisions. Search expansion uses the same up scopes.

## The steps

1. **Exclusive.** Choose an exclusive scope at `addressed` or better,
   preferring the lowest metric and then snapshot order.
   [*engine-routing.step-exclusive]
2. **Search domain.** Among up scopes, choose the longest matching domain
   suffix, compared by labels without case distinctions.
   [*engine-routing.step-search-domain]
3. **Reverse subnet.** For a reverse-mapping name, choose an up scope whose
   subnet contains the address. Lowest metric wins, then snapshot order.
   A prefix beyond the address width is treated as that width.
   [*engine-routing.step-reverse-subnet]
4. **Default route.** Choose an up default-route scope, preferring the lowest
   metric and then snapshot order. [*engine-routing.step-default-route]
5. **Lowest metric.** Choose an up scope that has servers, preferring the
   lowest metric and then snapshot order. [*engine-routing.step-lowest-metric]
6. **Fallback.** Use the fallback scope if configured servers exist.
   [*engine-routing.step-fallback]

The first matching step wins. When none selects a scope, the candidate is
`unavailable` without a query.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### An exclusive scope that does not qualify [*engine-routing.exclusive-without-servers-or-address-not-exclusive]

An exclusive scope at `link` alone does not qualify for step 1. It can
participate in later steps as an ordinary up scope.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### A selected scope without servers [*engine-routing.serverless-scope-keeps-selection]

Steps 1 through 4 can select a scope without servers. If upstream work is
needed, the candidate becomes `unavailable`; it does not fall through to
another interface or the fallback set. Synthetic answers and the selected
scope's cache keep their existing precedence.

### Ties between search domains [*engine-routing.search-domain-tie-break]

Between matching domains with the same number of labels, the one in the
scope with the lower metric wins. With equal metrics too, the first
match found wins: the earlier scope in snapshot order, and within one
scope the earlier domain.

## Consequences

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Step 1 takes every candidate [*engine-routing.exclusive-takes-every-candidate]

Step 1 is absolute while it applies: with an exclusive scope chosen,
every candidate goes to it, whatever its name, and step 2 never runs.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Search domains beat the subnet rule [*engine-routing.search-domain-beats-subnet]

Step 2 runs before steps 3 and 4, so a scope whose search domain is
`in-addr.arpa` or `10.in-addr.arpa` takes reverse names ahead of the
subnet rule.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Fallback servers are a last resort [*engine-routing.fallback-unused-while-any-interface-has-a-server]

Fallback servers are used only when no earlier step selects a scope.
An up scope with servers always wins before fallback, and a serverless
match in steps 1 through 4 also prevents fallback. Answers cached through it
are then not consulted, and stay in
the cache until they are flushed, overwritten or evicted (§4.5).

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### A candidate asks only its own scope's servers [*engine-routing.candidate-asks-only-its-scope]

Every attempt for a candidate, and the TCP retry after a truncated
reply, goes to a server of the one scope the candidate was routed to.
When those attempts fail, the candidate is `unavailable` (§4.6); the
servers of other scopes, and the fallback servers, are not asked for
it.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Demotion does not affect routing [*engine-routing.demotion-does-not-affect-routing]

Routing reads only the current scope list. Which servers are demoted
has no effect on which scope a candidate goes to: a scope whose every
server is demoted still takes the candidates routing gives it.
