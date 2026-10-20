---
title: Terminology
description: The terms specific to resolvd's engine — task, candidate, transaction, attempt, routable scope — and where the contract's own terms are defined.
---

The protocol's terms — name, question, record, scope, route, outcome,
source, door, synthetic answer, control object, stub door — are used as
PSPU §6.2 defines them. The terms below are resolvd's own.

**Task.** One question the engine is working on: a name and a record
type. A `resolve` or `reverse` request, and every stub query, is one
task. A `lookup` is one task per address family it asks for.

**Candidate.** One name a task asks. A multi-label name has exactly one
candidate, itself. A single-label name has one candidate per applicable
search domain (§4.3), asked in turn.

**Transaction.** One query sent to one server over one transport, with
its own DNS message identifier, its own case pattern, its own socket and
its own deadline.

**Attempt.** A transaction counted against the question's attempt limit.
Failures spend the shared question budget. A TCP retry after a truncated
UDP reply also spends an attempt (§4.6).

**Up scope.** A scope at `link` or better. Up scopes contribute search
domains and participate in routing independently of whether they have
servers. Exclusive selection additionally requires `addressed` or better.
Only the ordinary lowest-metric choice requires servers (§4.4).

**Scope key.** The string that identifies a scope in the cache and in
routing: the interface's `ifid` from netd, or `fallback` for the
registry's fallback servers.

**Demoted server.** A server address whose last failure was less than
30 seconds ago, and which has not given a usable reply since; it is
tried after its healthy peers (§4.6).

**In-flight ceiling.** The bound on outstanding upstream transactions,
beyond which a question that needs the network is answered `unavailable`
at once (§4.6).

**The loop.** resolvd's single thread and its `poll` (§2.5).
