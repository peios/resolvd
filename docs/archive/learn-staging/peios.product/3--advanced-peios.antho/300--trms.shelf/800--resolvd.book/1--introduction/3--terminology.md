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

**Attempt.** A transaction counted against a candidate's attempt limit.
Every UDP transaction is an attempt; the TCP transaction that follows a
truncated reply is not (§4.6).

**Routable scope.** In [source `b4f7085`](https://github.com/peios/resolvd/blob/b4f70857729069952762f8e2a2b56357b15d4760/resolvd/src/engine.rs),
a scope that is up — at level `link` or better, in
the sense of PSPU §6.2 — and has at least one server. Only routable
scopes take part in routing and contribute search domains (§4.3, §4.4);
an up scope with no servers takes part in neither.

The [proposed source correction](https://github.com/peios/resolvd/blob/f5190f8bd47ae74da73e0c1ffa405f86eb782acf/resolvd/src/engine.rs) separates
being up from having DNS servers, as PSPU §6.2 requires. All up scopes
participate in search expansion and routing steps 1–4, with step 1 still
requiring `addressed` or better and the exclusive flag. Only the ordinary
lowest-metric choice in step 5 requires servers (§4.4). This is proposed
source behavior, not a released package or an installed resolver; check
the installed source revision before relying on it.

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
