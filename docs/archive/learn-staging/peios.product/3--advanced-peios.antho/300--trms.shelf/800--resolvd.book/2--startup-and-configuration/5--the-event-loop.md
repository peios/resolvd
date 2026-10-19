---
title: The Event Loop
description: resolvd's single thread — what it polls, how long it sleeps, the order it services ready descriptors in, and what that order means for a client.
---

## One thread and one poll [*loop.single-thread-single-poll]

resolvd runs on one thread. Every input is a descriptor in one `poll`
call, and the engine sees time only when the loop hands it the current
instant.

## What is polled

Each iteration builds the poll set afresh:

1. the native listener, except during its accept-error backoff;
2. the stub UDP socket;
3. the stub TCP listener, except during its accept-error backoff;
4. the netd channel, while connected;
5. the registry watch, while armed;
6. every native connection still sending its request;
7. every stub TCP connection still sending its query;
8. every upstream socket — for reading, or for writing while a TCP
   connection is still being established or its query is still being
   sent;
9. native and stub TCP replies waiting to write, for writability;
10. native and stub TCP streams awaiting engine answers, for hangup and
    error indications only. Readability and read-half-close are not
    requested, preserving supported half-closes without spinning on EOF.

### The poll timeout [*loop.poll-timeout-is-earliest-deadline]

The poll timeout is the earliest of: the next upstream transaction
deadline, the next netd reconnection time while disconnected, the
moment the oldest stub TCP connection reaches its 10-second bound, the
moment the oldest native connection reaches its 5-second bound, the
earliest queued reply write deadline, and the end of either listener's
250 ms accept-error backoff. With none of these pending, the loop sleeps
until a descriptor is ready.

The timeout is the time to that moment in whole milliseconds, rounded
down. A moment less than a millisecond away gives a timeout of zero, so
the loop polls again without sleeping until the moment has passed.

## Service order [*loop.service-order]

After `poll` returns, ready descriptors are serviced in this order:

1. waiting native and stub TCP streams with definite hangup/error,
   cancelling their questions and upstream transactions;
2. upstream sockets — replies that have arrived are answers already owed;
3. queued native replies, then queued stub TCP replies, whose sockets are writable;
4. the stub UDP socket, reading at most 64 datagrams;
5. the stub TCP listener, accepting at most 64 connections;
6. stub TCP connections still sending queries;
7. the native listener, accepting at most 64 connections;
8. native connections still sending requests;
9. the netd channel;
10. the registry watch.

The fixed datagram/accept batches yield to the other doors and timers even
while one listener remains continuously ready. [*loop.listener-batches]

## Timers after descriptors [*loop.timers-run-after-descriptors]

Once the ready descriptors have been serviced, the timers run, in this
order: transactions at or past their deadline fail over to their next
attempt (§4.6), a due netd reconnection is attempted (§3.2), stub TCP
connections 10 seconds old or older are closed, expired reply writes are
closed, and native connections 5 seconds old or older are closed.

## Answers within an iteration [*loop.local-answers-within-the-iteration]

A question that can be answered without the network — synthetic, from
the cache, or refused — has its answer prepared and its first write
attempted within the iteration that read it.

A question that needs the network sends its first transaction within
that iteration too, and has its answer prepared in the iteration that
sees its deciding reply or its last deadline. Delivery may continue over
later writable events for a slow native or TCP reader.

## Nonblocking reply writes [*loop.replies-written-blocking]

Native and stub TCP replies get one nonblocking write attempt immediately.
If the socket cannot accept the whole frame, the unwritten suffix is
queued and resumed when that socket is writable. Each ready event makes
one write attempt; partial progress is retained without duplicating bytes.
The connection closes after the whole frame is written, on a write error,
or when its fixed one-second write deadline expires. Progress does not
extend that deadline. Other inputs and timers continue to be serviced.

At most 256 unfinished native replies and 256 unfinished stub TCP replies
are queued. Each frame is bounded by its protocol ceiling (§5.1, §6.2).
Even when a queue is full, a new reply gets its immediate write attempt;
if it too needs queue space, that connection closes. Ready readers can
therefore still receive replies while stalled readers occupy the queue.

Stub UDP replies and upstream queries are not written this way. The
netd subscription request is written with a two-second timeout when
the channel is opened (§3.1).
