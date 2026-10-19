---
title: Stalls and Loops
description: The failures that come from resolvd's single thread and its channel to netd — a stalled reply reader, a refused subscription, a lost registry watch, and cache capacity pressure.
---

## A client that does not read

Native and stub TCP replies are written without blocking (§2.5). A client
that does not read can retain its own queued reply until the fixed
one-second write deadline, then its connection closes. It does not stop
other lookups. Each door holds at most 256 queued replies; if full, a
new reply that cannot be written immediately is closed too. Stub TCP
write failures are silent; native failures log `control: reply failed`.

## netd refuses the subscription

When netd accepts the connection and answers `subscribe` with an error
— resolvd's account lacks `NETWORK_QUERY`, for instance — resolvd drops
the channel and retries with exponential backoff (§3.2): 0.5 seconds,
then 1, 2, 4, 8, and ten seconds between attempts until a good snapshot
resets the sequence. The log shows `subscribed to netd`, then `netd
refused the subscription`, then `lost the netd channel; reconnecting`
for each refusal. `resolv status` shows `netd`
as `not connected` except in the moment between each reconnection and
its refusal, and the scopes are whatever the last accepted snapshot
held, or none.

## The registry watch is lost

When the watch cannot be armed at startup, or fails and cannot be
re-armed, configuration changes are no longer seen (§2.3). `resolv
status` still shows the fallback servers in use, so a change to
`FallbackServers` that does not appear there is the sign. A restart
reads the key again and re-arms the watch.

## Cache capacity pressure

At 8 192 entries, storing a new key removes expired entries first. If
that creates room, it keeps every live entry; otherwise it replaces only
the entry with the earliest expiry (§4.5). A long answer lifetime does
not cause a sweep of shorter-lived answers that are still valid.

`cache_entries` can fall sharply when admission removes many expired
entries. Expiry alone does not remove them, so reaching 8 192 does not
mean 8 192 live answers. Looking up an expired key also removes it,
before its replacement arrives.

Older builds compared the sweep against the incoming answer's expiry
(§4.5). On those builds a day-long answer could empty a full cache of
live answers, causing a burst of upstream requests.
