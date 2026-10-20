---
title: Synthetic Names
description: The names resolvd answers before any network — localhost, the static names, the machine's own name, .local, and their reverses — in the order it checks them and for which record types.
---

PSPU §6.7 lists the names a resolver answers before any network.
resolvd checks them in a fixed order, on the name as asked and before
any search expansion, and the first match answers the task.

## The order

1. **`localhost`, or any name under it.** `127.0.0.1` for `A`, `::1`
   for `AAAA`, both for `ANY`. Source `synthetic`.
   [*engine-synthetic.localhost]
2. **A static name.** An exact, case-insensitive match against the
   `Hosts\` values (§2.3). The name's addresses of the asked family —
   IPv4 for `A`, IPv6 for `AAAA`, both for `ANY`. Source `hosts`.
   [*engine-synthetic.static-name]
3. **The machine's hostname.** An exact, case-insensitive match against
   the hostname (§3.3), answered with the machine's own addresses
   (below). Source `synthetic`. [*engine-synthetic.hostname]
4. **`.local`.** The name `local` or any name under it is `notfound`,
   whatever the type asked. Source `synthetic`. No query is sent.
   [*engine-synthetic.local-is-notfound]
5. **A reverse-mapping name, for `PTR` or `ANY` only.** See below.

A name that matches none of these goes on to search expansion and the
network.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Static names beat the hostname and `.local` [*engine-synthetic.check-order]

Because the order is fixed, a static name beats the hostname and
`.local`: a `Hosts\` value named `printer.local` is answered with its
addresses, and one named after the machine overrides the machine's own
addresses.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### `localhost` beats a static name [*engine-synthetic.static-name-under-localhost-unused]

`localhost` is checked first, so a `Hosts\` value named `localhost`, or
a name under it such as `printer.localhost`, never answers a forward
question: the synthetic loopback answer is given instead. Its addresses
still answer reverse questions through the static-name row below,
except loopback addresses, which the loopback row takes first.

### Record types [*engine-synthetic.other-types-are-empty-found]

For the three address-bearing kinds, the answer is `found` whatever type
was asked; a type other than `A`, `AAAA` or `ANY`, or a family the name
has no address in, gives `found` with no records. `localhost` asked for
`MX` is an empty `found`, not a `notfound`, and is not forwarded.

### The machine's own addresses

- They are every address of every scope at `addressed` or better,
  whether or not the scope has servers, in snapshot order, link-local
  addresses included and loopback addresses excluded.
  [*engine-synthetic.own-addresses-from-every-addressed-scope]
- Repeated addresses are removed only when they are adjacent in that
  list, so an address on two interfaces that are not consecutive in the
  snapshot appears twice. [*engine-synthetic.only-adjacent-duplicates-removed]
- When there are none, the hostname is answered with `127.0.0.1` and
  `::1`. [*engine-synthetic.hostname-without-addresses-is-loopback]

## Reverse names

### Reverse-mapping names [*engine-synthetic.reverse-name-forms]

A reverse-mapping name is one under `in-addr.arpa` with exactly four
labels before the suffix, or one under `ip6.arpa` with exactly 32. The
suffix is matched case-insensitively.

- Each `in-addr.arpa` label parses as a decimal number from 0 to 255.
  Leading zeros and a leading `+` are accepted, so `1.0.0.0127.in-addr.arpa`
  and `+1.0.0.127.in-addr.arpa` both name `127.0.0.1`.
- Each `ip6.arpa` label is a single hexadecimal digit, in either case.

A name of either shape whose labels do not parse is not a
reverse-mapping name.

### Synthetic reverse answers

Asked for `PTR` or `ANY`, a reverse-mapping name is answered
synthetically when its address is:

| Address | Answer | Source |
|---|---|---|
| A loopback address — anything in `127.0.0.0/8`, or `::1` | `PTR localhost` | `synthetic` [*engine-synthetic.reverse-loopback] |
| Listed under a static name | `PTR` that name | `hosts` [*engine-synthetic.reverse-static-name] |
| One of the machine's own addresses, when there is a hostname | `PTR` the hostname | `synthetic` [*engine-synthetic.reverse-own-address] |

The rows are tried in that order.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### An address shared by static names [*engine-synthetic.shared-static-address-reverse-per-configuration]

When several static names list the same address, resolvd returns one PTR:
the name whose ASCII-lowercased presentation form sorts first in byte order.
For example, `alpha.home` wins over `beta.home`. The answer is independent
of registry insertion order, hash-table order, reloads and restarts while
the set of matching names stays the same. It changes when that set changes
and another name sorts first. The selected name retains its configured
spelling in the reply. This rule applies to IPv4 and IPv6, for both `PTR`
and `ANY` questions.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### Other reverse questions [*engine-synthetic.other-reverse-questions-go-to-network]

A reverse name asked for any other type, and a reverse name whose
address matches none of the rows, goes to the network.

## Properties of every synthetic answer

- Every synthetic record has TTL 0. [*engine-synthetic.ttl-zero]
- Synthetic answers are never cached, and the `no_cache` flag has no
  effect on them. [*engine-synthetic.never-cached]
- Each one adds one to the `synthetic` counter (§4.10).

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
## Expanded candidates are not checked [*engine-synthetic.expanded-candidates-not-checked]

Only the name as asked is checked. An expanded candidate is never
compared with the synthetic names, so with a static name `printer.lan`
and the search domain `lan`, a question for `printer` is expanded and
sent to the network as `printer.lan`.
