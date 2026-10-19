---
title: The Access Check
description: How resolvd checks each native request against its control object — the peer's token, the generic mapping, the compiled default descriptor — and when a new descriptor takes effect.
---

The control object and its check are PSPU §6.4's. resolvd makes the
check after the request has been decoded and before anything else is
done with it.

## The check

1. The connecting peer's token is opened from the socket. When it
   cannot be, resolvd logs `control: no peer token: <error>` and the
   request is denied. [*native-access.no-peer-token-is-denial]
2. A KACS access check is made of the request's right against the
   control object's descriptor, with that token. A check that cannot be
   completed counts as a denial. [*native-access.failed-check-is-denial]
3. A denied request is answered `access denied` (§5.1). [*native-access.denial-reply]

| Request | Right |
|---|---|
| `resolve`, `lookup`, `reverse`, `status` | `RESOLVER_QUERY` (`0x0001`) [*native-access.query-right-requests] |
| `flush` | `RESOLVER_CONTROL` (`0x0002`) [*native-access.control-right-requests] |

### The generic mapping [*native-access.generic-mapping]

The check uses this generic mapping:

| Generic right | Maps to |
|---|---|
| `GENERIC_READ` | `RESOLVER_QUERY`, `READ_CONTROL` |
| `GENERIC_WRITE` | `RESOLVER_CONTROL`, `READ_CONTROL` |
| `GENERIC_EXECUTE` | `RESOLVER_QUERY` |
| `GENERIC_ALL` | `RESOLVER_ALL_ACCESS` (`0x000F0003`) |

### Decoding comes before the check [*native-access.decode-before-check]

A request is decoded before it is checked, so a malformed request gets
its decoding error whoever sent it, and an unknown `query` gets
`unknown query` rather than `access denied`.

### The answer does not depend on the caller [*native-access.answer-independent-of-caller]

The peer's identity is used for this check and for nothing else. Every
caller allowed to ask gets the same answer to the same question.

## The compiled default descriptor [*native-access.compiled-default-descriptor]

The descriptor is `ControlSecurity` when it holds a valid self-relative
descriptor, else the compiled default (§2.3):

| Component | Value |
|---|---|
| Owner | SYSTEM |
| Group | SYSTEM |
| DACL | SYSTEM: `RESOLVER_ALL_ACCESS`; Administrators: `RESOLVER_ALL_ACCESS`; Everyone: `RESOLVER_QUERY` and `READ_CONTROL` |

## A new descriptor applies to later requests [*native-access.new-descriptor-applies-to-later-requests]

The descriptor is rebuilt whenever the registry configuration changes
(§2.3). A request decoded after the change is checked against the new
one; a request already being answered is not checked again.

## What the control object does not govern [*native-access.stub-not-governed]

The stub listener is not checked against the control object (PSPU §6.8):
anything on the machine that can reach `127.0.0.53` can ask. A program
denied `RESOLVER_QUERY` on the native socket still resolves names
through the stub listener. The NSS shim uses the native socket, so for
such a program `getaddrinfo` fails (§7.1) while a resolver that speaks
DNS directly succeeds.
