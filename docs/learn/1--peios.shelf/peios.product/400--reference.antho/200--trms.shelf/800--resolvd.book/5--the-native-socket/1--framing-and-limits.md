---
title: Framing and Limits
description: How resolvd reads a request from a native connection — the connection cap, the size ceiling, the five-second bound, decoding, and the exact error replies — and how it writes the reply.
---

The framing, the one-request-per-connection rule, and the requirement to
answer errors with an error reply are PSPU §6.4's. This article is
resolvd's reading of them.

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
## Accepting connections [*native-framing.pending-connection-cap-closes-silently]

At most 64 waiting connections are accepted per event-loop iteration.
When 256 native connections are either still sending their requests or
waiting for engine answers, a newly accepted connection is closed at
once, with no reply; so is one that cannot be made nonblocking. Reading a
request keeps its slot occupied until resolution completes or the asker
is abandoned (§4.1). Reply writers use a separate bounded queue (§2.5).

## Reading the request

Each connection is read without blocking. Partial headers and payloads
are retained until more bytes arrive or the delivery bound expires.

1. Read exactly the four-byte little-endian payload length. A length
   above 65 536 gets the reply `request too large` and the connection
   closes, without reading any payload bytes. [*native-framing.length-ceiling]
2. Read only that many payload bytes, in chunks of at most 4 096 bytes.
   The buffered frame never exceeds 65 540 bytes, including its header.
   [*native-framing.buffered-bytes-ceiling]
3. Decode the complete payload immediately. Bytes after this first frame
   remain unread and do not count against its size ceiling; they cannot
   make a legal request too large. [*native-framing.trailing-bytes-ignored]

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### The length check precedes the payload [*native-framing.payload-read-before-length-check]

The declared length is checked before any payload is read, even when the
client queues the header and a large payload together. A legal request
followed by additional bytes is still answered once. This is one request
per connection; extra frames are not processed. When extra bytes remain
unread, the client can observe a connection reset after its framed reply
instead of a clean end of file.

## A connection that ends early

- A connection that closes, or fails to read, before its request is
  complete is dropped without a reply. [*native-framing.early-close-dropped]
- A client that sends its whole request and then shuts down its writing
  side is answered as usual, whether the end of file is already waiting
  behind the request or arrives later. The complete frame is decoded
  without reading beyond it, and the connection closes after its one
  reply. A partial frame followed by end of file is dropped immediately,
  without waiting for the delivery timeout.
  [*native-framing.request-then-half-close-dropped]
- A connection that has not delivered a complete request five seconds
  after it was accepted is closed without a reply.
  [*native-framing.five-second-delivery-bound]

## Decoding

The payload is a MessagePack map. Keys are strings; duplicate top-level
keys fail. Duplicate keys within an unknown skipped value are not checked.
[*native-framing.duplicate-top-level-key-is-error]

Unknown fields are skipped, including floats, fixed and variable-length
extensions, and the full unsigned 64-bit range. Skipped strings must still
be valid UTF-8 and skipped containers retain the 32-level depth limit.
Truncated values fail, and the reserved `0xC1` marker is unsupported.
[*native-framing.unknown-keys-skipped]
[*native-framing.unknown-key-unsupported-value-fails]
[*native-framing.unknown-key-nesting-limit]
[*native-framing.proposed-unknown-field-correction]

`query` is required and must name a supported operation.
[*native-framing.missing-or-unknown-query-is-error]

Known fields are type-checked even when unused by the selected operation.
The `type` field must fit its documented range. Unknown-field skipping does
not widen any known field's accepted range.
[*native-framing.wrong-field-type-is-error]

Bytes after the top-level map are ignored. The first error encountered in
map order is returned; required-field checks follow decoding of the map.
[*native-framing.bytes-after-map-ignored]

## Error replies

Every error reply is `ok: false` with an `error` string and nothing
else. The decoder reports these causes:

| `error` | Cause |
|---|---|
| `request too large` | The size checks above |
| `malformed message: truncated message` | The payload ends inside a value, or an array or map claims more items than bytes remain, a map's keys and values counted separately [*native-framing.error-truncated] |
| `malformed message: unexpected value type` | A known field, a key, or the payload itself has the wrong MessagePack type; this includes a `type` that is negative or above 9 223 372 036 854 775 807 [*native-framing.error-unexpected-type] |
| `malformed message: unsupported value type` | The reserved MessagePack marker `0xC1` [*native-framing.error-unsupported-type] |
| `malformed message: string is not UTF-8` | A string that is not UTF-8 [*native-framing.error-not-utf8] |
| `malformed message: nested too deeply` | Nesting beyond 32 levels inside a skipped value [*native-framing.error-nested-too-deeply] |
| `missing or malformed field <name>` | A field the request needs is absent; a `type`, in any request, from 65 536 to 9 223 372 036 854 775 807; or the `address` of a `reverse` that is not an IP address [*native-framing.error-missing-or-malformed-field] |
| `duplicate field <name>` | A repeated key [*native-framing.error-duplicate-field] |
| `unknown query "<name>"` | A `query` resolvd does not know [*native-framing.error-unknown-query] |
| `access denied` | The access check (§5.2) |
| `reply too large` | The encoded reply would exceed the 65 536-byte payload ceiling; it is replaced by this error |

<!-- Keep the published citation identifier on its heading. -->
<!-- lint-disable-next-line line-length -->
### The connection after an error reply [*native-framing.connection-closed-after-error-reply]

After an error reply the connection is closed.

## Writing the reply

- The reply is framed the same way — four-byte little-endian length,
  then the MessagePack map — and written without blocking. An unfinished
  write is queued with a fixed one-second deadline and a cap of 256 queued
  native replies (§2.5). A failed or expired write is logged as
  `control: reply failed: <error>`. The connection is then closed.
  [*native-framing.reply-written-then-closed]
- An encoded reply payload can be at most 65 536 bytes, excluding its
  four-byte length prefix. A larger reply is replaced by the error
  `reply too large`; no partial answer is sent. This applies to every native
  reply kind. Exactly 65 536 bytes is allowed.
  [*native-framing.reply-size-not-checked]
