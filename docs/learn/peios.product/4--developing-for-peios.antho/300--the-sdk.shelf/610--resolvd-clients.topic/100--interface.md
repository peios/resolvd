---
title: Using libresolvd
type: reference
description: Operations, ownership, errors, and Rust access for libresolvd ABI 1.
---

`libresolvd.so.1` provides the public C interface for resolvd. The
`resolvd-client` crate wraps the same shared library and returns owned Rust
values. Internal implementation crates do not replace this public boundary.

## Operations

The library reads resolver status, looks up addresses, resolves DNS record
types, performs reverse lookups, and flushes the cache. Replies retain their
source, interface, and server information. A successful library exchange can
still contain a DNS failure outcome; check the typed answer before using its
records. Flushing requires the caller's existing control permission.

The shared library is `libresolvd.so.1`. It is separate from the platform's
`libresolv` library and from `libnss_peios_net.so.2`, which provides the glibc
name-service interface. Applications do not link the NSS module directly.

## Linking and ownership

Include `<peios/resolvd.h>` and use the `resolvd` pkg-config module. The
installed header and `libresolvd(3)` describe individual functions and data
layouts. `peios_resolvd_abi_version()` returns the ABI major version, 1.

Each operation returns an owned result, including failures. Check
`peios_resolvd_result_error()` before reading a view, and release the result
exactly once with `peios_resolvd_result_free()`. Error codes are POSIX
numbers;
human-readable diagnostic wording is not a stable identifier. Reading the
stored error does not set thread-local `errno`.

Strings are UTF-8 spans with explicit byte lengths, without terminating NUL
bytes. Input spans are borrowed for the call and must remain live, aligned,
and initialized. A null pointer with zero length represents absent optional
text; a non-null pointer with zero length represents present empty text.
Returned strings, arrays, and nested views belong to the result. Copy what
you need before freeing it. Handles from another library are not valid here.

## Connections and failure

Each ordinary daemon operation opens its own filesystem Unix socket. The
system default is `/run/resolvd/resolv.sock`; clients can select another
socket for a
private service instance or a test.

A positive timeout in milliseconds bounds connection, sending, and receiving
together. A full connection queue can fail immediately. A transport error
does not establish whether a requested change was applied. The library does
not automatically replay operations after an uncertain failure.

## Rust access

Use `Client::system(Duration)` for the installed daemon or
`Client::new(path, Duration)` for an explicit socket. The wrapper copies
result views into Rust values and releases C results through `Drop`.
Select a matching source revision of `resolvd-client` and link the installed
shared library; the crate is not a precompiled Rust ABI package.
