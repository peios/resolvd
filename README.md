# resolvd

Peios name resolution, the resolv command, and the NSS module.
The public client library is `libresolvd.so.1`, with the safe Rust wrapper
`resolvd-client`.

- [Build and validate](docs/building.md).
- [User and developer documentation](docs/learn/1--peios.shelf/peios.product).
- [Command and library manuals](docs/man).

Use pekit to build and test resolvd. Packages and builds with the native
Peios toolchain are not yet built with pekit; a Linux development build is
not a native release qualification.
