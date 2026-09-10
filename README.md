# resolvd

`resolvd` is Peios's machine-wide name-resolution service. It keeps one DNS
policy and one cache behind three compatible client surfaces:

- the native `/run/resolvd/resolv.sock` protocol used by Peios programs;
- the loopback DNS stub on `127.0.0.53:53`; and
- `libnss_peios_net.so.2`, the fixed hosts NSS module used by Peios glibc.

Live per-interface servers, search domains, addresses, metrics, and routing
roles arrive from `netd`. Machine-wide fallback servers and static host names
come from `Machine\System\Network\Dns`. The service never rewrites
`/etc/resolv.conf` and Peios has no `/etc/hosts`; the packaged file is a
constant pointer to the loopback stub.

## Repository layout

- `dns`: bounded DNS wire parser and encoder, with adversarial and fuzz tests.
- `libresolv`: native request/reply protocol and framing.
- `resolvd`: policy engine, cache, upstream transports, and service process.
- `resolv`: operator client.
- `nss`: minimal NSS shim loaded into POSIX processes.
- `fuzz`: libFuzzer targets for every externally controlled parser and engine.

The split is deliberate. The pure protocol crates own no I/O or policy, the
operator client owns no service state, and the NSS package keeps the code
loaded into every process independent from the daemon.

## Development

The workspace requires Rust 1.98.1 or later and the Peios SDK development
files. Netd's public control-protocol crate and the Peios Rust bindings are
pinned to immutable Git revisions. For an in-tree development build,
`.env-dev` points Cargo only at the local Peios SDK library and header outputs:

```sh
. ./.env-dev
cargo test --workspace --locked
```

Release packaging is defined by `pekit.toml` and `packages.pekit/`. It tests
the exact locked dependency graph offline, emits independently installable
daemon, client, and NSS packages, and validates installed payload and ELF
hardening before any package can be published.

The public resolver behavior and protocol contracts are specified in the
Peios documentation under the name-resolution interface and networking
guides. This README is only a source-tree orientation, not a second contract.

## Licence

resolvd is licensed under the MIT License. See `LICENSE`.
