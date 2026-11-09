# scupper

A fail-closed VPN gateway for Linux. Client traffic leaves through a VPN exit
or not at all: the kill switch is enforced by the kernel (nftables and namespace
routing), not by a running process.

Status: early development. The design is being written; there is no usable
release yet.

M2 uses the immutable configuration store under `/var/lib/scupper`. `config show`,
`validate`, `load`, `history`, `diff`, and `rollback` inspect and version TOML;
`load` and `rollback` require root and confirmation (`--yes` without a TTY).
They store configuration and rendered rules without applying them. `rules`
prints head's namespace ruleset; `rules --diff` compares it with live rules.
`check` and `status` require an M2 gateway. The v1 host-layout `apply`,
wg-quick `connect` and `disconnect` commands have been retired.

The kernel lab is [cargo xtask leaktest](lab/README.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
