# scupper

A fail-closed VPN gateway for Linux. Client traffic leaves through a VPN exit
or not at all: the kill switch is enforced by the kernel (nftables and policy
routing), not by a running process.

Status: early development. The design is being written; there is no usable
release yet.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
