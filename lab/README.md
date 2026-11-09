# Namespace leak lab

The M2 reference lab runs through `cargo xtask leaktest`. The M1 shell lab
was retired; its recorded results belong in the review archive.

Use a disposable Linux host with root and kernel WireGuard support. Install
`wireguard-tools nftables iproute2 tcpdump dnsmasq-base util-linux iputils-ping
conntrack slirp4netns`, then run from the repository:

```sh
cargo build -p scupper --locked
sudo timeout 1200 cargo xtask leaktest --artifacts lab-out --capture-fixtures lab-out/fixtures
```

The runner refuses occupied resources, builds the M2 namespace topology,
checks healthy and injected fault states, and records captures and results in
`lab-out`. CI runs the `leaktest` job on Ubuntu 24.04 and 22.04. See
[the xtask guide](../xtask/README.md) for topology, prerequisites and artifacts.
