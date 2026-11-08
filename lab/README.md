# Kernel lab

Run only on a disposable Linux VM with root, outbound internet, and kernel
WireGuard support. **Never run this on a live gateway.** The lab reserves the
`gw`, `provider`, and `client` namespaces and the `172.31.0.0/16` subnet.

It builds the v1 gateway (`eth0`, `wg0`, `proton0`), a WireGuard provider with
NAT, and a WireGuard client. The host supplies internet forwarding. Only tagged
host iptables forwarding/NAT rules and IPv4 forwarding are changed outside the
namespaces; cleanup removes those rules and restores forwarding on exit.
Reverse-path filtering is disabled inside the namespaces for policy routing.
`proton0` has no main-table routes (the equivalent of `Table = off`).

Install `musl-tools wireguard-tools nftables iproute2 util-linux curl iptables`,
then, from the repository with its pinned Rust toolchain:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --locked --target x86_64-unknown-linux-musl
sudo timeout 900 lab/run.sh target/x86_64-unknown-linux-musl/release/scupper lab-captures
```

The lab checks real exit codes, heals and checks again after each fault, and
compares the client's HTTPS exit IP with `check`. The legacy iptables fault runs
last and heals by rebuilding `gw`; it is skipped only if `iptables-legacy` is
missing. Internet/DNS/probe failures fail the assertions rather than being
skipped. The first real kernel run happens in CI.

Captures include healthy and fault-state command output, canonical nft JSON,
command exit codes/stderr, kernel/nft versions, the nftables service unit when
available, and `results.tsv`. Public WireGuard keys become `PUBKEY1` etc.; fresh
private keys stay in a temporary directory with mode 0700 and are deleted.
