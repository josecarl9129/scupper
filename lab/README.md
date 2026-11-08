# Kernel lab

Run only on a disposable Linux VM with root, outbound internet, and kernel
WireGuard support. **Never run this on a live gateway.** The lab reserves the
`gw`, `provider`, and `client` namespaces and the `172.31.0.0/16` subnet.

It builds the v1 gateway (`eth0`, `wg0`, `proton0`), a WireGuard provider with
NAT, and a WireGuard client. The host supplies internet forwarding. Only tagged
host iptables forwarding/NAT rules and IPv4 forwarding are changed by
`lab/run.sh` outside the namespaces; cleanup removes those rules and restores forwarding on exit.
Reverse-path filtering is disabled inside the namespaces for policy routing.
`proton0` has no main-table routes (the equivalent of `Table = off`).

Install `musl-tools wireguard-tools nftables iproute2 util-linux curl iptables tcpdump iputils-ping`,
then, from the repository with its pinned Rust toolchain:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --locked --target x86_64-unknown-linux-musl
sudo timeout 900 lab/run.sh target/x86_64-unknown-linux-musl/release/scupper lab-captures
```

The lab checks real exit codes, heals and checks again after each fault, and
compares the client's HTTPS exit IP with `check`. The legacy iptables fault runs
last and heals by rebuilding `gw`; it is skipped if `iptables-legacy` or its kernel facility is
unavailable. Foreign nft dup/fwd and tc cases also record `skipped` with the
reason for explicit kernel capability errors; other injection failures fail
the lab. Internet/DNS/probe failures fail the assertions rather than being
skipped. CI runs the same musl binary on Ubuntu 24.04 and 22.04 with independent
results (`fail-fast: false`), covering the host-ruleset canonicalization in V-04.
Artifacts are named `lab-captures-<runner>`.

Each case and heal also runs continuous client pings and a rate-limited HTTPS
transfer, with an established TCP connection verified before fault injection.
`tcpdump` captures the host end of gateway `eth0`, filtering for `10.99.0.2` or
`10.2.0.2` before the host's NAT. Healthy, bug-4, tunnel-deleted (bug 2),
exit-link-down, config-disagreement, and every heal must have zero un-NATed
packets; other check-2 cases report their counts as information. Per-case pcaps,
traffic logs, and packet counts accompany the existing verdict assertions in
`results.tsv`. Failure to establish the TCP flow or run/read the capture fails
the lab.

Run `sudo timeout --kill-after=10 300 lab/v23.sh lab-captures` after the namespace
lab to record V-23 on the disposable runner host. It records the nftables unit's
`ExecStop`, probe-table survival after stock and no-flush stops, and restart and
table survival during package reinstall in `v23.tsv`. Answers are observations;
failed operations fail the script. It removes its table and temporary drop-in.
This script starts/stops nftables and can flush the host ruleset.

Then run `sudo timeout --kill-after=10 180 lab/v24.sh lab-captures` to record
V-24 on the host (or a reason for skipping when networkd is inactive). It tests
route-table 51820 and rule 1000 survival across networkd restarts on an unmanaged
`v24wg`, first without and then with both `ManageForeign*` settings disabled.
It refuses existing probe resources, rule priority 1000, table 51820 contents,
or the target drop-in, and removes its rule, route, link, key, and drop-in before
restarting networkd again. It never changes the host's main-table default route.
CI prints all three TSV reports at the end and retains them with the captures.

Captures include healthy and fault-state command output, canonical nft JSON,
command exit codes/stderr, kernel/nft versions, the nftables service unit when
available, and `results.tsv`. Public WireGuard keys become `PUBKEY1` etc.; fresh
private keys stay in a temporary directory with mode 0700 and are deleted.
