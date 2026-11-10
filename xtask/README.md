# Uplink capture oracle

`cargo xtask classify capture.pcap --policy policy.toml [--limit 20]` prints a
JSON report. Exit status is 0 only when every capture record is allowed and the
positive-evidence requirements are met; policy, container and packet failures
return 1. Container/policy errors go to stderr.
The library entry points are `xtask::pcap::Policy::from_toml` and
`xtask::pcap::classify`; neither performs I/O.

Capture the entire uplink without a source-address filter. A capture filtered to
client/exit addresses cannot prove the allow-list property: leaked packets can
have host addresses after NAT, or carry client addresses inside ICMP quotations.
This checker is the pure oracle for the later namespace runner; it does not run
namespaces, tcpdump, or leak scenarios.

## Policy

`forbidden_addrs` is required and must be non-empty. Other lists and toggles
default to empty/false; `min_packets` defaults to 1 and cannot be zero. Unknown
keys are errors. A capture below `min_packets` fails with `EmptyCapture`.
The optional `expect` list requires at least one allowed packet for every listed
class (`wireguard`, `host_allow`, `arp`, `ndp`) or exact rule (`wireguard[0]`,
`host_allow[0]`); missing evidence fails with `ExpectedClassMissing`. Use this as
a positive control alongside the runner's own positive control.
Addresses must be literal IP addresses; prefixes accept CIDR or a single IP.
Rules use either direction, with the local endpoint always in `uplink_addrs`.
Omitted host ports mean any port, but TCP/UDP rules must specify at least one
port. Host prefixes wider than /24 (IPv4) or /48 (IPv6) require `allow_wide = true`.
Uplink addresses, WireGuard endpoints and host remote prefixes must not overlap
forbidden prefixes. Protocols are `tcp`, `udp`, `icmp` and `icmpv6`; ICMP rules
cannot specify ports. Their optional `types = [8]` list restricts accepted types.
Without it, ICMPv4 permits echo 0/8 and errors 3/4/5/11/12; ICMPv6 permits echo
128/129 and errors 1–4. Link control types still require `ndp`.

```toml
uplink_addrs = ["192.0.2.1", "2001:db8::1"]
forbidden_addrs = ["10.99.0.0/24", "10.2.0.2/32"]
canary_markers = ["canary.example", [222, 173, 190, 239, 42, 19, 87, 233, 16, 92, 188, 211]]
min_packets = 1
expect = ["wireguard[0]"]
arp = true
ndp = true

[[wireguard]]
gateway = "192.0.2.1:51820"
peer = "198.51.100.2:51820"

[[host_allow]]
proto = "tcp"
local_port = 22
remote_addr = "198.51.100.0/24"
# remote_port omitted: the harness's SSH source port can vary.

[[host_allow]]
proto = "udp"
local_port = 40000
remote_addr = "192.0.2.53"
remote_port = 53
```

Markers are UTF-8 strings or arrays of bytes 0–255, each at least 12 bytes.
Short markers can randomly match encrypted WireGuard or TLS ciphertext and make
large leak captures flaky; a 12-byte marker makes that probability negligible.
Use unpredictable markers for leak runs. They are matched exactly against the
whole IP datagram (including options and extensions), trailers, reassembled
payloads and ICMP quotations. Expanded DNS names join labels with dots; string
markers match those names ASCII case-insensitively, while byte-array markers
remain exact. Markers supplement the allow-list, which also rejects unmarked
unexpected traffic.

WireGuard rules require an uplink gateway IP and equal endpoint address
families. UDP endpoints must match exactly. The four-byte type/reserved field
must be `[1..4, 0, 0, 0]`; initiation, response and cookie messages require
148, 92 and 64 bytes respectively; transport data requires at least 32 bytes.
A matching endpoint pair with an invalid message cannot fall back to a host
rule. Configured WireGuard transports may use port 53. Bounded DNS name scanning
runs before the WireGuard decision; decoding failures are non-fatal for a packet
that otherwise matches WireGuard. Data packets have no 16-byte length alignment
requirement because Linux may cap padding at the MTU.

The `wireguard_error[i]` exception admits ICMPv4 errors 3/11/12 and ICMPv6
errors 1–4 only for an exact incoming WireGuard tuple quoted by its uplink
gateway to the listed peer. Quoted IP and UDP lengths must agree; IPv4 options,
IPv6 extension headers, fragments and trailers are excluded. A quotation must
be complete or end exactly at 548 bytes (IPv4) or 1232 bytes (IPv6). Available
message bytes must satisfy the same type, reserved-byte and length rules as
positive WireGuard traffic. A complete empty UDP datagram is also permitted;
a header-only prefix of a longer datagram is rejected. These framing checks
apply after matching the tuple; other ICMP errors retain their host rules.

Content inside allowed WireGuard/TLS flows is opaque: it is judged only by
endpoints and shape, with plaintext canary detection as an additional check.
A type-4 frame can carry arbitrary bytes after its framing, including plaintext
or an embedded client header. L3/L4 therefore establish framing and address
containment with opaque payloads, not payload confidentiality. Keep host rules
narrow; an allowed SSH/TLS or UDP flow can carry tunneled traffic that endpoint
and shape checks cannot distinguish.

ARP permits Ethernet/IPv4 requests and replies only when sender or target is an
uplink address. The `ndp` toggle permits router solicitation/advertisement,
neighbor solicitation/advertisement and MLDv1/v2 reports from link-local or the
uplink's own addresses. NS also permits the unspecified source for duplicate
address detection; NS/NA targeting an uplink address remain permitted inbound.
RS/RA and MLD reports require multicast destinations. ND/RS/RA require code 0,
hop limit 255 and valid option lengths. Redirects are not permitted by `ndp`.
Forbidden fields override these permissions, including ND targets, redirect
target/destination, RA prefixes, route and DNS-server options, and MLD group/source
addresses.

Forbidden outer source/destination addresses always override allow rules and
markers. IPv6 v4-mapped, v4-compatible, NAT64 `64:ff9b::/96` and 6to4 addresses
also check their embedded IPv4 address against forbidden IPv4 prefixes.
ICMPv4 errors 3/4/5/11/12 and ICMPv6 errors 1–4 inspect quotations recursively to
depth 3, including source/destination, options/extensions, payload and available
DNS names. ICMPv4 redirect gateways are also checked. Quotes may legally omit
the original packet's tail; a cut quoted IP/extension header still fails.
Quotations exceeding the depth limit fail closed.

## Capture and report semantics

The small hand-written classic-pcap reader avoids adding a parser dependency or
licence exception. It accepts microsecond/nanosecond timestamps in either byte
order, Ethernet (including stacked 802.1Q/802.1ad tags), SLL, SLL2 and raw IP
LINKTYPE 101. Pcapng is rejected. Invalid framing, impossible capture lengths and
incomplete container records are errors; unsupported link layers are packet
violations. Any snaplen-cut record fails, including a cut payload whose headers
are intact. Checksums are not validated because captures can precede checksum
offload. IPv6 jumbograms and unsupported extension/transport protocols have no
allow rule and fail closed.

IPv4 options and IPv6 hop-by-hop, routing, fragment and destination option
headers are traversed and their raw bytes scanned. Defined IPv4 RR/LSRR/SSRR and
timestamp address lists, IPv6 routing type 0/2/4 segment lists and Home Address
options are checked for forbidden addresses. Unsupported routing formats fail
closed. Authentication header bytes are also retained and scanned. Reassembly
keys are `(source, destination, ID, protocol)`.
Nonterminal fragments require eight-byte alignment. Duplicate/overlapping
ranges, inconsistent lengths and oversized sets fail; incomplete sets fail at
EOF. Complete groups are classified as datagrams and their verdict is assigned
to every contributing record. IDs can be reused after completion. There is no
wall-clock expiry: unresolved sets remain until EOF. Reassembly storage grows
with the capture, with at most 65,535 payload bytes per valid pending datagram.

Bytes after the declared IP length fail with `TrailingData`. Ethernet permits
only padding up to the 60-byte minimum frame (64 with a declared four-byte FCS);
padding is still scanned for markers. Raw IP, SLL and SLL2 permit no trailers.

DNS decodes questions, answer owner names and common name-bearing answer RDATA,
with bounded compression-pointer traversal. TCP DNS requires complete framed
messages within the captured TCP segment. TCP stream reassembly is outside this
checker: partial frames fail closed. ICMP quotations inspect all complete DNS
names available before a short tail.

The report contains one `Allowed(rule)` or `Violation(reason)` per record,
counts by allowed rule/violation kind, and the first `--limit` packet violations in
capture order. Reassembled fragments retain their original indexes/timestamps.
Timestamps use integer seconds/nanoseconds. Summaries contain addresses and
protocols; each sampled violation includes at most the first 64 captured bytes
as hex. Counts and all packet verdicts remain complete when the sample is capped.
Capture-wide `EmptyCapture`/`ExpectedClassMissing` reasons appear in
`capture_failures` (omitted when empty), without inventing packet records.
`violation_count` includes both failed records and capture-wide failures; the
packet sample limit does not suppress capture-wide failures.

## Verification

`cargo test -p xtask` builds synthetic captures in code: all WireGuard message
types/directions, host SSH, ARP, ND, client/exit sources, all required ICMP error
types and quotations, DNS compression and loops, fragment reassembly/overlap/
incompleteness, IPv4/TCP options, IPv6 extension headers, VLAN/SLL/SLL2, truncated
headers/captures, byte order/timestamp resolution, strict policy parsing, CLI
JSON/exit codes, bounded property tests and a golden mixed JSON report.
`UPDATE_GOLDEN=1 cargo test -p xtask golden_report` regenerates the golden.

# Reference namespace leak lab

On a disposable Linux VM, install `wireguard-tools nftables iproute2 tcpdump
dnsmasq-base util-linux iputils-ping conntrack slirp4netns`, build `cargo build -p xtask --release --locked`, then:

```console
sudo timeout 1200 target/release/xtask leaktest --artifacts lab-out --capture-fixtures lab-out/fixtures
```

`cargo xtask leaktest` is the same runner in a development build. It requires
root and refuses occupied namespace names, resolver directories, staging links,
or its randomly named private directory under `/run`. It creates no addresses,
routes, firewall rules or sysctl changes in the invoking host's network
namespace. Staging veths briefly exist there before moving; run on a disposable
host without a network manager that configures unknown links. The M1 shell lab
was retired in M2. The reference builder now invokes `scupper boot`.
`conntrack` is required for an existing namespace rebuild: after loading and
verifying the rules, boot flushes conntrack before enabling forwarding. A missing
binary or failed flush stops boot with forwarding off.

The allocation lives in `src/lab/addresses.rs` (WAN address first):

| Link / network | WAN | Neighbour |
| --- | --- | --- |
| wan–gwhost, 198.51.100.0/30 | 198.51.100.1 | 198.51.100.2 |
| wan–client, 192.0.2.0/30 | 192.0.2.1 | 192.0.2.2 |
| wan–provA, 203.0.113.0/30 | 203.0.113.1 | 203.0.113.2 |
| wan–internet, 192.0.2.4/30 | 192.0.2.5 | 192.0.2.6 |
| temporary wan–scupper bridge, 198.51.100.4/30 | 198.51.100.5 | 198.51.100.6 |
| internet IPv6, 2001:db8:4::/64 | 2001:db8:4::5 | 2001:db8:4::6 |
| client tunnel, 10.99.0.0/24 | gateway wg0: 10.99.0.1 | client wg0: 10.99.0.2 |
| provider tunnel, 10.2.0.0/24 | provider wgp: 10.2.0.1 | ex-ch1: 10.2.0.2 |
| client IPv6 test, fd00:99::/64 | — | client wg0: fd00:99::2 |
| client link-local test | — | client wg0: fe80::2 |
| IPv6 exit control, 2001:db8:2::/64 | provider wgp: 2001:db8:2::1 | ex-ch1: 2001:db8:2::2 |
| IPv6 provider WAN control, 2001:db8:3::/64 | 2001:db8:3::1 | provA eth0: 2001:db8:3::2 |
| IPv6 bridge, 2001:db8:5::/64 | 2001:db8:5::5 | scupper: 2001:db8:5::6 |

The client ULA is the explicit negative-test exception to documentation and
scupper-internal ranges. The validated `lab/site-lab.toml` omits health route-
probe fields because validation requires public destinations there; those
defaults are never contacted. The requested `route get 1.1.1.1` fixture is a
kernel lookup, with no packet sent.

All gwhost commands use `nsenter --net=/run/netns/gwhost -- ...`. WireGuard wg0
(51820) and ex-ch1 (51821) are born there and then moved to scupper, preserving
socket ownership. An additional temporary `scupper-verify` namespace loads the
rendered rules independently; canonical JSON equality gates forwarding. The
builder uses `render_netns`, `desired_routes` and `desired_sysctls`, reapplies
hardening after enabling forwarding, and checks all sysctls by read-back. It
applies forwarding=0 and hardening before moving the down tunnel links, loads
and verifies the ruleset, then assigns addresses, brings links up, installs
routes and enables forwarding. All namespaces set IPv4 forwarding explicitly;
gwhost uses 1, client/internet use 0, and wan/provA use 1. IPv6 forwarding is
explicit too and enabled on wan/provA only during the IPv6 path controls.
Private keys exist only in a randomly named mode-0700 `/run` directory outside
the artifact tree, in mode-0600 files, removed during cleanup. Artifact paths
that would contain this directory are refused. No command requests WireGuard
private-key output, `showconf` or `dump`.

Each service check sends four independent markers (128 random bits apiece): TCP
and UDP by IP and through `<marker>.lab.test`. The probe sends explicit UDP
A/AAAA queries to 10.2.0.1, without libc/NSS or the host resolver. dnsmasq has
no upstream and answers only the lab domain. TCP reads a line and echoes it; UDP
echoes the payload. The runner checks acknowledgments and the sink's JSON-lines
receipts, requiring exactly one receipt per marker from provA's NAT address.
Probe logs record the resolved destination and structured outcome after each
attempt. Forward drops require a timeout/no reply, and scupper output drops
require EPERM. Bind, routing, resolution, acknowledgment and launcher errors
fail the case. TCP and UDP use unique source ports; restore flushes scupper
conntrack before the after-check, preventing earlier permissive flows from
surviving.

The cases run in this order, with provider service checks before and after:

| Case | Assertion |
| --- | --- |
| `baseline` | Service works; full uplink pcap is allowed WireGuard/control traffic. |
| `client-v6-dropped` | Unfiltered wg0 capture proves ULA TCP/UDP and link-local UDP arrive. nft traces prove antispoof drops both sources; unfiltered ex-ch1/provA captures see no v6. Repeated with routes, WireGuard ACLs and WAN forwarding open, then accept-all must deliver ULA markers through ex-ch1 and provA. Each capture has in-phase IPv4 service liveness. |
| `bridged-real-ruleset` | IPv4 /32 and IPv6 /128 route lookups must select lab-bridge. In-case ARP and IPv4/IPv6 ping prove capture liveness; forwarded and local canaries must be contained. The temporary IPv6 client set entry allows testing the forward chain beyond antispoof. |
| `positive-control-permissive` | Accept-all retains exit NAT for DNS and must deliver IPv4/IPv6 bridge markers with client source addresses. Its live capture must flag leaks and contain both scupper-output UDP markers. |
| `positive-control-uplink` | Exactly three injected packets must violate: one spoofed forbidden-source packet (`ForbiddenAddress`) and DNS plus UDP-payload packets from gwhost to wan (`CanaryMarker`). Tuple, full UDP content, reason and multiplicity must match; any other violation fails. |

Every uplink capture is unfiltered, with `tcpdump -U -s 0 -w` on wan's gwhost
veth. Its generated policy requires four packets per case marker and both
WireGuard endpoint pairs, including deliberate controls. Only the oracle decides
uplink verdicts. Every auxiliary capture is unfiltered. Bridge policies require
the six packets generated by two ping exchanges and ARP resolution, plus the ARP
and both ICMP classes. IPv6 capture evidence separately requires IPv4 service
packets and its expected ingress/egress canaries. Empty captures always fail.
The marker-only uplink injections exercise marker classification without
forbidden addresses masking the result. Wan silently drops just those two
injected tuples after the capture point to prevent ICMP responses adding
unintended control violations. Capture readiness/process liveness are checked,
and shutdown must report zero kernel/interface drops.

Commands use argv vectors without a shell. Foreground commands have a 15-second
GNU timeout (plus a two-second kill escalation), background processes have a
1050-second timeout, setup has a 180-second deadline, each case has 140 seconds,
and the whole run has 1000 seconds plus bounded cleanup. Signal handlers for
INT/TERM/HUP request cancellation; the ownership guard stops process groups and
removes namespaces, staging veths, temporary keys and owned netns directories.
Resources are registered only after successful exclusive creation. Failed
creates never grant ownership; moved/deleted resources are unregistered so
cleanup cannot claim later replacements at their old names. Bridge captures stop
before their veth disappears; deletion tolerates the asynchronous disappearance
of a peer. Cleanup failures fail the run and are recorded in `cleanup.txt`.

Artifacts include pcaps, generated policies and oracle JSON reports, sink and
probe logs, command argv/stderr diagnostics, `results.tsv`, `results.json`, and
optional healthy observation fixtures. Fixture output replaces public keys with
`PUBKEY1` etc. The runner attempts all cases, restores between them and fails at
the end if any failed; `failure.txt` records the reasons. The `got` column
records observed packet/violation and receipt counts with the markers actually
received. No fixtures are committed by this task.

Normal, unprivileged tests cover allocation, configuration validation, generated
policies and positive evidence, argv wrapping for every external program,
process deadlines, successful-create/idempotent cleanup, sink log parsing,
public-key redaction and TSV/JSON results. Regressions cover exact uplink
injections, missing or extra violations, empty auxiliary captures, v6 on ex-ch1,
antispoof trace correlation, explicit DNS decoding and local probe errors
(including an occupied UDP source port through the CLI). The actual namespace
suite runs in CI on both Ubuntu 24.04 and 22.04; it is not part of `cargo test`.

L17-V14 waits for the held namespace inode to reappear, then requires exactly
one mount on `/run/netns/scupper`. Restore leaves a single mount of the held
inode alone, detaches a hijacked mount with `MNT_DETACH | UMOUNT_NOFOLLOW` before binding, and
creates the mount-point file only when missing. Unexpected mount counts or a
wrong inode after binding report an escalation. With scupperd stopped, a single
`ip netns delete scupper` must detach that mount and remove the name. With the
daemon running, deletion is temporary: the next audit restores the held inode.
Restore requires an already shared parent mount and never rewrites propagation.
Its directory flock uses non-blocking retries, capped at 100 ms and the tick
deadline. A descriptor held through a deleted named mount is replaced as a bind
source by a fresh `/proc/thread-self/ns/net` descriptor from a short-lived thread
that enters the held network namespace. This avoids inheriting its old mount's `MNT_UMOUNT` flag
on older kernels; the held namespace identity remains unchanged.

The check wrapper uses `unshare --mount --propagation unchanged`. It makes only
mounted overlay ancestors (`/`, `/etc`, `/var`, `/var/lib`) private, without
recursion, before binding the lab's `/etc` and `/var/lib`. The two replacement
mounts are also made private without recursion. It leaves all nsfs
mounts and `/run/netns` propagation intact.

The lab saves `/run/netns` mountinfo lines immediately after L17 restore,
after its `ip netns exec` and fresh check, before
each daemon case cleanup, and before final teardown (`*-host.mountinfo`,
`*-daemon.mountinfo`, and `*-mounts.json`). Daemon snapshots read its procfs
mountinfo directly and record whether its mount namespace differs from the
host. Parent mount propagation fields and duplicate path entries are preserved.
A stack or loss of shared nsfs peers fails the daemon case that left it. Shared
peer shape is checked before stopping, before cleanup and after case cleanup,
against the untouched `wan` namespace. Final cleanup reports stacked names
in `cleanup.txt`, lazily unmounts every layer with a bounded loop, then deletes
the name; ordinary single mounts are deleted directly and checked absent.

L13 starts the foreign-side control capture and waits for tcpdump's listening
acknowledgement before sending three distinct UDP control markers on fresh
tuples, spaced by probe completion and 250 ms. At least one exact UDP payload
must appear. The measurement uses a separate continuous marker and still
requires a pre-containment packet, redirect removal and link-down within eight
seconds, and no matching packet later than containment plus 250 ms (or eight
seconds from resume). Packet-loss checks and the uplink leak oracle still apply.

Boot rebuilds first close forwarding, disable every foreign or wrong-kind link
using its raw kernel name, and clear clsact/ingress and XDP on all namespace links.
Foreign links remain down and boot fails for operator attention. Other RPDB or
main-table route drift still requires the operator or planner to remove it.
Pin and Prefer naming an unconfigured exit both fail closed; no fallback exit is
chosen. Missing state retains Disconnected intent and forwarding=0 because the
quarantine latch is unknown. Failed attempts holding the writer lock replace
boot.json with their failure report (publication failures are reported too).

L9 tests fresh crash prefixes and L9b rebuilds a live namespace with hardening
drift, killing at steps 1–6. Whenever wg0 is configured, the client session is
reset and a fresh gateway handshake is required before canaries. The oracle
requires increasing wg0 receive bytes and the UDP marker in a wg0 capture, plus
a clean uplink capture; steps 6–7 also require provider transport as a positive
control. Host leftovers are checked down and peerless before retry. The expected
ruleset is independently loaded from `render_netns` output in scupper-verify.
