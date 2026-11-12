# scupper design (Release 1, with R2+ extension points)

Status: accepted, 2026-11-08. This is the authoritative design for the Rust
implementation. Each significant decision has an ADR in [`adr/`](adr/), which
gives the context and the alternatives considered. Background on v1 is in
`BINARY-FUNCTIONALITY.md`, `CODE-WALKTHROUGH.md` and `CONCEPTS.md`.

Addresses: `10.99.0.0/24`, `fd00:99::/64` (client tunnel) and `10.2.0.0/24`
(provider tunnel side) are private. Every public address in this document is
from a documentation range (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, `2001:db8::/32`).

Contents

1. Overview, scope, threat model
2. Invariants and safety arguments
3. Topology and state ownership
4. Process model, workspace, dependencies
5. Rulesets, routes, sysctls
6. Exit health and the failover state machine
7. Watch and repair loop
8. Configuration
9. DNS forwarder
10. Control plane and API authentication
11. CLI
12. Health model, verdicts, exit codes
13. Events, metrics, alerts, heartbeat
14. Mac client
15. Install, boot, upgrades, migration, rebuild
16. R2+ extension points (including high availability)
17. Testing
18. Failure modes
19. Milestones
20. Verification tasks
21. ADR index

---

## 1. Overview, scope, threat model

scupper is a **fail-closed VPN gateway**. Clients (in R1, one Mac) join the
gateway over WireGuard. The gateway forwards their traffic into one of
several WireGuard VPN exits (in R1, one provider: Proton), or not at all.

```
Mac ──WireGuard──▶ gateway host ──WireGuard──▶ VPN provider exit ──▶ internet
10.99.0.2          10.99.0.1 (client side)      10.2.0.2 (exit side)
                   eth0 198.51.100.7 (uplink, carries only encrypted UDP for clients)
```

The one big structural decision (ADR 0001): **from milestone 2 the plaintext
data path lives in a dedicated network namespace `scupper` that contains no
uplink.** Its only interfaces are `lo`, the client tunnel `wg0` and the exit
tunnels `ex-*`. WireGuard interfaces are created in the host namespace and
then moved, so their encrypted UDP sockets stay on the host uplink while the
decrypted packets exist only inside the namespace. The kill switch is the
topology itself; nftables inside the namespace is a second, independent
layer. Milestone 1 is a pure Rust port of v1 in the v1 (host) layout, built and
tested in a lab only, to prove the port before the layout changes; the first
deployment is milestone 2 on a freshly built host.

### Threat model

| In scope | Out of scope |
|---|---|
| Hostile or buggy clients (spoofing, scanning, client-to-client) | A compromised kernel |
| Failed, flapping or misbehaving VPN exits; provider-side traffic toward the gateway | A hostile administrator with root or `CAP_NET_ADMIN` on the gateway (can remove any software firewall) |
| Crashes, hangs and partial failures of scupper's own processes | Traffic analysis of the encrypted tunnels |
| Other system daemons changing shared state (networkd, unattended-upgrades, `nftables.service`, ufw) | Compromise of the VPN provider |
| Partial or interrupted config changes, reboots, disk full, clock steps | Apple or macOS changing pf semantics without notice (tested, not prevented) |
| Browser-based attacks against the gateway API from the Mac (CSRF, DNS rebinding) | |
| Hostile local networks for the Mac (spoofed routers, captive portals) | |

**Dedicated appliance assumption (R1).** The gateway host runs no container
runtime, no other router and no other VPN. scupper does not depend on host
networking state, but the leak suite and support statement only cover this
configuration.

**Gateway-own traffic.** SSH, package updates, NTP, the gateway's own DNS,
WireGuard transport (encrypted UDP), alert delivery and the external
heartbeat legitimately use the host uplink, as in v1. None of it carries
client plaintext, and no host service may proxy for clients.

### Requirement statements refined by this design

| Requirement | Statement as designed |
|---|---|
| Boot protection ("fail closed at boot before any process starts") | **No client-capable path exists until protection is verified.** A process has to install the rules; before `scupper boot` runs there is no namespace, so no client path at all. Every prefix of the boot procedure is closed (§15). |
| DNS forcing (§3 of the requirements) | **Plain DNS is forced, DoT is blocked, DoH is not controllable.** All client UDP/TCP port 53 to any destination is redirected to the gateway forwarder; TCP and UDP 853 are rejected so clients fall back to port 53 at once; DNS over HTTPS on 443 is indistinguishable from HTTPS and still leaves only through the VPN (I1). |
| Mac protection | pf protection applies while pf is enabled and evaluates the scupper anchor, from the moment `join` has installed and verified it. Events that remove the anchor or its evaluation path (macOS reloading pf, another tool disabling pf) are detected within one 5 s check and repaired; the length of any such gap and the macOS operations that cause one are measured (V-05), not assumed to be zero. Between boot and the helper restoring a persisted join, and between a network change and an auto-join, the Mac is not protected. R1 accepts this guarantee; R2 re-evaluates a Network Extension backend from the V-05 measurements (§19, D-2). |
| Multi-gateway in R1 | Data model and config only: several gateways and a shared client-facing identity are expressible; R1 validation accepts exactly one active gateway (§16). |

---

## 2. Invariants and safety arguments

| ID | Invariant |
|---|---|
| I1 | **VPN or nothing.** Client traffic leaves via a configured VPN exit or not at all. No bypass on the gateway: no split tunnel, no override. (A future Mac captive-portal helper is the only exception, explicit, short-lived and Mac-side.) |
| I2 | **Kernel-enforced.** The kill switch is kernel state (topology, routes, nftables). A scupper process dying, hanging or crashing never opens a path. No client-capable path exists until protection is verified. |
| I3 | **Truthful health.** `check`, status, metrics and the heartbeat report OK only for states actually verified. Every piece of state shared with another daemon has an owner or a watcher. |
| I4 | **Repairs only tighten or restore.** Automatic actions never loosen policy. Loosening happens only through a committed config version. |
| I5 | **Privacy.** No destination, domain or DNS-query logging by default; no type in events or metrics can carry one. |
| I6 | **Secrets stay local.** Provider and gateway private keys never leave root-only files on the machine that uses them: never in config, API, logs, bundles or sync traffic. (R2 HA option (a) is a documented, deliberate exception for one key, §16.) |
| I7 | **Isolation by default.** Clients cannot reach each other or gateway services other than DNS, the API and rate-limited ping. Exits cannot open flows toward clients or the gateway. |

### Topology lemma T (R1 layout, M2 onward)

> In netns `scupper` every non-loopback interface is a WireGuard interface
> listed in the applied config. A packet leaving such an interface is
> encrypted to a peer whose AllowedIPs cover its destination. Client peers
> have host prefixes only (validation rejects default routes); exit peers
> are VPN servers. **So any packet leaving the namespace goes to a client or
> into a VPN tunnel. Nothing else can carry it out.**

T depends only on (a) the set of links in the namespace and (b) peer
AllowedIPs. Both are owned by scupper, invisible to host daemons, and
verified by `check` (stage 1). Foreign links are detected and set down.

T holds only while the link set is as configured. A foreign link added by
root (out of scope as an attacker, in scope as a mistake) can carry packets
out, including through a tc `mirred` action that acts below nftables and
independently of forwarding, until it is detected. Foreign links and tc
hooks are therefore acted on in the first tick that sees them (no
debounce): link down first, then hook removal, then verification (§7).

### Safety argument per invariant

Phases: **S** steady state, **F** failover, **A** apply, **B** boot,
**D** daemon (scupperd or edge) dead or hung, **P** partial failure.

**I1 VPN or nothing**
- S: T rules out the uplink. `forward` accepts only client→exit and the
  directional exit→client return; client→client is dropped.
- F: one `ip route replace` per family, each atomic. Before: old exit; after:
  new exit or `unreachable`. The route writer only accepts
  `RouteTarget::{Exit(ExitIfname), Unreachable}`; the ruleset is not touched.
- A: `nft -f` (flush + full table) is one kernel transaction. Even with no
  ruleset at all, T holds; the effect is loss of NAT, isolation and DNS
  forcing (I7 gap below), never an uplink path. I1 does not rely on the
  provider dropping un-NATed packets (unverified, V-08).
- B: no namespace exists before `scupper boot`. Boot order: netns →
  forwarding 0 → hardening sysctls → ruleset → verify → links → routes →
  forwarding 1 unless latched or Disconnected. A crash leaves a prefix;
  every prefix is closed.
- D: the data path is kernel objects only. With scupperd dead, failover stops;
  if the active exit dies, packets wait inside its WireGuard interface (no
  handshake, nothing sent). With edge dead, DNS fails (closed).
- P: a link created but not yet moved is down in the host and has no peer; a
  moved but unconfigured exit has no peer and sends nothing. A failed
  config apply re-plans toward the previous version (§8).

**I2 Kernel-enforced**
- S: the path and its absence are links, routes and nft rules. No userspace
  process forwards client packets; the DNS forwarder only answers queries.
- F/A: route replace and `nft -f` are kernel-atomic; no process holds a gate.
- B: before `scupper boot` there is no namespace, hence no path. Forwarding
  in the namespace is 1 only after the ruleset is verified.
- D: watchdogs restart processes; no unit has a stop action that tears
  protection down, and no cleanup handler loosens anything.
- P: each repair is a `Restore` or `Tighten` variant; a partial repair is a
  prefix of a safe plan (property-tested).

**I3 Truthful health**
- S: `check` returns 0 only after observing, in order: topology T, exact
  ruleset, admin intent, fresh active handshake, forwarding, the kernel's
  route answer for every client address (`route get … iif wg0`), an exit
  probe through the real route, a DNS answer, daemon liveness.
- F: during failover `check` returns 4 for a bounded grace window, then 3 if
  the switch is stuck (§12).
- A: `check` compares against the ruleset of the *applied* version; a pending
  version is reported as such.
- B: before boot completes, stage 1 fails (`NetnsMissing` → 2) or stage 4
  fails (forwarding 0 → 3); never 0.
- D: `check` runs its probes itself and does not need scupperd; run locally
  (or over SSH) a dead daemon gives 5, never 0. Via the tunnel API a dead
  scupperd gives `503 supervisor_unavailable` and the CLI falls back to SSH,
  which runs the local check. Edge never serves a cached verdict older than
  30 s as current (§13). The heartbeat stops when scupperd stops.
- P: an observation that fails is exit code 1, never a "safe" code. A known
  violation wins over an observation error.
- Shared state: in the netns layout the client path shares with other
  daemons the host's routing of encrypted UDP, the host input filter (ufw, a
  cloud firewall) and the UDP listen port of `wg0`. Exit-side transport is
  watched through exit handshake age; the client side through stage 4
  (`wg0` public key and listen port as configured, a host UDP socket bound
  to that port) and client handshake ages (warning only, §12). These affect
  availability only, never containment. In the M1 (v1) layout, policy rule
  1000 and table 51820 are shared with networkd (owned via the networkd
  drop-in, watched by the route probe), and **the host ruleset is shared
  with `nftables.service`**, whose stock unit flushes the ruleset on stop.
  In that layout the forward `policy drop` is the only barrier between `wg0`
  and the uplink while the exit tunnel is down, rule 1000 is missing or the
  gateway is disconnected. M1 is therefore never deployed to a production
  gateway: it runs only in a lab namespace or VM (decision D-1 in §19).

**I4 Repairs only tighten or restore**
- All automatic actions are variants of `enum Repair`, each statically
  classified `Restore` (bring kernel state back to the rendered config) or
  `Tighten` (forwarding 0, link down, delete foreign rule/tc, flush
  conntrack, route unreachable). No variant adds an accept, routes to a
  non-exit, or enables forwarding without a same-tick verified ruleset.
- F: the failover machine's output alphabet is {route to configured exit,
  unreachable, conntrack flush, exits down, events}. A logic bug can choose a
  bad VPN exit or close the path, never open one.
- When a repair budget is exhausted, the gateway ends closed (forwarding 0)
  for safety drift and alerts. That state is a **persisted quarantine
  latch** (ADR 0031): while it is set no repair, boot step or planner step
  may raise forwarding; only `scupper repair clear` or a verified full
  `scupper apply` clears it (property-tested).

**I5 Privacy**
- The forwarder has no code path that writes query names. Event and metric
  types have no destination, domain or payload fields (serialization test
  over every variant). nft counters are per chain or interface. Conntrack is
  never dumped to logs. Heartbeat and alert payloads are typed operational
  fields only.

**I6 Secrets stay local**
- Config holds `*_ref` names; keys are files `/etc/scupper/secrets/<kind>/<ref>`,
  root 0600, opened without following symlinks (§8). `wg set … private-key
  /dev/stdin` passes keys via stdin (`/dev/stdin`), never argv or env. The exec layer has an
  explicit allow-list of `wg` invocations (`show <if>` with
  `latest-handshakes`, `endpoints`, `allowed-ips`, `transfer`, `peers`,
  `listen-port`, `public-key`, `persistent-keepalive`; `set` with key files
  by path) and refuses everything else, including `showconf`, `show … dump`,
  `show … private-key` and `show … preshared-keys`. Key bytes in memory are
  `Zeroizing` and have no `Debug` or `Serialize`. Client keys are generated
  on the client. Config bundles cannot contain secrets (schema has no
  key-typed field; export refuses `secrets/`).

**I7 Isolation**
- S: `input` policy drop admits only DNS, API and rate-limited ping from
  client tunnels; no client→client accept; exits only get established
  replies.
- F: ruleset unchanged by failover.
- A: atomic.
- B: forwarding stays 0 until the ruleset is verified.
- D: kernel state; unaffected.
- **Known gap:** if someone with root flushes the namespace ruleset at
  runtime, isolation is lost until the next tick (≤ 2 s plus exec time)
  sets forwarding 0. There is never an uplink leak in that window (T).

---

## 3. Topology and state ownership

### Namespace layout (M2 onward)

```
 host (init) netns                                netns "scupper"
┌───────────────────────────────────┐            ┌───────────────────────────────────────┐
│ eth0  198.51.100.7 (uplink)       │            │ lo                                    │
│ sshd  (break-glass, public addr)  │            │ wg0     10.99.0.1/24  fd00:99::1/64   │◀── Mac
│ UDP sockets of wg0 and ex-*       │◀═encrypted═│ ex-ch1  10.2.0.2/32 2001:db8:2::2/128 │──▶ exit A
│   (WireGuard birthplace)          │            │ ex-nl1  10.2.0.2/32 (v4 only)         │──▶ exit B
│ scupperd (root): reconcile,       │            │ scupper-edge (unprivileged):          │
│   health, failover, alerts and    │◀─unix sock─│   DNS forwarder :53, API :7380,       │
│   heartbeat via eth0, event log   │            │   /metrics                            │
│ probe children (enter the netns)  │            │                                       │
└───────────────────────────────────┘            └───────────────────────────────────────┘
```

Routing in the namespace (ADR 0016): **no policy routing**. The main table
holds, per family, exactly one default route: `dev <active exit>` or
`unreachable`. Kernel connected and local routes are the only others. The
RPDB stays at kernel defaults (0, 32766, 32767).

### Ownership

Principle (ADR 0017): **scupper owns the namespace completely and owns nothing
in the host namespace except its own files and units.** Inside the namespace
there is no other legitimate writer, so drift is always an incident. Outside,
scupper only reads.

| State | Owner | Drift handling |
|---|---|---|
| netns `scupper` (`/run/netns/scupper`), identified by **inode**, fd held by scupperd | `scupper boot` | name gone, inode alive: re-mount from the held fd; inode gone: stop edge, rebuild (§7) |
| WireGuard links `wg0`, `ex-*` | scupper (create in host → move → configure → up) | missing: recreate; foreign link in netns: set down, never delete |
| Addresses on those links | scupper | restore |
| Peers: public key, AllowedIPs, keepalive | scupper | restore. Endpoints are learned by WireGuard (client roaming, provider NAT) and never compared as drift; an exit's endpoint is set from config at creation and when its handshake is stale |
| Netns routes (v4, v6 main table) | only the failover machine | the table must be exactly the default route plus kernel connected/local routes: restore the default; delete anything else (tighten) |
| Netns policy rules | nobody (kernel defaults) | extra rule: delete (tighten) |
| Netns nftables ruleset (whole ruleset) | scupper: `flush ruleset` + table, one transaction | exact compare every tick; close, reload |
| Netns sysctls (forwarding, hardening) | scupper | restore; re-apply hardening after every forwarding toggle |
| Netns conntrack | kernel; scupper flushes on failover and ruleset restore | none |
| tc qdiscs/filters on netns links | nobody | permitted baseline: the kernel default root qdisc (`noqueue` on WireGuard links) and no filters; any `ingress`/`clsact` qdisc, other root qdisc or filter is a violation: delete (tighten), at once |
| WireGuard UDP sockets (host); the host input filter in front of them | kernel, created by scupper; filter: operator | exits: handshake age; `wg0`: listen port bound in the host, public key as configured, client handshake ages (warnings) |
| Host routes, rules, nft, sysctls, resolver, networkd, sshd | operator / distribution | **not touched, not needed** (one exception: optional `/etc/sysctl.d/90-scupper.conf` with host `ip_forward=0`, written by `install` on a dedicated host; `check` warns on drift, never repairs) |
| `/etc/scupper/`, `/var/lib/scupper/` | scupper | key file mode checked at load |
| Units `scupper-net`, `scupperd`, `scupper-edge` | `scupper install` | `install --check` |

**Host nftables:** scupper never runs `flush ruleset` in the host namespace
and installs no host table in the netns layout. The single exception is M1,
which keeps v1's behaviour of owning `/etc/nftables.conf` (§5.1) and
therefore shares the host ruleset with `nftables.service` (below).

### M1 (v1 layout) ownership

As v1, plus: the networkd drop-in `/etc/systemd/networkd.conf.d/10-scupper.conf`
sets `ManageForeignRoutingPolicyRules=no` and, as a precaution,
`ManageForeignRoutes=no` (whether networkd touches routes in table 51820 on
the unmanaged `proton0` is untested, V-24; a new drop-in takes effect at the
next networkd restart). Rule 1000 and table 51820 are watched only by
`check`'s route probe; no repair code is written for the v1 layout.

**Shared with `nftables.service`.** On Debian and Ubuntu the stock unit runs
`nft flush ruleset` on stop (V-23), and a failed start (for example a broken
`/etc/nftables.conf`) leaves no ruleset. `wg-quick@wg0` does not depend on
that unit, and host `ip_forward=1` comes from sysctl. In the v1 layout this
is a fail-open path whenever the exit tunnel is down, rule 1000 is missing
or the gateway is disconnected: client packets follow the main table to the
uplink, un-NATed. `apply` therefore validates with `nft -c -f` before the
rename (§5.1), and `check` compares the whole host ruleset. The further M1
Because of this, M1 is a lab milestone only (§19, D-1): it is built and
tested in an `unshare -rn` lab and a VM and never deployed to a gateway that
carries real traffic. The first deployment is M2, on a freshly built host
with the namespace layout, which does not depend on `nftables.service`.

---

## 4. Process model, workspace, dependencies

### Processes (ADR 0004)

| Process | Where | Privilege | Role | In data path |
|---|---|---|---|---|
| `scupper-net.service` (oneshot, `scupper boot`) | host → builds netns | root | namespace, sysctls, ruleset, links, routes at boot | no (exits) |
| `scupperd` | host netns | root, no network listener | synchronous reconcile loop, health, failover, repairs, event log, alerts and heartbeat via eth0, control socket; heartbeat fresh checks use a concurrent read-only worker (§13, ADR 0004 exception) | no |
| `scupper probe …` children | started by scupperd, enter the netns | root until sockets exist, then `scupper-probe` | path, exit-IP and DNS probes | no |
| `scupper deliver …` children | started by scupperd in host netns | `scupper-alert` from exec (`Command::uid`) | one alert/heartbeat HTTPS request | no |
| `scupper-edge` | **whole process in the netns** (`NetworkNamespacePath=`) | user `scupper-edge`, `CAP_NET_BIND_SERVICE` only | DNS forwarder, tunnel API, `/metrics` | DNS only |
| `scupper` | anywhere | caller | CLI | no |
| `scupper mac helper` (LaunchDaemon `net.scupper.helper`) | Mac | root; root-owned binaries only (ADR 0030) | pf, wg-quick, persisted join intent; typed commands over a local socket; parses no HTTP | Mac side |
| `scupper mac agent` (LaunchAgent `net.scupper.agent`) | Mac | logged-in user | network fingerprint, join requests, gateway events, notifications, bundle copies, API token | no |

Rules:
- **No TLS or HTTP parsing as root.** Probe children create their sockets
  (setns into the netns via the held namespace fd, `SO_BINDTODEVICE` where
  needed) while single-threaded, then drop supplementary groups, gid and
  uid, verify with `getresuid`/`getresgid` and abort if any id is 0. Delivery
  children are started unprivileged. The Mac helper follows the same rule.
- **Edge sees a minimal filesystem.** Its unit replaces `/run` with an empty
  tmpfs and binds in only its own socket (§15), so the host resolver's
  Varlink and D-Bus endpoints (`/run/systemd/resolve/`, `/run/dbus/`) and any
  other host-side proxy socket are unreachable from the namespace process.
  Abstract Unix sockets are per network namespace and already separate. A
  negative test (L45) attempts host-mediated resolution from the installed
  edge sandbox. Edge and probe children never dump core (`LimitCORE=0`), so
  no DNS name reaches a core file (I5).
- **No `setns` in multi-threaded processes.** Edge is placed in the namespace
  by systemd before it starts; probe children `setns` before creating any
  thread.
- scupperd is **synchronous**: one reconciler thread owns all state and reads
  a channel of events (ticks, control requests, child completions). Worker
  threads only wait on children. Deterministic and fake-clock testable.
- Edge starts with a current-thread tokio runtime and `hyper`; a synchronous
  implementation is an allowed later simplification (no design change).
- Edge talks to scupperd over its own filesystem Unix socket
  `/run/scupper/edge.sock` (0660 `root:scupper-edge`; path sockets cross
  network namespaces, abstract sockets would not), which accepts only the
  edge operation set (§10). Local administrators use
  `/run/scupper/control.sock`.

### Cargo workspace

```
Cargo.toml          workspace; [workspace.lints]: forbid(unsafe_code), deny clippy::unwrap_used, expect_used
rust-toolchain.toml pinned
deny.toml
crates/
  scupper-core/     pure, no I/O, no clock, no tokio: config model + validation, renderers
                    (nft, pf, units), verdict + staging, failover machine, planner, parsers
  scupper-proto/    serde types for API, control socket and --json (schema = 1)
  scupper-sys/      Linux adapters: Exec with timeouts and allow-list, System impl, netns, probes
  scupper-mac/      pf, wg-quick, launchd, network fingerprint (exec only)
  scupperd/         bin: reconciler, events, alert/heartbeat scheduling, control socket
  scupper-edge/     bin: DNS forwarder, HTTP API, metrics
  scupper/          bin: CLI (clap), transports, human rendering; hidden boot/probe/deliver
xtask/              leak-test harness, golden update, reproducible release build
tests/golden/       v1 ruleset.golden + egress guard (ADR 0032), netns rulesets, pf anchors, units, --json
```

M1 is a single crate (`scupper`) at the repository root with `rules`,
`parse`, `verdict`, `system`, `cli` modules; the workspace split happens at
the start of M2.

### Dependencies

| Crate | Where | Why |
|---|---|---|
| `thiserror` | all | typed errors |
| `serde`, `toml`, `serde_json` | core, proto, CLI | config and JSON; `deny_unknown_fields` everywhere |
| `ipnet` | core | prefixes |
| `clap` (derive), `clap_complete`, `clap_mangen` | CLI | command tree, completions, man pages |
| `dialoguer`, `comfy-table`, `anstream` | CLI | prompts and pickers, TTY tables, TTY-aware colour (§11) |
| `rustix` | sys | `setns`, credential drop, sockopts, without first-party unsafe |
| `socket2` | sys, edge | `bind_device`, `IP_FREEBIND` |
| `ureq` (rustls) | CLI, delivery child | sync HTTPS for API client, sinks, heartbeat |
| `tokio` (rt, net, time), `hyper`, `hyper-util` | edge only | concurrent DNS and HTTP |
| `hickory-proto` | edge, probe | DNS message parsing only |
| `sha2`, `zeroize` | core, sys | hashes; key bytes wiped |
| `sd-notify` | scupperd, edge | watchdog |
| `tracing`, `tracing-subscriber` | bins | stderr logs to journald |
| `proptest`, `pcap-file` | dev | properties; capture parsing |

Rejected for R1: netlink crates (ADR 0003), `axum`, SMTP clients, SQLite,
certificate tooling. Kernel interface is exec of `ip -j`, `nft -j`, `wg`,
`tc -j`, `conntrack`, `sysctl` with absolute paths and a hard timeout per
exec (3 s; probes 8 s). Parsers are tested against outputs captured on
Ubuntu 22.04, Ubuntu 24.04 and Debian 12.

---

## 5. Rulesets, routes, sysctls

### 5.1 M1: v1 parity ruleset

The v1 host-layout commands were retired in M2; the pure v1 renderer and golden remain as regression tests.

`fn ruleset(cfg: &V1Config) -> Result<String, ConfigError>` renders
`tests/golden/ruleset.golden` byte for byte: v1's ruleset plus the post-NAT
egress chain (ADR 0032), reproduced here:

```nft
#!/usr/sbin/nft -f
# Generated by scupper, do not edit. Regenerate with: scupper apply
# The kill switch is the absence of any eth0 exit path below.
flush ruleset

table inet scupper {
	chain forward {
		type filter hook forward priority 0; policy drop;
		iifname "wg0" oifname "proton0" accept
		iifname "proton0" oifname "wg0" ct state established,related accept
	}

	chain postrouting {
		type nat hook postrouting priority 100;
		oifname "proton0" masquerade
	}

	chain output {
		type filter hook output priority 0; policy accept;
		oifname "eth0" ip saddr 10.2.0.2 drop
	}

	chain egress {
		type filter hook postrouting priority 110; policy accept;
		oifname "eth0" ip saddr 10.2.0.2 drop
	}
}
```

Gateway-generated ICMP errors about NATed client flows can take the main-table
route to the uplink; conntrack applies the related flow's NAT after the output
hook, so the output rule cannot see their final exit source address. The egress
chain runs at postrouting priority 110, after source NAT at 100, and drops those
packets on the uplink. The output rule remains for locally generated packets
that do not pass through NAT.

`apply` behaves as v1 with one addition: write a temp file, validate it
with `nft -c -f`, rename it over `/etc/nftables.conf`, `nft -f` it. A file
that does not validate is never renamed into place, so it cannot become the
boot ruleset. This golden and the v1 renderer stay in
the tree until the last v1-layout gateway is retired, then both are deleted
together.

**Exact ruleset comparison (ADR 0013), from M1.** v1 checked that six
substrings occur in `nft list ruleset`; an extra rule such as
`iifname "wg0" oifname "eth0" accept`, or an unconstrained
`ct state established,related accept`, still "matched". M1 replaces it with
kernel canonicalization:

1. Run `unshare --net -- scupper canon <rendered file>` (util-linux
   `unshare`: an anonymous namespace that disappears with the process, so a
   crash leaves nothing behind). The hidden `canon` subcommand first compares
   `/proc/self/ns/net` with `/proc/1/ns/net` and **aborts if they are
   equal**, so a failed namespace switch can never load the file into the
   host. It then runs `nft -f <file>` and `nft -j list ruleset` and prints
   the JSON. A unit test fixes the argv shape.
2. Live: `nft -j list ruleset` in the host (M1: scupper owns the whole host
   ruleset through `flush ruleset`, so any foreign table, netdev chain or
   `dup`/`fwd` statement is a difference) or inside netns `scupper` (M2+).
3. Strip from both: `handle` fields, counter `packets`/`bytes`, the
   `metainfo` object. Keep everything else, including rule order. (R2: the
   elements of sets the renderer marks dynamic are stripped too; their
   declaration, type and flags are kept, §16.)
4. Equal JSON values → `Exact`; table absent → `Missing`; else
   `Differs{live_sha256, want_sha256}`. The canonical form is cached in
   `/run/scupper/` keyed by (rendered sha256, `nft --version`, the nft
   binary's inode and mtime, `uname -r`). Before `Differs` is reported the
   comparison is repeated once with a fresh canonicalization, so a stale
   cache can never produce a violation.

This needs no hand-written normalizer and survives nft's text normalization
(`priority 0` printed as `priority filter`) across versions. Renderer
constraint (E7, test R-07): interfaces are matched by **name**
(`iifname`/`oifname`, `ifname` sets) everywhere except `lo`, so the rendered
text loads in a namespace where our links do not exist.

### 5.2 R1 netns ruleset (complete example)

Example config: one client `mac` (10.99.0.2, fd00:99::2), client tunnel
`wg0`, exits `ex-ch1` (v4+v6) and `ex-nl1` (v4 only), API port 7380. Loaded
with `ip netns exec scupper nft -f`, so `flush ruleset` affects only the
namespace (ADR 0017).

The uplink-side property must hold after NAT: nothing with an exit address or
client address may appear on the uplink, including gateway-generated ICMP errors.

```nft
#!/usr/sbin/nft -f
# Generated by scupper from config version 43 (sha256 3f1c...). Do not edit.
# Loaded inside network namespace "scupper", which contains no uplink: no
# packet can leave it except through a WireGuard tunnel. This ruleset decides
# which tunnel, forces DNS and keeps clients isolated.
flush ruleset

table inet scupper {
	set client_ifaces { type ifname; elements = { "wg0" } }
	set exit_ifaces { type ifname; elements = { "ex-ch1", "ex-nl1" } }
	set exit_ifaces_v6 { type ifname; elements = { "ex-ch1" } }
	set client_nets4 { type ipv4_addr; flags interval; elements = { 10.99.0.2/32 } }
	set client_nets6 { type ipv6_addr; flags interval; elements = { fd00:99::2/128 } }

	# Destinations that are never forwarded for clients (I7 hardening against
	# provider-internal and local networks). Static: no host addresses here.
	set nonglobal4 {
		type ipv4_addr; flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
			     169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16,
			     224.0.0.0/4, 240.0.0.0/4 }
	}
	set nonglobal6 {
		type ipv6_addr; flags interval
		elements = { ::/127, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8 }
	}

	counter fwd_dropped { }

	# Second layer behind WireGuard's AllowedIPs check.
	chain antispoof {
		type filter hook prerouting priority raw; policy accept;
		iifname @client_ifaces ip saddr != @client_nets4 drop
		iifname @client_ifaces ip6 saddr != @client_nets6 drop
		# Exit peers have AllowedIPs 0.0.0.0/0: a provider-side packet must never
		# carry a client source address.
		iifname @exit_ifaces ip saddr @client_nets4 drop
		iifname @exit_ifaces ip6 saddr @client_nets6 drop
	}

	# Plain DNS is forced: every client query on port 53, to any address,
	# goes to the gateway forwarder on the incoming interface's address.
	chain dns_redirect {
		type nat hook prerouting priority dstnat; policy accept;
		iifname @client_ifaces meta l4proto { tcp, udp } th dport 53 redirect to :53
	}

	# I7: clients reach DNS, the API and ping on the gateway, nothing else.
	# From exits only replies to the gateway's own probes and DNS queries.
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state invalid drop
		ct state established,related accept
		iifname @client_ifaces meta l4proto { tcp, udp } th dport 53 accept
		iifname @client_ifaces tcp dport 7380 accept
		iifname @client_ifaces icmp type echo-request limit rate 10/second accept
		iifname @client_ifaces icmpv6 type echo-request limit rate 10/second accept
		iifname @client_ifaces icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		# TCP of flows whose state was flushed (failover, restore) is invalid
		# (nf_conntrack_tcp_loose=0); reset it so client applications reconnect.
		iifname @client_ifaces meta l4proto tcp ct state invalid reject with tcp reset
		ct state invalid drop
		# Port 53 that reaches forward was not redirected (a flow older than the
		# redirect rule): never forward it.
		iifname @client_ifaces meta l4proto { tcp, udp } th dport 53 drop
		# DoT/DoQ cannot be redirected; reject so clients fall back to 53.
		iifname @client_ifaces tcp dport 853 reject with tcp reset
		iifname @client_ifaces udp dport 853 reject with icmpx type port-unreachable
		iifname @client_ifaces ip daddr @nonglobal4 drop
		iifname @client_ifaces ip6 daddr @nonglobal6 drop
		# Client to exit: any configured exit; the route picks the active one.
		iifname @client_ifaces meta nfproto ipv4 oifname @exit_ifaces accept
		iifname @client_ifaces meta nfproto ipv6 oifname @exit_ifaces_v6 accept
		# Return traffic: directional, established/related only (bug 2).
		iifname @exit_ifaces oifname @client_ifaces ct state established,related accept
		# Deny by omission: no client-to-client, no new flows from exits.
		counter name "fwd_dropped" drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname @exit_ifaces masquerade
	}

	# Locally generated packets (kernel RSTs and ICMP errors, forwarder
	# upstream queries, probes) may only use the namespace's own tunnels
	# (bug 3). A foreign interface becomes a drop, not a path.
	chain output {
		type filter hook output priority filter; policy drop;
		oif "lo" accept
		oifname @client_ifaces accept
		oifname @exit_ifaces accept
	}
}
```

Feature gating (the renderer is a pure function of config; each variant has
a golden):

| Part | Present from |
|---|---|
| sets, antispoof, input (without 53/7380), forward (client→exit, return), postrouting, output | M2 |
| `dns_redirect`, input port 53, forward port-53 drop, 853 rejects, `nonglobal4/6` | M4 (with the forwarder; before M4 clients use the provider resolver `10.2.0.1` directly, which `nonglobal4` would block) |
| `exit_ifaces_v6` non-empty | M4, only for exits whose v6 support is verified (V-11) |
| input port 7380 | M5 |

Why each part exists:
- `antispoof`: WireGuard already enforces AllowedIPs; this covers a peer
  configured too broadly on the gateway (R2 router peers, mistakes). Exit
  peers legitimately have AllowedIPs `0.0.0.0/0`, so the exit rules stop a
  provider-side packet with a client source address from reaching edge or a
  client. Binding return traffic to the exit a flow left through (a
  conntrack mark) is deferred to R2 multi-provider.
- forward port-53 drop: NAT is decided on a flow's first packet, so a DNS
  flow to an outside resolver that existed before `dns_redirect` was loaded
  would otherwise keep bypassing the forwarder (apply also flushes conntrack
  when the NAT or forcing rules change).
- invalid-TCP reset: a conntrack flush does not reset connections by itself;
  with `nf_conntrack_tcp_loose=0` the next segment of a flushed flow is
  invalid and the client gets a reset instead of a silent hang.
- `input` policy drop: I7. The API port is unreachable from exits by rule and
  from the uplink by topology.
- `forward`: exactly two accepted shapes. The family split sends v6 only to
  exits declared and verified v6-capable. The `nonglobal` sets contain no host
  addresses, so host address changes cannot affect the client path.
- `postrouting`: masquerade only on exits. Several exits share `10.2.0.2`;
  that is fine for masquerade and source selection.
- `output` policy drop: kernel-generated packets can only use our tunnels.

### 5.3 Routes written by the failover machine

The only non-kernel routes in the namespace:

```
ip -n scupper    route replace default dev ex-ch1      # active exit
ip -n scupper -6 route replace default dev ex-ch1      # active exit is v6-capable
ip -n scupper -6 route replace unreachable default     # active exit has no v6: ICMPv6 error, apps fall back fast
ip -n scupper    route replace unreachable default     # Disconnected or no healthy exit
ip -n scupper -6 route replace unreachable default
```

`unreachable` (not `blackhole`) so applications get an error at once instead
of hanging until timeout.

### 5.4 Namespace sysctls

Set by `scupper boot`, read back every tick, re-applied after every
forwarding change (writing `net.ipv4.ip_forward` rewrites every device's
`forwarding` and `accept_redirects`; it does not touch `rp_filter`, but all
values are re-applied and read back anyway), and set explicitly rather than inherited (a new netns
copies IPv4 `all`/`default` values from the host, e.g. Ubuntu's
`rp_filter=2`):

| Sysctl (in netns) | Value | Why |
|---|---|---|
| `net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding` | 0 until verified, then 1 | gate |
| `net.ipv4.conf.{all,default,<each link>}.rp_filter` | 0 | standby probe replies arrive on a link with no route back while the default is elsewhere or `unreachable`; with rp_filter on, standbys never qualify and the gateway cannot leave FailClosed. Source validation is done by AllowedIPs and `antispoof`. |
| `net.ipv4.conf.{all,default}.accept_redirects`, `send_redirects`, `accept_source_route` | 0 | hardening |
| `net.ipv6.conf.{all,default}.accept_ra`, `accept_redirects`, `autoconf` | 0 | no route/address injection |
| `net.ipv4.conf.all.proxy_arp`, `net.ipv6.conf.all.proxy_ndp`, `net.ipv4.conf.all.route_localnet` | 0 | hardening |
| `net.netfilter.nf_conntrack_tcp_loose` | 0 | after a conntrack flush, mid-stream TCP is invalid and reset (§5.2) instead of being picked up again (V-25) |

Order whenever forwarding changes: write forwarding → re-apply all hardening
values → read back all → mismatch is a repair item.

---

## 6. Exit health and the failover state machine

### Signals per exit

| Signal | Mechanism | Active | Standby | Timeout |
|---|---|---|---|---|
| handshake | `wg show <if> latest-handshakes` | 5 s | 5 s | – |
| path probe | DNS query (A record of the first probe hostname) to the exit's provider DNS, **through that exit** | 10 s; 2 s while Suspect | 30 s | 3 s |
| exit-IP probe | HTTPS GET to configured targets (default `https://ifconfig.me/ip`, `https://icanhazip.com/`); the probe resolves the hostname with its own DNS query through the same exit, then connects to that IP with SNI; success if either target returns a parseable IP | 60 s | 5 min | 8 s |

- Active-exit probes use **unbound** sockets in the namespace: locally
  generated packets take the output route lookup, which in a namespace
  without policy rules agrees with the forwarding lookup for client packets.
  `check` additionally runs `ip route get … from <client> iif wg0`; neither
  replaces the other.
- Standby probes use `SO_BINDTODEVICE` to the standby link (the route points
  at the active exit). They must work while the default route is
  `unreachable` (V-02). They run over **IPv4 only**: IPv6 output routing
  applies strict interface matching to bound sockets and has no on-link
  fallback, so a bound v6 probe has no route while the v6 default is
  elsewhere or `unreachable` (V-22). An exit's v6 capability is verified
  while it is active (stage 5 v6, stage 6 over v6) and by V-11; standby
  qualification says nothing about v6.
- Nothing in the namespace uses the host resolver (`/etc/resolv.conf` points
  at `127.0.0.53`, which does not exist there). Edge never resolves names.
- An exit-IP equal to any host uplink address is a **violation** (2), not a
  failover.
- Latency is measured and exported, never used for switching in R1.

**Exit quality (informational in R1).** From the probes already running,
scupperd keeps per hot exit a bounded window of probe round-trip times and
outcomes (in memory, last 1 h): median and p95 RTT, and the probe failure
rate. Cold exits keep their last measurement with its age. `exit list`
shows these, `exit show` adds the history, and they are exported as metrics
(§13). Failover order is unchanged by them; R2 latency-based policies may
use them. `exit test EXIT --speed` runs an on-demand throughput test: one
HTTPS download from `health.speed_test_url` (config), bounded to 25 MB and
10 s, from a probe child bound to that exit only, never via the uplink. A
cold exit is brought up only for the test and only if that keeps at most
two exits hot; otherwise the test is refused with a message naming the
limit. Probe and speed-test targets are config, not user traffic, so I5 is
unaffected. Aggregation (median, p95, failure rate, window eviction) is a
pure function with unit tests; the hot-session check is a pure function
with a test that the speed test is refused when it would exceed two hot
sessions. Proton's server-load figure (undocumented API) is R2, optional
and isolated: if it breaks, nothing else is affected.
- Hard Down: handshake stale > 180 s (keepalive 25 s gives a re-handshake
  about every 2 min), link or peer missing, key file missing.

**Common-mode rule.** A probe failure counts against an exit only if at
least one other exit's path probe succeeded within the **comparison window**
(the last 20 s on the monotonic clock), or the exit's own handshake is
stale. When the active exit turns Suspect, scupperd immediately runs a bound
path probe on the hot standby, so a fresh comparison exists within about 3 s
instead of waiting for the 30 s standby cadence. If every probed exit fails
at once, the probe target or the gateway is suspect: no switch, verdict 3
`CommonModeProbeFailure`, alert. With a single configured exit, probe
failures alone never cause a switch.
A comparison witness must be non-Down with a successful latest probe within the window (a same-round failure invalidates it), and switches including automatic failback are blocked when all recent observed probes fail, regardless of Down or unprobed standbys.

**No comparison available** (cold standbys only, or the hot standby is
itself Down): if the active exit has failed its probes for 60 s with a fresh
handshake, scupperd brings up the next cold candidate as a **qualifier** (it
takes the standby's hot slot, so at most two exits are up) and qualifies it
(handshake + 3 path successes). If it qualifies, the active exit's failures
count and normal failover applies; if it fails too, the failure is
common-mode. This covers "handshake works, payload forwarding fails" with
cold standbys (L48).

### Per-exit health

```
Unknown ──fresh handshake + 3 consecutive path successes──▶ Healthy
Healthy ──1 counted failure──▶ Suspect ──1 success──▶ Healthy
Suspect ──3 consecutive counted failures──▶ Down
any ──handshake stale > 180 s, link/peer/key missing──▶ Down
Down ──fresh handshake──▶ Recovering ──3 consecutive successes spanning ≥ 30 s──▶ Healthy
Recovering ──any failure──▶ Down
```

Detection of a dead active exit through probes: ≤ 10 s to the first failure,
then two more at 2 s: about 15 s.

### Intent and global state (ADR 0010)

```
Selection (persisted, survives reboot): Auto | Prefer(exit) | Pin(exit) | Disconnected
Global:                                 Active(exit) | FailClosed(reason)
```

Candidate order: `Auto` = configured `policy.exits`; `Prefer(x)` = x first,
then the configured order; `Pin(x)` = only x; `Disconnected` = none.
`exit use X` sets `Prefer(X)`; `exit use X --pin` sets `Pin(X)`;
`exit auto` sets `Auto`.

| From | Condition | To | Actions |
|---|---|---|---|
| Active(e) | e Down, first Healthy candidate c ≠ e | Active(c) | SetRoute(c), FlushConntrack, NotifyEdge, Emit(Failover) |
| Active(e) | e Down, no Healthy candidate | FailClosed(NoHealthyExit \| PinnedExitDown) | SetRoute(Unreachable), FlushConntrack, Emit(FailClosedStarted) |
| FailClosed(_) | selection ≠ Disconnected, a candidate Healthy | Active(first Healthy) | SetRoute, NotifyEdge, Emit(FailClosedEnded{duration}) |
| any | selection := Disconnected | FailClosed(AdminDisconnected) | SetRoute(Unreachable), FlushConntrack, SetExitsDown |
| any | selection changed by admin | re-evaluate immediately with the new order | as above |
| Active(e) | **only if `failback = "auto"`**: a candidate p ordered before e Healthy ≥ `failback_hold` (10 min) and ≥ `min_dwell` (120 s) since the last switch, failback not suppressed | Active(p) | SetRoute(p), FlushConntrack, NotifyEdge, Emit(Failback) |
| Active(e) | > 4 switches in 30 min | unchanged; failback suppressed 1 h | Emit(Flapping) |

**Sticky by default** (`failback = "manual"`): after a failover the gateway
stays on the working exit. Every switch resets all flows and changes the
public IP; switching back gains no safety.

**Switch procedure** (ADR 0016): `route replace` v4, `route replace` v6 (exit
or `unreachable`), `conntrack -F` inside the namespace (flows NATed via the
old exit cannot survive a public-IP change; the flush invalidates state, it
does not itself reset connections: with `nf_conntrack_tcp_loose=0` the next
client TCP segment of such a flow is invalid and answered with a reset
(§5.2), other packets are dropped, and safety is judged by packet admission
and routing, not by the flush), notify edge of the new DNS upstream
(edge flushes its cache), emit the event. Every intermediate state routes to
a configured exit or `unreachable`. After a crash scupperd re-observes and
never trusts its memory of a phase.

**Standby mode** (ADR 0011): `standby = "hot"` (default) keeps the active
exit and the next candidate up so the standby's health is known and a switch
is one route change (~15 s outage). It needs one provider session per hot
exit; any number of exits may be configured, at most **two** are hot (§8),
and hot standby is relied on only after V-09 confirms the provider account
permits two simultaneous WireGuard sessions sharing `10.2.0.2`.
`standby = "cold"` keeps only the active exit up; on Down it brings the next
candidate up, qualifies it (handshake + 3 path successes at 2 s) and then
switches: roughly 30-60 s outage, no extra session.

### Types

```rust
pub struct ExitId(String);                        // validated config id
pub struct ExitIfname(String);                    // constructible only from a configured exit
pub enum RouteTarget { Exit(ExitId), Unreachable }

pub enum ExitHealth {
    Unknown,
    Healthy { since: MonoTime },
    Suspect { failures: u8, since: MonoTime },
    Down { since: MonoTime, reason: DownReason },
    Recovering { successes: u8, since: MonoTime },
}
pub enum Selection { Auto, Prefer(ExitId), Pin(ExitId), Disconnected }
pub enum FailClosedReason { AdminDisconnected, NoHealthyExit, PinnedExitDown(ExitId) }

pub struct Failover {
    selection: Selection,
    active: RouteTarget,
    health: BTreeMap<ExitId, ExitHealth>,
    switches: VecDeque<MonoTime>,
    failback_suppressed_until: Option<MonoTime>,
}

pub enum FailoverInput { Handshakes(..), ProbeResult(..), SelectionChanged(Selection), Tick }
pub enum FailoverAction { SetRoute(RouteTarget), FlushConntrack, SetExitsDown, NotifyEdge(ExitId), Emit(Event) }

impl Failover {
    /// Pure; all time comes in as `now`.
    pub fn step(&self, now: MonoTime, input: FailoverInput, cfg: &FailoverConfig)
        -> (Failover, Vec<FailoverAction>);
}
```

All intervals (holds, dwell, flap suppression, grace, budgets) use
`MonoTime` (`CLOCK_BOOTTIME`), so clock steps cannot expire or stall them;
wall-clock time is used only for display and event timestamps. Holds do not
survive a reboot; they restart from zero, which can only delay a failback.

---

## 7. Watch and repair loop

Level-triggered polling (ADR 0022): every tick observes the full state and
compares it with the desired state derived from (applied config version,
persisted selection, failover state). scupperd never trusts its memory of
what it did; a crash between action and bookkeeping is harmless.
`ip monitor`/`nft monitor` may later be added as a wake-up hint without
changing the logic.

### Cadence

| Every | Observation |
|---|---|
| 2 s | netns inode; links, addresses, peers; routes v4/v6; rules; ruleset fingerprint; sysctls; tc on our links |
| 5 s | `wg show all latest-handshakes` (in netns) |
| 10 s (2 s Suspect) | active path probe |
| 30 s | standby path probes; DNS self-test against the forwarder; edge liveness |
| 60 s | active exit-IP probe; heartbeat (§13) |
| 5 min | standby exit-IP probes |

The systemd watchdog (`WatchdogSec=30`) is fed **only at the end of a
complete iteration**, so a hung exec or a stuck loop counts as a hang.

**Tick budget.** The safety observations (netns inode, links, ruleset
fingerprint, forwarding, tc) run first in every tick, each exec bounded at
3 s and the group at 6 s. Probes run in children and never block the tick.
Event `fsync` runs on a writer thread, so a stalled disk delays the record,
never a safety action. The reaction bound for safety drift is therefore one
tick interval plus the safety group: about 2 s normally, at most 8 s with
stalled tools. L7 and L21 measure it, and the measured numbers are the ones
this document quotes.

**DNS self-test** (M4+): a query for `<random label>.example.com` with a
fresh label every run, so the cache cannot answer; any upstream response,
NXDOMAIN included, is success. It is sent from the namespace to
`10.99.0.1:53` over UDP and TCP (and `[fd00:99::1]:53` when a client has
v6), so it tests the client-facing listeners, and it compares edge's
upstream generation with scupperd's.

### Repairs

Disconnected keeps all forwarding gates at 0.

| Drift | Detected by | Repair (in order) | Class |
|---|---|---|---|
| Ruleset missing or differs | fingerprint | forwarding 0 (both families, **immediately**, no debounce) → `nft -f` rendered file → verify → `conntrack -F` (drops flows created during the gap) → forwarding 1 unless latched or Disconnected → re-apply hardening → read back | Tighten, then Restore |
| Forwarding 0 with verified ruleset, no quarantine latch, not Disconnected | sysctl | forwarding 1 (only with an exact match on the same tick, unless latched or Disconnected), re-apply hardening | Restore |
| Hardening sysctl differs | sysctl | write, read back | Restore |
| Route missing or wrong | route table | `route replace` with the failover machine's current target | Restore |
| Extra route in the netns main table | route table | delete | Tighten |
| Client or exit link missing | link list | recreate: host (down) → move → configure → up | Restore |
| Address or peer config differs | `ip -j addr`, `wg show … peers/allowed-ips/persistent-keepalive` (learned endpoints are not compared) | reapply from config | Restore |
| Foreign link in netns | link list | at once (no debounce): `ip link set down`, alert, never delete | Tighten |
| Extra policy rule in netns | `ip -j rule` | delete | Tighten |
| tc qdisc/filter beyond the baseline (§3) on any netns link | `tc -j` | at once (no debounce): set the link down if it is foreign, delete the hook, alert | Tighten |
| Netns name gone, inode alive (held fd or edge's `/proc/<pid>/ns/net`) | stat of `/run/netns/scupper` | re-create the mount point and bind-mount the existing namespace to it | Restore |
| Netns inode gone | no holder | stop edge, rerun the boot procedure, then start edge | Restore |
| Edge in another namespace (`/proc/<edge pid>/ns/net` inode ≠ held inode) | `stat` | restart edge | Restore |
| Leftover host-side link of ours (crash between `ip link add` and the move) | host link list: our name, kind `wireguard`, down, no peers | delete it, continue the boot procedure; any other host link with that name stops boot (closed) | Restore |
| Exit handshake stale | handshakes | failover (§6); re-set the peer endpoint from config to force a handshake | Restore |
| Edge dead | systemd, DNS self-test | none beyond alerting (systemd restarts it) | – |
| Host-side state | not observed for repair | none (T); optional host `ip_forward` warning | – |

Rebuilding while the old namespace is alive would create a second namespace
whose new `wg0` cannot bind its listen port; this is why the inode, not the
name, identifies the namespace. `BindsTo=` links edge only to the *unit*: a
oneshot with `RemainAfterExit=yes` stays active when the namespace object is
deleted or replaced, and `NetworkNamespacePath=` is resolved only when edge
starts. The namespace identity is therefore checked by scupperd every tick
(row above), scupperd restarts edge after any rebuild, and scupperd's unit
keeps edge running with `Upholds=` (V-28).

**Not repairable by design:** anything needing a state looser than config;
key file missing or wrong mode (that exit stays Down, alert); invalid config
version (stay on the applied version, alert).

### Budgets and fighting

- At most **3 Restore repairs per object per 10 min** (monotonic clock);
  for safety drift (ruleset, foreign link, tc) the budget is per drift
  class, so changing names or handles does not reset it. Tighten repairs
  are never budgeted. When exhausted: stop restoring that object, emit
  `RepairSuppressed`, and for safety drift **set forwarding 0 and the
  quarantine latch** (ADR 0031): the latch is held in memory before the
  first step, forwarding goes to 0, the drift is tightened away, then
  `state.json` records `quarantine {reason, object, since}` (fsynced); boot step 6 and every
  planner and repair step refuse to raise forwarding while it is set; only
  `scupper repair clear` or a verified full `scupper apply` removes it, with
  an `AdminAction` event. If the latch cannot be persisted, it holds in
  memory and `PersistenceFailed` is raised; after a restart without the
  record the drift is seen again and re-latches. Suppression always ends
  closed.
- Debounce: drift must be seen on 2 consecutive ticks before a repair, except
  ruleset drift (forwarding 0 at once), foreign links and tc hooks (acted on
  at once).
- **One writer** (ADR 0028): every code path that mutates kernel or
  persistent state (the boot procedure, the scupperd tick, a local `apply`
  while scupperd is down, the deploy rollback executor) holds the exclusive
  lock `/run/scupper/writer.lock` (`flock`) for its whole step sequence. The
  property "every prefix is safe" is proved for one writer; the lock makes
  that the only case.
- In the netns layout the only possible "other writer" is a human with root;
  stopping and alerting is the right response to fighting.
- Disk errors never block a safety repair; the event is kept in memory and
  `PersistenceFailed` is raised.

### Planner

`plan(desired, observed) -> Vec<Step>` is pure. Steps are ordered tighten
before loosen: remove an exit from the route before deleting its link,
delete links before shrinking ruleset sets, grow ruleset sets before
creating links. Each step is idempotent. Property: **every prefix of every
plan satisfies `safe(state)`** (no forward path to a non-exit; forwarding on
implies a verified ruleset). On a failed step, scupperd re-plans from the
observed state toward the **previous** applied version and alerts;
`applied_version` is published under closed gates before the target boot. A failed
live apply restores the previous version and reports its rollback result (§18).

---

## 8. Configuration

### Model

One **site** file (TOML, `schema = 1`) describes gateways, client-facing
identities, exits (per gateway, since keys are local), users, devices,
alert sinks and the heartbeat. Each gateway applies its own section,
selected by the local file `/etc/scupper/gateway-id`. Stable IDs everywhere.
Sections for R2 features are **rejected** by R1 validation ("not supported in
this release"), never ignored. Secrets are `*_ref` names resolved to
`/etc/scupper/secrets/<kind>/<ref>` (root, 0600; directories 0700) (ADR 0023).
A ref matches `[a-z0-9][a-z0-9-]{0,62}` (no separators, no dots). `kind`
follows from the field (`wg` for `private_key_ref`, `url` for `url_ref`), so
a URL field can never name a key file. Files are opened relative to a
directory descriptor with `O_NOFOLLOW`; the opened object must be a regular
file, root-owned, 0600, in a root-owned 0700 directory. Content is validated
per kind (a WireGuard key decodes to 32 bytes, a URL parses as `https`), and
errors name the ref, never the content. Delivery children receive URL values
from scupperd over a pipe, never by reading the file.

```toml
schema = 1

[site]
name = "home"
primary = "gw1"                      # R2: config authority; R1: must equal the only gateway

[identities.edge]                    # client-facing WireGuard identity (R2 HA may share it)
public_key = "<base64 public key>"
private_key_ref = "wg0"              # /etc/scupper/secrets/wg/wg0
listen_port = 51820

[gateways.gw1]
netns = "scupper"
uplinks = ["eth0"]                   # checks only: exit IP must not equal an uplink address
endpoint = "198.51.100.7:51820"      # what clients dial; literal IP

[gateways.gw1.client_tunnel]
ifname = "wg0"
identity = "edge"
address4 = "10.99.0.1/24"
address6 = "fd00:99::1/64"
mtu = 1420

[gateways.gw1.api]                   # M5
port = 7380

[gateways.gw1.dns]                   # M4
block_dot = true                     # must be true in R1
cache = true                         # in memory only

[[gateways.gw1.exits]]
id = "ch1"                           # stable machine ID: config refs, events, metrics labels
name = "Zurich"                      # display name, editable (`exit rename`)
tags = ["fast"]                      # optional labels; R2 policies may select by tag
provider = "proton"
ifname = "ex-ch1"                    # 1-15 chars, prefix "ex-"
private_key_ref = "exit-ch1"
peer_public_key = "<base64 public key>"
endpoint = "203.0.113.10:51820"      # literal IP, no host resolver at boot
address4 = "10.2.0.2/32"
address6 = "2001:db8:2::2/128"       # present and verified => v6-capable
dns = ["10.2.0.1"]                   # literal IPs
keepalive = "25s"
mtu = 1420
enabled = true

[[gateways.gw1.exits]]
id = "nl1"
name = "Amsterdam"
provider = "proton"
ifname = "ex-nl1"
private_key_ref = "exit-nl1"
peer_public_key = "<base64 public key>"
endpoint = "203.0.113.20:51820"
address4 = "10.2.0.2/32"
dns = ["10.2.0.1"]

[policy]                             # R1: one global ordered list
exits = ["ch1", "nl1"]
failback = "manual"                  # manual (default) | auto
failback_hold = "10m"
min_dwell = "120s"
standby = "hot"                      # hot | cold

[health]
handshake_stale = "180s"
failover_grace = "30s"
probe_targets = ["https://ifconfig.me/ip", "https://icanhazip.com/"]
route_probe_dst4 = "1.1.1.1"
route_probe_dst6 = "2606:4700:4700::1111"
speed_test_url = "https://speed.example.net/25MB.bin"   # exit test --speed only
require_daemon = true                # check exits 5 when scupperd is not alive

[users.admin]
role = "admin"

[devices.mac]
user = "admin"
public_key = "<base64 public key>"
address4 = "10.99.0.2/32"
address6 = "fd00:99::2/128"
api_token_sha256 = "<hex>"           # token generated on the Mac; only its hash is here
gateways = ["gw1"]                   # R2 client-side HA: several entries

[alerts.sinks.phone]
kind = "ntfy"
url_ref = "ntfy-url"                 # topic URL is a credential
min_severity = "warning"

[alerts.sinks.chat]
kind = "webhook"
preset = "telegram"                  # telegram | pushover | generic
url_ref = "telegram-url"
min_severity = "critical"

[heartbeat]
kind = "healthchecks"                # the only R1 kind: alerts when pings stop, understands /<code>
url_ref = "heartbeat-url"
interval = "60s"
report = "status_code"               # ok_only | status_code

# R2, rejected by R1 validation:
# [groups.*], [[policies]], [[allow]], [providers.*] other than proton,
# an identity referenced by more than one gateway, more than one gateway section
```

### Validation (pure)

- ifnames 1–15 chars `[a-z0-9-]`, unique per gateway; exit names start with
  `ex-` and are disjoint from client names and `uplinks`.
- Exit `name`: 1–32 printable characters, unique per gateway
  case-insensitively, and never equal to another exit's `id`. `id` is
  immutable once created; renaming changes only `name`. Tags `[a-z0-9-]`.
- `policy.exits` references existing enabled exits, no duplicates. Any
  number of exits may be configured; R1: at most 2 are **hot** (connected)
  at once: the active exit and one standby. Further exits in the list are
  **cold** candidates, brought up only when failover reaches them (slower
  switch, no provider session used while idle).
- Device addresses are host prefixes (/32, /128) inside the client tunnel
  prefixes, unique; never `0.0.0.0/0` or `::/0`; never overlapping exit
  addresses or DNS.
- Endpoints and DNS servers are **literal IPs**.
- Durations positive; `suspect interval < active probe interval`.
- No key material: the schema has no key-typed field; a lint rejects any
  string that decodes as 32 bytes of base64 except `public_key` fields.
- R1: exactly one gateway; an identity used by at most one gateway;
  `block_dot = true`.
- On the gateway (not pure): referenced secret files exist, root-owned, 0600.

### Versioning (ADR 0012)

```
/var/lib/scupper/config/versions/000043.toml       immutable, 0640 root
/var/lib/scupper/config/versions/000043.meta.json  {parent: 42, sha256, actor, at, reason}
/var/lib/scupper/config/head                       "43" (atomic rename)
/var/lib/scupper/state.json                        {applied_version, selection, quarantine}
/var/lib/scupper/rendered/000043.nft               rendered netns ruleset of that version
/etc/scupper/scupper.toml                          read-only mirror of head (0444)
```

- **The version store is authoritative.** Every change (`config edit/set/load`,
  `exit import`, `device add`, API `POST /v1/config`) creates N+1 with
  `parent = N`. A write whose parent is not head fails (409): compare-and-swap.
- **Risk classes** (ADR 0029): a change that touches `devices`, `users`,
  `identities`, an exit's `endpoint`, `peer_public_key` or any `*_ref`, adds
  an exit, changes alert or heartbeat settings, or adds exits to
  `policy.exits` is **high-risk** and is accepted only over the local socket
  (SSH or root on the gateway). The tunnel API accepts only low-risk changes
  (exit order, enable/disable, names, tags, failback and standby settings,
  health timings). scupperd classifies the diff itself; edge cannot change
  the class.
- `config rollback 41` creates a new version with the content of 41,
  validated under the current schema. History stays linear. Its risk class
  is that of the diff from head, and a rollback that would re-add a removed
  device or a rotated token says so in its confirmation.
- **Durability:** every commit writes the new file, `fsync`s it, renames it
  and `fsync`s the directory, in the order version file, meta, `head`;
  `state.json` likewise. A disconnect is acknowledged only after `state.json`
  with `Disconnected` is durable. On start, a version file newer than `head`
  is an interrupted commit and is ignored.
- A hand edit of `/etc/scupper/scupper.toml` is detected (hash ≠ head),
  ignored and alerted. `scupper config load /etc/scupper/scupper.toml` turns
  it into a version deliberately, so "who changed what" stays answerable.
- Schema evolution: daemons read schema N and N−1; `scupper config migrate`
  writes a new version in schema N. Old binaries refuse newer schemas.
- At boot an invalid or missing applied version leaves the gateway closed.

### Operator-side secret references (ADR 0023)

Gateway-side secrets (`wg0` key, provider keys, credential URLs) are the
root-only files above. Every secret the **operator** supplies on the Mac
(cloud API token, an imported provider file's key when piped, a webhook URL
being added) is given as a reference and resolved just in time:

A reference has the generic form `scheme:rest` (or `scheme://rest`). The
scheme selects a **backend**; backends sit in a registry, so a new store is
one new backend, not a change to every command that takes a secret.

Built-in backends in R1:

| Reference | Resolution |
|---|---|
| `pass://vault/item/field` (**primary**) | exec Proton Pass `pass-cli` to read that field (an `item view <ref>`-style call; exact command and output format: V-19), with `PROTON_PASS_AGENT_REASON` set to the command (e.g. `scupper gateway create`), since recent `pass-cli` versions require a reason for audited reads. A minimum `pass-cli` version is pinned and checked (`pass-cli --version`) before use |
| `keychain:service/account` | exec `security find-generic-password -s service -a account -w`. An unsigned CLI gets the legacy "allow" dialog, not per-use Touch ID (that would need a signed app with entitlements) |
| `env:VAR` | environment variable |
| `file:PATH` | regular file owned by the caller with mode 0600, else refused |
| (none) | hidden interactive prompt, TTY only; without a TTY: refuse, exit 1 |

**Command-defined backends** cover any other store (1Password, Bitwarden,
gopass, HashiCorp Vault, a custom script) without code changes. They are
declared in the Mac-side config and register their scheme:

```toml
# ~/.config/scupper/mac.toml
[secrets.backends.op]            # makes op://... references available
command = ["op", "read", "op://{ref}"]
timeout = "60s"                  # interactive unlock (Touch ID) allowed

[secrets.backends.bw]            # bw:item-id
command = ["bw", "get", "password", "{ref}"]
```

Rules for command backends: `command` is an argv list, never run through a
shell; `{ref}` (the part after the scheme) is substituted as exactly one
argument and is validated (no NUL, no leading `-`); the secret is stdout with
one trailing newline trimmed; non-zero exit, empty output or timeout is an
error showing the backend name, exit status and at most the first line of
stderr (never stdout); the child inherits the TTY so the store can prompt;
its environment is minimal (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, the
variables the backend entry lists in `pass_env`, and `SCUPPER_SECRET_REASON`
with the scupper command), so cloud tokens and other credentials in the
caller's environment are never passed on. **Never as root:** secret
resolution of any kind refuses to run when the effective uid is 0, and no
root process (the Mac helper, `sudo scupper …`) reads
`~/.config/scupper/mac.toml`. Command backends are refused unless
`mac.toml` is owned by the invoking user and not group- or world-writable. Built-in
schemes cannot be overridden by a config entry; an unknown scheme is an
error listing the known ones. 1Password is shipped as a documented example
of a command backend rather than a built-in.

Each reference resolves only through its own backend: if `pass-cli` is
missing, too old or not logged in, resolution fails with an actionable
message (`pass-cli is not logged in; run: pass-cli login`) and **never falls
back silently** to another backend. Example:
`scupper gateway create --provider digitalocean --token pass://Infra/digitalocean/token`.
`scupper secret check REF` resolves a reference and prints only whether it
worked and the value's length, never the value.

Reference strings are not secret and may be stored in Mac-side config
(`~/.config/scupper/mac.toml`). Values are held only in memory
(`Zeroizing`), never written to config, events, logs, process arguments or
the gateway; backend children receive the reference, never a value, and the
value is read from their stdout.

```rust
pub struct SecretRef { scheme: Option<String>, rest: String }   // None = prompt
pub trait SecretBackend: Send + Sync {
    fn scheme(&self) -> &str;                                     // "pass", "keychain", ...
    fn resolve(&self, r: &SecretRef, cx: &ResolveContext) -> Result<Secret, SecretError>;
}                                                                 // Secret: Zeroizing, no Debug/Serialize
pub struct SecretRegistry { backends: BTreeMap<String, Box<dyn SecretBackend>> }
// built-ins: ProtonPass, Keychain, Env, File, Prompt; config: CommandBackend { argv, timeout }
pub enum SecretError { UnknownScheme { scheme: String, known: Vec<String> }, NotLoggedIn { backend: String, fix: String },
                       ToolMissing { tool: String }, ToolTooOld { tool: String, min: String },
                       NotFound(String), Refused(String), Failed { backend: String, status: Option<i32>, stderr_head: String },
                       Timeout { backend: String }, Io(String) }
```

`FakeBackend` serves fixed values in tests; parsing of reference strings and
command-backend argv substitution are pure functions with unit and property
tests (no shell injection, exactly one argument per `{ref}`).

### Config bundle (fast rebuild)

`scupper config bundle [-o FILE]` (any transport) writes a tar of all
versions, their meta files, `head` and `state.json` (selection), plus a
`MANIFEST` with sha256 of each file. It never contains `secrets/`, keys or
event logs; export fails if any file outside that list is requested.
`scupper install --bundle FILE` restores it (§15). Import extracts into a
fresh staging directory with an exact member allow-list (`MANIFEST`, `head`,
`state.json`, `versions/NNNNNN.toml`, `versions/NNNNNN.meta.json`), regular
files only (no links or devices), no member path with `..` or a leading `/`,
at most 16 MiB in total and 1 MiB per file. Every hash and every version is
validated before anything moves into `/var/lib/scupper/`. The Mac agent stores a
copy after every `ConfigCommitted` event (§14).

---

## 9. DNS forwarder (ADR 0005, 0006)

**An embedded forwarder in `scupper-edge`, not a resolver.** It relays
queries to the active exit's provider DNS (Proton `10.2.0.1`, which also
applies the provider's filtering), over UDP and TCP, with a small in-memory
cache.

- **Listen:** `10.99.0.1:53` and `[fd00:99::1]:53` (UDP, TCP) with
  `IP_FREEBIND`, so it can start before `wg0` has addresses. nft `input`
  admits port 53 only from client tunnels. nft redirects every client port-53
  packet, to any destination, here.
- **Upstream:** sockets created in the namespace, not bound to a device: they
  follow the namespace default route, i.e. the active exit. The upstream
  addresses are the active exit's `dns`, received from scupperd through a
  long-poll subscription `DnsUpstream{exit, servers, generation}`; on a new
  generation edge flushes its cache. Every upstream query and cache
  insertion carries the generation it was sent under; a response from an
  older generation is discarded, never cached or returned. If scupperd is
  unreachable, edge keeps the last upstream and re-subscribes every 5 s; on
  reconnect it compares generations and flushes on any difference. The DNS
  self-test and `check` stage 7 compare edge's generation with scupperd's.
- **No leak by construction:** the process has no uplink (T). With all exits
  down, upstream sends fail and clients get SERVFAIL.
- **No logging:** no code path writes query names. Errors are counted by kind
  (`timeout`, `servfail`, `refused`, `malformed`).
- **Parsing:** `hickory-proto` validates messages; malformed queries are
  dropped and counted. Limits: 512-byte UDP answers unless EDNS, TCP 64 KiB,
  max 256 in-flight queries, 2 s upstream timeout, cache ≤ 10 000 entries,
  TTL capped at 1 h, no negative caching beyond 60 s. No DNSSEC validation
  (the provider's filtered answers pass unchanged, V-12).
- **Protocol behaviour (specified and unit-tested):** a response is accepted
  only on the socket the query was sent from, from the upstream address and
  port queried, with the same transaction ID and question (RFC 5452
  matching); each upstream query uses a fresh random ID and source port;
  cached answers are served with the TTL reduced by their age; a truncated
  UDP answer is retried over TCP; EDNS options and the DO, AD and CD bits
  pass through unchanged; the client's transaction ID is restored on the
  reply.
- **Firefox DoH canary:** queries for `use-application-dns.net` (every record
  type) are answered locally with NXDOMAIN and never forwarded. Firefox then
  does not switch on DNS over HTTPS by itself and keeps using the gateway
  resolver (the provider's DNS and filtering). This does not affect DoH that
  a user has enabled explicitly; Chrome and Safari do not check the canary.
  Operator note: set the browser's "secure DNS" to off or to the system
  resolver. DoH still travels only through the tunnel and a VPN exit (no
  leak), but it bypasses the gateway resolver and the provider's filtering.
  Unit test: a canary query of each type yields NXDOMAIN with no upstream
  send; behaviour test L54.
- **DoT/DoQ:** TCP 853 rejected with RST, UDP 853 with ICMP port-unreachable,
  so clients fall back to port 53 immediately. **DoH cannot be forced** and
  still leaves only through the VPN.
- **Fallback:** if the forwarder slips, dnsmasq in the namespace
  (`server=10.2.0.1@ex-…`, `nftset=` for R2) is the documented substitute,
  without changing the ruleset.
- **R2:** per-domain routing parses answers and adds A/AAAA records to nft
  sets with timeouts, so domain policy chooses among exits only.

---

## 10. Control plane and API authentication

### Transports

| Transport | Endpoint | Identity |
|---|---|---|
| Local | Unix socket `/run/scupper/control.sock`, 0660 `root:scupper-admin`, newline-delimited JSON | `SO_PEERCRED`: uid 0, or a uid whose group list contains `scupper-admin` (looked up with `getgrouplist`, since `SO_PEERCRED` carries only the primary gid) = admin |
| Edge | Unix socket `/run/scupper/edge.sock`, 0660 `root:scupper-edge` | `SO_PEERCRED` uid = `scupper-edge`; only the edge operation set: forward an authenticated tunnel request with its device principal, the `DnsUpstream` subscription, the verdict/metrics snapshot |
| Tunnel API (M5) | HTTP/1.1 + JSON, edge, `10.99.0.1:7380` and `[fd00:99::1]:7380`, inside the namespace | WireGuard source address + device token |
| SSH (break-glass) | `ssh root@<public address> scupper remote`, request as JSON on stdin | sshd on the host, untouched by scupper |

There is **no SSH inside the tunnel** (ADR 0008): sshd stays in the host
namespace, so `ssh 10.99.0.1` does not work after the move to the netns
layout. The CLI uses the API; SSH goes to the gateway's public address.

**Remote command construction.** OpenSSH joins the remote command and its
arguments with spaces and the remote shell parses the result, so separate
local arguments give no remote argument boundary. Every SSH call therefore
runs exactly one fixed command, `scupper remote` (built from constants
only), and sends a bounded (1 MiB) JSON request `{op, args, request_id}` on
stdin; key material for `exit import` follows as a length-prefixed field of
the same stream. The gateway validates the operation and its arguments with
the same types as the local socket. Tests feed quotes, newlines, `$(…)`,
backticks, leading hyphens and malformed identifiers through every
operation.

### API authentication (ADR 0007)

1. **WireGuard identity.** Edge maps the connection's source address to
   exactly one device (WireGuard guarantees a source inside a peer's
   AllowedIPs was sent by that peer's key). Unknown source → 403.
2. **Device token.** `Authorization: Bearer <token>` on every request except
   `GET /v1/health`. 32 random bytes, base64url, generated on the device;
   the gateway stores only its sha256; compared in constant time. This
   defends against any web page in the Mac's browser sending requests to
   `10.99.0.1` (CSRF, DNS rebinding).
3. **Host check.** `Host` must be the literal tunnel address (with port).
   No CORS headers; `OPTIONS` preflights are refused.
4. **Trust boundary.** Edge forwards authenticated calls to scupperd with an
   asserted principal `Device{id, user}`; scupperd accepts assertions only
   on the edge socket. **scupperd decides what a tunnel principal may do**
   (ADR 0029): the operational set (status, check, events, metrics, connect,
   disconnect, exit selection, apply of head, low-risk config changes,
   deploy confirmation) and never a high-risk change (§8), whatever edge
   asserts. A compromised edge, or a stolen token used from the device, can
   disrupt service or choose among configured exits, but cannot add a
   device, change an exit's endpoint or keys, or redirect alerts. Edge is
   unprivileged, holds no keys and is hardened.
5. **No TLS.** WireGuard provides confidentiality and peer authentication.
6. **Authorization.** `Principal → User → Role {Admin, User}`; R1 has one
   admin. R2 users may read their own devices and events and choose exits
   within their group's allowed list.
7. Request limits: 1 MiB body; 16 concurrent connections, two of them
   reserved for `check`, `connect`/`disconnect` and deploy confirmation;
   deadlines per endpoint: 10 s by default, 35 s for `events?wait=30s`, 45 s
   for `check` (a full fresh check). Mutations carry a client-generated
   `request_id`; scupperd keeps the last 256 ids with their results for
   10 min and answers a repeat with the stored result instead of executing
   it again.

### API (all under `/v1`, `schema: 1` in every response)

| Method, path | CLI |
|---|---|
| `GET health` (no token; returns only `ok`: edge is alive, nothing more) | – |
| `GET ready` (200 only while scupperd is alive and its last verdict is 0 and < 30 s old; else 503 with the reason) | – |
| `GET status` | `status` |
| `GET check` (fresh probes run by scupperd; `503 supervisor_unavailable` if scupperd is dead) | `check` |
| `POST connect`, `POST disconnect` | `connect`, `disconnect` |
| `GET rules`, `GET rules?diff=1` | `rules` |
| `POST apply {dry_run}` | `apply` |
| `GET exits`, `GET exits/{id}`, `POST exits/{id}/use {mode: prefer\|pin}`, `POST exits/auto`, `POST exits/{id}/test` | `exit …` |
| `GET config`, `GET config/versions`, `GET config/versions/{n}`, `POST config {parent, toml, reason}`, `POST config/rollback {to}` (low-risk changes only, §8), `GET config/bundle` | `config …` |
| `GET events?since=&kind=&wait=30s` (long-poll) | `events` |
| `GET alerts`, `POST alerts/test {sink}` | `alerts …` |
| `GET metrics` (Prometheus text, token required) | – |
| `POST deploy/{id}/confirm` (accepted only while `pending.json` names that id; M6) | `deploy`, `upgrade` |

Secrets are never accepted or returned by any route. `exit add`/`import`,
`device add`/`remove`, token rotation and every other high-risk change are
local-socket operations; the CLI sends them over SSH by itself (it does not
try the API first), so they work the same from the Mac as long as
break-glass SSH works.

### CLI transport selection

`--via auto|local|api|ssh[=HOST]`, default `auto`: the local socket if
present, else the tunnel API (1 s connect timeout), else SSH to the
configured public address. Fallback to SSH happens **only when the API is
unavailable before the request was delivered** (connect failure, connect
timeout, `503 supervisor_unavailable`), **never on 401/403**. If a
mutation's response is lost after the request was sent, the CLI does not
replay it over SSH; it asks for the outcome by `request_id` (over SSH if
needed) and reports it. The CLI always reports the transport it used (stderr
line; `transport` field in `--json`).

---

## 11. CLI

Global flags: `--via`, `--json`, `--gateway ID`, `--quiet`, `--no-color`
(implied when stdout is not a TTY), `--yes`.

```
scupper                                 bare: short status summary with next-step hints
├── status [--watch]                    human overview; exit 0 if rendered, 1 if no transport works
├── check                               verdict = exit code (0-5, §12)
├── connect [EXIT]                      clear Disconnected (optionally prefer EXIT), wait ≤ 10 s for handshake + route;
│                                       0 on success, 3 if not ready in time
├── disconnect                          route unreachable, exits down, persisted; prints "traffic is now blocked"
│                                       only after verifying the closure in the kernel (§12)
├── rules [--diff]                      print the rendered ruleset; --diff against live
├── apply [--dry-run]                   converge to head config (atomic ruleset, ordered plan)
├── exit
│   ├── list                            "Name [id]", health, handshake age, RTT median/p95, failure rate (1 h), v6, position, active marker
│   ├── show EXIT                       adds probe and RTT history
│   ├── use [EXIT] [--pin]              prefer (failover allowed) or pin (fail closed if it dies)
│   ├── auto                            back to configured order
│   ├── test EXIT [--speed]             run probes now; --speed: bounded throughput test through that exit only
│   ├── add [FILE | - | --clipboard | --paste | --from REF] [--name N] [--id ID] [--position P]
│   │                                   from the Mac: parse a provider wg-quick file locally, upload the key over
│   │                                   SSH only, add the exit in a new version, verify, offer to delete FILE
│   ├── import FILE [--name N] [--id ID]  same, run on the gateway itself (file already there)
│   ├── rename EXIT NEW_NAME
│   ├── move EXIT --position P          change failover order
│   ├── enable EXIT | disable EXIT
│   └── remove EXIT                     delete the key file, new version; reminds to revoke at the provider
├── device
│   ├── list
│   ├── add ID --public-key KEY --address4 A [--address6 A] --token-sha256 HEX
│   └── remove ID
├── config
│   ├── show [--version N]
│   ├── edit                            $EDITOR on a temp copy; validate; commit
│   ├── set KEY VALUE
│   ├── load FILE [--reason TEXT]
│   ├── validate [FILE]
│   ├── history
│   ├── diff A [B]
│   ├── rollback N
│   ├── migrate
│   └── bundle [-o FILE]
├── events [--since DUR] [--kind K] [--follow]
├── alerts
│   ├── list
│   └── test [SINK]
├── dns status
├── repair status | clear [--reason TEXT]   show or clear the quarantine latch (§7)
├── install [--plan | --check] [--bundle FILE] [--uplink IF] [--exit-file FILE --exit-id ID]...
├── deploy <GATEWAY> | --host ADDR [--binary FILE] [--confirm-timeout DUR]   (from the Mac, §15)
├── upgrade [GATEWAY] [--version V]     fetch release + checksum, then deploy
├── gateway
│   └── create --provider digitalocean [--region R] [--size S] [--name N] [--token REF]
├── secret
│   ├── check REF                       resolve REF, print ok + value length only (never the value)
│   └── backends                        list built-in and command-defined schemes
├── version
├── completion SHELL
├── mac                                 (macOS builds only)
│   ├── join | leave | status
│   ├── trust add [--current] | trust rm NAME | trust list
│   ├── enroll --gateway HOST           generate device key + API token locally, register over SSH
│   ├── helper install | uninstall      root LaunchDaemon with root-owned tool copies (ADR 0030)
│   └── agent install | uninstall | run  per-user LaunchAgent
└── (hidden) boot | probe … --json | deliver …      used by units and scupperd
```

**Exit names.** Commands that take `EXIT` accept the `id` or the `name`,
case-insensitively (`zurich`, `Zurich`, `ch1`); on a TTY a unique prefix
also matches and an ambiguous one lists the candidates; without a TTY only
an exact id or name is accepted. Human output shows `Zurich [ch1]`; JSON,
events and metrics carry both `id` and `name`, and anything stored
(policy, events, metric labels) uses the immutable `id`, so a rename never
breaks history or dashboards.

**Adding an exit (`exit add`).** Run on the Mac. The provider's wg-quick
configuration can come from any of these sources; none requires saving it
to a file first:

| Source | How |
|---|---|
| `FILE` | a downloaded `.conf` |
| `--clipboard` | read the system clipboard directly (macOS pasteboard; Linux Wayland/X11 when available) |
| `--paste` | hidden paste prompt: terminal echo off, input ends at end-of-file (Ctrl-D) or after the `[Peer]` section is complete, so the key never appears on screen or in terminal scrollback |
| `-` | standard input, e.g. `pbpaste \| scupper exit add -` or from another tool |
| `--from REF` | a whole configuration stored in a secret store, e.g. `pass://VPN/ch-1234/config` |
| (none, on a TTY) | asks which source to use; offers the clipboard when it holds something that parses as a wg-quick configuration |

**Handling of the private key, whatever the source.** The configuration is
held only in memory (`Zeroizing` buffers, at most 16 KiB, larger input is
refused before parsing); it is never written to a temporary file, never
passed as a process argument, never logged, and never part of an error
message: parse errors name the section and key and replace any value of
`PrivateKey` or `PresharedKey` with `<redacted>`. The `Debug` output of the
parsed type redacts both fields too. When the source was the clipboard,
after a successful add the command offers to clear it, and clears it only
if the clipboard still holds the same content (compared by hash), so it never
wipes something copied in the meantime. It warns once that clipboard
history tools and Universal Clipboard (Handoff) may already have copied the
content to other places scupper cannot clear.

**Validation (pure parser, before anything is sent).** Exactly one
`[Interface]` and one `[Peer]`. `[Interface]`: `PrivateKey` (base64 that
decodes to exactly 32 bytes; the derived public key is shown as a
fingerprint so it can be matched with the provider dashboard), `Address`
(one IPv4 host address, at most one IPv6 host address), `DNS` (literal IPs
only); optional `MTU` within 1280-1500. `[Peer]`: `PublicKey` (32 bytes),
`Endpoint` (literal IP and port; a host name is refused, since the gateway
resolves nothing at boot), `AllowedIPs` exactly `0.0.0.0/0` and optionally
`::/0` (an exit must be able to carry everything), optional
`PersistentKeepalive`, optional `PresharedKey` (32 bytes, handled like the
private key). Refused: `PostUp`, `PreUp`, `PostDown`, `PreDown`, `Table`,
`SaveConfig`, `FwMark`, `ListenPort`, unknown keys, duplicate keys, a
second peer, and a private key or peer public key already used by another
configured exit. Provider comment lines (Proton writes the server name, e.g.
`CH#1234`) seed the suggested `id` (`ch-1234`) and `name` (the country,
editable), both validated against the id and name grammar before use;
NetShield level and IPv6 presence are shown. The summary shown for
confirmation never contains the private key.

**Transfer and activation.** The private key is sent **only over SSH** (as
a field of the `scupper remote` request on stdin, §10), never through the
API, never as a process argument; the gateway re-validates the whole
configuration with the same parser, writes the key to
`/etc/scupper/secrets/wg/exit-<id>` (0600, written to a temporary file in the
same directory, fsynced, then renamed) and creates the new config version
whose exit entry references it. The exit is then brought up (hot or cold per
position and `policy.standby`) and verified (handshake, route probe, exit
IP); if verification fails, the user is asked whether to keep the exit
disabled or remove it, and the key file goes with a removal. When the source
was a file, the command finally offers to delete it, since it holds a
private key. `exit remove` deletes the gateway key file and reminds the
operator to revoke the configuration in the provider dashboard (no provider
API in R1).

Tests: parser unit and property tests (every refused key, size limit,
duplicates, a private key never present in any `Display`, `Debug` or error
string for arbitrary inputs); the clipboard is behind a `Clipboard` trait
with a fake; the "clear only if unchanged" rule has a unit test; an
integration test checks that no file under the temp directory and no process
argument ever contains the key during `exit add`.

```
$ scupper exit add --clipboard
  Found: Proton CH#1234 · endpoint 203.0.113.10:51820 · NetShield 1 · IPv4 + IPv6
  Key fingerprint: public key k3Vq…9fQ= (compare with the provider dashboard)
  Name [Switzerland]: Zurich
  ID [ch-1234]:
  Position: 1) primary  2) standby  3) last   [3]: 2
  Upload key to gw1 over SSH and add as config v44? [Y/n]
  ✓ Zurich [ch-1234] added (v44), handshake 2s, exit IP verified
  The clipboard holds a private key. Clear it now? [Y/n]

$ scupper exit list
  POS  EXIT                    STATE     HANDSHAKE  EXIT IP          FAMILY
  1  * Zurich [ch-1234]        active    12s        203.0.113.77     v4+v6
  2    Amsterdam [nl-0042]     standby   18s        verified 2m ago  v4
```

Mutation commands return 0 when the operation completed, 1 on error.
`check` is the only health verdict. Human output is for reading; `--json`
is versioned (`schema`) and covered by golden tests.

```
$ scupper check; echo $?
protected: via ch1 (exit 203.0.113.77), kill switch in place
0

$ scupper status
gateway gw1 · config v43 applied · scupperd up 3d4h · via local
verdict      PROTECTED via ch1 (exit 203.0.113.77)
kill switch  netns scupper: wg0, ex-ch1, ex-nl1; ruleset = v43
exits      * ch1  healthy  handshake 41s  path ok 3s   exit-ip ok 22s  v4+v6
             nl1  healthy  handshake 18s  path ok 12s                  v4
selection    auto (ch1, nl1), failback manual, standby hot
client mac   handshake 12s, route v4 via ex-ch1, v6 via ex-ch1
dns          forwarder ok, upstream 10.2.0.1 via ex-ch1
alerts       phone ok, chat ok · heartbeat ok 14s ago
```

M1 implements exactly v1's six commands (`status check connect disconnect
rules apply`) and exit codes 0-4; `connect`/`disconnect` start and stop
`wg-quick@proton0` as v1 does.

### Interactive use: helpful, never required (M5 for the full set)

Rules:

| Rule | Behaviour |
|---|---|
| TTY detection | colour, tables, prompts, pickers and live redraw only when the relevant stream is a TTY; `NO_COLOR` and `--no-color` respected |
| Piped output | stable plain text (one record per line, tab-separated columns), no colour, no prompts |
| Machine output | `--json`, versioned by `schema`, never interactive |
| Flag equivalence | every interactive step has a flag equivalent; a fully flagged command never prompts |
| Confirmations | `--yes` skips them. **Without a TTY and without `--yes`, a command that needs confirmation refuses with exit 1** and says which flag to add; it never guesses |
| Exit codes | unaffected by interactivity; `check` never prompts |

Features:

| Feature | Detail |
|---|---|
| Bare `scupper` | short status summary (verdict, active exit, config version, transport) plus next-step hints, e.g. `not joined: run scupper mac join` |
| Pickers | a missing required argument on a TTY opens a filterable list: `exit use` (exits with health and handshake age), `exit show/test`, `config rollback` (versions with actor, time, reason), `config diff`, `alerts test`, `mac trust rm`. Without a TTY: usage error (1) |
| Confirmation with preview | `disconnect` ("all client traffic will be blocked until `scupper connect`"); `exit use --pin` ("if EXIT fails, traffic is blocked, no failover"); `config rollback N` (diff head → N); `apply` (config diff and ruleset diff, plan steps) |
| Guided `install` | detect interfaces and the uplink, propose values, import the provider file, show the plan, confirm. Same result as `install --uplink … --exit-file … --yes` |
| Guided `mac enroll`, `mac trust add --current` | show what will be generated or trusted (fingerprint), confirm |
| `config edit` loop | `$EDITOR` on a temp copy → validate → on error show it and reopen → show diff → confirm commit and apply |
| Live views | `status --watch` (redraws every 2 s on a TTY; prints one block per change when piped), `events --follow` (JSON Lines with `--json`) |
| Actionable errors | every error names the failed object and a suggested command, e.g. `key file /etc/scupper/secrets/wg/exit-ch1 has mode 0644; fix: chmod 600 /etc/scupper/secrets/wg/exit-ch1` |
| Completions and man pages | `scupper completion SHELL` with dynamic candidates for exit ids, device ids, sinks and config version numbers (from the local socket or API, with a 300 ms budget, falling back to static); man pages generated at build time |

Crates (chosen):

| Crate | Use | Why, and what was not chosen |
|---|---|---|
| `clap` (derive) + `clap_complete` | parsing, static and dynamic completions | one source of truth for the command tree |
| `clap_mangen` | man pages from the same definitions | no hand-maintained pages |
| `dialoguer` (with `fuzzy-select`) | prompts, confirmations, filterable pickers | synchronous like the CLI, small; `inquire` has richer widgets that are not needed |
| `anstream` + `anstyle` | TTY-aware colour that strips styling when piped | already in clap's tree, so no new dependency |
| `comfy-table` | tables on a TTY | handles widths and wrapping; piped output bypasses it |
| (none for progress) | `connect`/`apply` waits print one updating line on a TTY | `indicatif` not needed for waits of ≤ 10 s |

A full-screen TUI stays R2+.

---

## 12. Health model, verdicts, exit codes

### Exit codes (ADR 0009)

| Code | Meaning | Verdict | From |
|---|---|---|---|
| 0 | protected and connected, every stage verified | `Protected` | M1 |
| 1 | usage or internal error, or a required observation failed | (error) | M1 |
| 2 | **unprotected**: topology or ruleset differs from policy, or exit IP is an uplink address | `Unprotected` | M1 |
| 3 | degraded: path closed or unusable for availability reasons | `Degraded` | M1 |
| 4 | failing closed: no healthy exit, pinned exit down, admin disconnected, failover in progress | `FailClosed` | M1 |
| 5 | data path verified as for 0, but scupperd is not alive (no failover, repairs, alerts, heartbeat) | `Unsupervised` | M2 |

Scripts that page on any non-zero code page on 5; that is intended.

Ping publishes an active apply or rebuild with its source and target versions
and elapsed age. Check reports `Degraded::OperationInProgress` (3) during this
transition, including rollback, without comparing the kernel to the version
being published in state.json. This is an availability indication; no topology
verdict is asserted until the transition publishes its attached snapshot.
The initial Ping and Check (including one retry after SupervisorUnavailable)
share one absolute 5 s deadline established before the initial Ping. The Ping
itself is capped at 2 s; its elapsed time reduces the remaining Check budget.
After an explicit Check error, a fresh Ping receives its own fixed 500 ms
allowance, even when the shared deadline has expired. No Check retry starts
after that deadline. After a local violation, the transition Ping likewise gets
500 ms; namespace retries reuse that Ping deadline rather than renewing it.
The fallback bound is 5 s plus one local check, a second local check if a
namespace retry is needed (at most two local checks total), and at most 1 s for
these two Ping allowances.
Only a Check with no reply before its deadline retains the first Ping's age
for stage 8. Explicit refusal, EOF or SupervisorUnavailable uses a fresh Ping,
with an unavailable supervisor treated as Dead.

### Check order (severity, safety before availability; costly stages run only if earlier ones passed)

| Stage | Observation | Fails with |
|---|---|---|
| 1 | netns present with expected inode; links = configured set, all WireGuard; peers and AllowedIPs as configured; ruleset canonical-exact; RPDB = kernel defaults; tc = baseline only (§3) | 2 (`Violation`) |
| 2 | selection `Disconnected`: 4 `AdminDisconnected` only when the kernel shows the closure (both defaults `unreachable`, exit links down or without peers); otherwise 3 `DisconnectNotEffective` (the repair loop then tightens) | 4 / 3 |
| 3 | the **observed** default routes (not the failover machine's intent) are `unreachable` in both families; main table = default + kernel routes only | 4 `NoHealthyExit` / `PinnedExitDown`; intent unreachable but a kernel route via an exit, or an extra route → 3 `RouteWrong` |
| 3 | active exit handshake never/stale: if another enabled exit is fresh and the active has been stale for less than `failover_grace` (default 30 s, about 2× probe detection time), 4 `FailoverPending`; after that 3 `FailoverStuck`; if no exit is fresh, 4 `NoHealthyExit` | 4 / 3 |
| 4 | forwarding = 1 for v4 (and v6 if any client has v6); with the quarantine latch set, forwarding 0 is 4 `Quarantined`. Client side: `wg0` public key = its identity's `public_key`, listen port as configured, a host UDP socket bound to it (else 3 `ClientSideBroken`); stale client handshakes are a warning only (a Mac may be offline) | 3 / 4 |
| 5 | `ip -n scupper -j route get <dst4> from <client4> iif wg0` → `dev <active exit>`; v6 likewise → active exit, or `unreachable` when the active exit has no v6 | 3 |
| 6 | exit-IP probe through the route over v4 and, when the active exit is v6-capable, over v6; on failure, one bound path probe on a standby to classify `CommonModeProbeFailure` vs `ExitProbeFailed` | 3; exit IP ∈ uplink addresses → 2 |
| 7 | the DNS self-test (§7: cache-bypassing random label, UDP and TCP, each configured listener family) gets an upstream response, and edge's upstream generation equals scupperd's (M4+) | 3 |
| 8 | scupperd alive: control-socket `Ping` answered within 2 s with last complete iteration < 30 s ago (only if `require_daemon`, M2+) | 5 |

M1 order (v1 layout, v1 plus the exact comparison and a config
cross-check): whole host ruleset exact, no tc qdisc or filter beyond the
baseline on `wg0` or `proton0`, and the config matches the kernel (the
uplink is the device of the host default route, `exit_addr` is assigned to
`exit_iface`, `client_addr` lies inside `wg0`'s peer AllowedIPs; validation
refuses an interface name that does not exist) (2) → handshake fresh (4) → `ip route get 1.1.1.1 from 10.99.0.2 iif wg0` =
`dev proton0` (3) → exit probe bound to `proton0` (3).
In M1, tcx BPF links (kernel 6.6+) and other eBPF attachments without a
qdisc are not detected; `tc filter show` covers only root filters, and the
qdisc check is the guard for ingress/clsact.

Rules: an observation error is 1, never a safe code; a known violation wins
over an observation error. `Never` is not fresh; `Age(d)` is fresh iff
`d <= max_handshake_age`; `InFuture(d)` is fresh iff `d <= max_clock_skew`
and always adds `Warning::ClockSkew`, including beyond the skew bound,
where it is stale. `check` run locally performs every
stage itself; via the API, scupperd runs a fresh check. `status` may show
cached observations, always with their age.

`Warning::HardeningSysctl` includes a default forwarding sysctl that disagrees
with its corresponding global gate. This consistency warning applies when
the global gate is either open or closed. Hardening restoration failures do
not override a successfully verified forwarding-gate result; subsequent
observations retain the hardening drift for repair and warnings.

**Coverage.** A gateway `check` = 0 states that the gateway side works:
containment, the exit path, the gateway's DNS and the listening side of the
client tunnel. It cannot prove that a client reaches the gateway (a cloud
firewall can drop UDP 51820 before the host); that is shown by client
handshake ages, by the Mac's own checks (§14) and by deploy confirmation
(§15).

### Types

```rust
pub type Probe<T> = Result<T, ProbeError>;

pub enum Handshake { Never, At { unix_secs: u64 } }
pub enum HandshakeAge { Never, Age(Duration), InFuture(Duration) }
impl Handshake {
    /// Pure. Freshness rule (above): InFuture(d) is fresh only if d <= max_clock_skew,
    /// always with Warning::ClockSkew; beyond the bound it is stale.
    pub fn age_at(&self, now_unix_secs: u64) -> HandshakeAge;
}

pub enum RulesetObs { Exact, Missing, Differs { live: Sha256, want: Sha256 } }

pub struct TopologyObs {
    pub netns: NetnsObs,                       // Present { inode } | Missing | WrongInode
    pub links: Vec<LinkObs>,                   // name, kind, up, addresses
    pub peers: BTreeMap<Ifname, Vec<PeerObs>>, // public key, allowed ips, endpoint (no keys)
    pub ruleset: RulesetObs,
    pub extra_rules: Vec<String>,
    pub tc_hooks: Vec<Ifname>,
}

pub struct Observations {
    pub topology: Option<Probe<TopologyObs>>,
    pub selection: Selection,
    pub active: RouteTarget,
    pub handshakes: BTreeMap<ExitId, Handshake>,
    pub forwarding: Option<Probe<Forwarding>>,
    pub routes: Option<Vec<(ClientAddr, Probe<RouteAnswer>)>>,   // Dev(Ifname) | Unreachable
    pub exit_probe: Option<Probe<IpAddr>>,
    pub standby_probe: Option<Probe<()>>,
    pub dns: Option<Probe<()>>,
    pub supervisor: Option<Supervisor>,        // Alive { iteration_age } | Dead | NotRequired
}

/// Staging lives in the pure core: what to observe next, or the verdict.
pub enum Next { Topology, Handshakes, Forwarding, Routes, ExitProbe, StandbyProbe, Dns, Supervisor,
                Done(Result<Report, CheckError>) }
pub fn next(obs: &Observations, cfg: &HealthConfig, now: UnixTime) -> Next;

pub enum Verdict {
    Protected { exit: ExitId, exit_ip: IpAddr },
    Unprotected(NonEmpty<Violation>),
    Degraded(Degraded),
    FailClosed(FailClosed),
    Unsupervised { exit: ExitId, exit_ip: IpAddr, why: SupervisorFault },
}

pub enum Violation {
    NetnsMissing, NetnsWrongInode, ForeignLink(Ifname), LinkKind(Ifname),
    PeerDiffers { ifname: Ifname }, RulesetMissing, RulesetDiffers { live: Sha256, want: Sha256 },
    ExtraPolicyRule(String), TrafficControlHook(Ifname), ExitIpIsUplinkAddress(IpAddr),
    ConfigMismatch(String),                    // M1: config disagrees with the kernel
}
pub enum Degraded {
    FailoverStuck { exit: ExitId, fresh_standbys: Vec<ExitId> },
    ForwardingDisabled,
    RouteWrong { client: ClientAddr, got: RouteAnswer, want: RouteTarget },
    DisconnectNotEffective,
    OperationInProgress { from: u64, to: u64 }, // snapshot transition; no kernel comparison
    ClientSideBroken(ClientFault),             // wg0 key, listen port or host socket
    ExitProbeFailed(ProbeError),               // the probe ran and the path failed (not a local setup error)
    ExitProbeImplausible { ip: IpAddr },       // exit IP cannot be a public exit address
    CommonModeProbeFailure,
    DnsFailed(ProbeError),
}
pub enum FailClosed { AdminDisconnected, NoHealthyExit, PinnedExitDown(ExitId), FailoverPending { from: ExitId },
                      Quarantined { reason: RepairKind } }
pub enum Warning {
    StandbyUnhealthy(ExitId), ClockSkew, KeyFileMode(PathBuf), HardeningSysctl(String),
    HostForwardingOn, LegacyUnitEnabled(String), RepairSuppressed(RepairKind), DaemonDead,
    ClientHandshakesStale,
}
pub struct CheckError { pub stage: Stage, pub source: ProbeError }   // exit code 1

pub struct Report { pub verdict: Verdict, pub warnings: Vec<Warning>, pub at: UnixTime, pub config_version: u64 }

impl Verdict {
    pub const fn exit_code(&self) -> u8 {
        match self {
            Verdict::Protected { .. } => 0,
            Verdict::Unprotected(_) => 2,
            Verdict::Degraded(_) => 3,
            Verdict::FailClosed(_) => 4,
            Verdict::Unsupervised { .. } => 5,
        }
    }
}
```

The v1 verdict table ports 1:1 as tests; the bug-4 case (route via `eth0`,
bound probe succeeded) stays a named test.

---

## 13. Events, metrics, alerts, heartbeat

### Event log (ADR 0019)

- Append-only JSON Lines, `/var/lib/scupper/events/YYYY-MM.jsonl`, 0640
  `root:scupper-admin`, `fsync` per event. Retention: 13 months or 100 MB.
  journald holds operational logs; the event log is the audit record.
- Line: `{seq, at, kind, actor, gateway, config_version, data}`; `seq` is
  monotonic per gateway and persisted.
- Kinds: `ConfigCommitted{version,parent,sha,reason}`, `ConfigApplied`,
  `ApplyFailed`, `Failover{from,to,cause}`, `Failback`,
  `FailClosedStarted{reason}`, `FailClosedEnded{duration}`,
  `ExitHealthChanged`, `DriftDetected`, `Repair{kind,class,result}`,
  `RepairSuppressed`, `VerdictChanged{from,to}`, `AdminAction{command}`,
  `DaemonStarted{version}`, `Boot{result,step}`, `SinkFailed`,
  `HeartbeatFailed`, `PersistenceFailed`.
- `actor`: `Daemon | Local{uid} | Device{id,user} | Boot`.
- **Privacy by type:** no variant has a destination, domain or traffic field;
  a test serializes every variant and checks the field set.

### Metrics (edge `/metrics`, tunnel only, token required, M5)

`scupper_verdict{kind}`, `scupper_exit_up{exit}`, `scupper_exit_active{exit}`,
`scupper_exit_handshake_age_seconds{exit}`,
`scupper_exit_probe_latency_seconds{exit,probe}`,
`scupper_exit_bytes_total{exit,dir}`, `scupper_client_bytes_total{device,dir}`
(both from `wg show transfer`), `scupper_failovers_total`,
`scupper_fail_closed_seconds_total`, `scupper_repairs_total{kind}`,
`scupper_forward_dropped_packets_total`, `scupper_dns_queries_total{result}`,
`scupper_alerts_total{sink,result}`, `scupper_heartbeat_last_success_timestamp`,
`scupper_observation_age_seconds`, `scupper_supervisor_up`,
`scupper_exit_rtt_seconds{exit}` (summary: median, p95),
`scupper_exit_probe_failures_total{exit,probe}`.
Labels are bounded (exit, device, kind); never destinations (I5).

Freshness: edge serves the verdict it last received from scupperd together
with its age. After 30 s without a fresh one it reports
`scupper_verdict{kind="unknown"}` and `scupper_supervisor_up 0`; a stale
healthy verdict is never exported as current. `GET /v1/health` means only
"edge is alive"; readiness is `GET /v1/ready` (§10).

### Alert sinks (R1 set)

| Sink | Transport |
|---|---|
| `ntfy` | HTTPS POST; ntfy's email forwarding covers email |
| `webhook` | HTTPS POST JSON, presets `telegram`, `pushover`, `generic` (template per preset) |
| Prometheus | scraped from `/metrics` |
| macOS notification | posted locally by the Mac agent (§14), not pushed by the gateway |

No native SMTP sink.

```rust
pub struct Alert {
    pub key: AlertKey,          // FailClosed, Failover, Unprotected, RepairSuppressed, ...
    pub severity: Severity,     // Info | Warning | Critical
    pub state: AlertState,      // Firing | Resolved
    pub seq: u64,               // event that produced it
    pub title: String,
    pub body: String,           // built from typed fields only
}
pub trait AlertSink: Send {
    fn name(&self) -> &str;
    fn deliver(&self, alert: &Alert) -> Result<(), SinkError>;  // runs a `scupper deliver` child, bounded
}
pub enum SinkError { Transient(String), Permanent(String) }
```

**Delivery** (ADR 0018): alerts are derived from events already fsynced.
Each sink has a cursor file `/var/lib/scupper/sinks/<name>.cursor`; a worker
thread with exponential backoff (5 s → 15 min, give up after 24 h with
`SinkFailed`). **At least once per sink, in order; duplicates possible after a
crash.** Delivery goes out of the **host namespace via the uplink**, so the
most important alert (all exits down) can be delivered when it matters. It
carries no client data. Rate limits: same `key` coalesces for 10 min (one
Firing, then one Resolved with duration and count); per-sink token bucket
(burst 5, refill 1 per 5 min); `Critical` bypasses coalescing but not the
bucket; suppressed alerts are summarized in the next delivered one.

### External heartbeat (dead-man switch), M2

Covers "the gateway (or scupperd) is dead", which no on-host alert can.

- Every `heartbeat.interval` (default 60 s; validated range 10 s to 1 h), after a complete iteration that ran a
  full check (all stages, fresh), scupperd starts a `scupper deliver
  heartbeat` child that requests the configured URL via the uplink.
- Only healthchecks-compatible services are supported (`kind =
  "healthchecks"`): the service must alert when pings stop and must
  interpret `/<code>`. ntfy and plain webhooks have no dead-man behaviour
  and are rejected for the heartbeat.
- `report = "ok_only"` (default): ping **only** when the verdict is 0; otherwise send
  nothing (healthchecks-style services alert when pings stop).
  `report = "status_code"`: append the exit code (`<url>/<code>`, the
  healthchecks convention, where 0 = success and non-zero = failure).
- Truthful (I3): the ping is derived from a verdict at most one interval old;
  a dead or hung scupperd sends nothing because the watchdog-gated
  iteration never completes. Each delivery child gets a deadline (verdict
  start + min(30 s, interval), monotonic) and exits without sending once it
  has passed. Sockets use SO_LINGER(0) and TCP_USER_TIMEOUT equal to the
  remaining deadline, refreshed before each socket operation. TCP_USER_TIMEOUT
  does not shorten the first retransmission or tail-loss probe. Before every
  socket write the child reads the current TCP_INFO.tcpi_rto (via the safe
  SOCK_DIAG interface) and requires more than RTO + 1 s remaining, and at least
  2 s. Closing or killing the child discards unacknowledged bytes. The child
  arms its own SIGKILL timer independently of the parent's process-group kill;
  while SIGSTOPped, the socket's kernel timeout still runs. Code 5 is never
  sent (scupperd is the sender). Coverage is the gateway-side verdict
  (§12).
- The URL is a secret ref (it identifies the check). Failures are retried
  once, then `HeartbeatFailed` (warning); the external service's own alert
  is the safety net.

M2 implementation deviations: a separate fresh check thread runs concurrently
with the reconciler (an exception to ADR 0004's single synchronous reconciler;
the thread observes only and never persists intent). Verdict time is the check's
start, the oldest observation it can use; checks taking 20 s or longer are
ineligible, including after SIGSTOP/resume. The next check is scheduled from the
last send attempt, so attempts, including failures, are throttled by the interval;
a check rejected for health is also throttled. Retries retain the original
deadline. Stuck checks after 40 s and deliveries 10 s past their deadline emit
`HeartbeatFailed` and release their receiver, permitting another cycle. Before
rebuild or apply, check workers get at most 50 ms to finish. A stuck read-only
worker is detached and its receiver closed; its late verdict cannot authorize a
send or veto repair. Each detachment emits `HeartbeatCheckDetached`. Completion
handles remain tracked until exit; at most four detached checks may remain live.
While that cap is occupied, no new heartbeat check starts, and each due attempt
emits `HeartbeatSkipped` with reason `HeartbeatWorkerLimit` (at most once per
configured interval). The drain runs before the scheduler charges the boot attempt.
Healthy verdicts rejected as stale emit the informational `HeartbeatSkipped`
event with reason `Stale`, at most once per minute.

Delivery uses HTTPS GET rather than HEAD. Child exit codes are 20 (HTTP
non-2xx or malformed response), 21 (deadline/timeout), 22 (internal/protocol),
23 (identity), 24 (other TLS protocol failure), 25 (network transport), 26 (exec),
27 (secret), 28 (TCP_INFO/RTO read failure), 29 (write refused by deadline/RTO
rule), 30 (connection reset) and 31 (certificate/verification failure); 0 is
success. Events and daemon stderr preserve these value-free failure categories.
Status includes `heartbeat_last_success_age`. URL secret files accept exactly
one trailing newline, with no other whitespace trimming. Before reading any
secret stdin bytes, the child disables core dumps, sets NoNewPrivs and becomes
NotDumpable. After parsing the request and rejecting expired jobs, it checks all
real/effective/saved/filesystem IDs through Linux procfs (the safe getresuid/getresgid equivalent available here),
empty supplementary groups, empty inheritable/permitted/effective/ambient
capability sets and NoNewPrivs. Its inherited capability bounding mask can remain
nonzero; NoNewPrivs and the empty live sets prevent regaining those capabilities.

Explicit M2 non-goal: scupper does not restrict the host network namespace.
`scupper-alert` can reach the uplink, loopback and host services like any host
process. Endpoint confinement is a property of the child implementation, not a
host firewall sandbox. The child receives only a root-owned URL and sends no
client data. The lab's dedicated endpoint tuple is not targeted by client flows;
its tuple-only oracle allowance is cross-checked with an established socket
owned by the locally allocated `scupper-alert` uid in L53/L53b.

The absolute CLOCK_MONOTONIC deadline assumes parent and child share a time
namespace. It does not advance during system suspend; wall-clock freshness over
suspend remains a documented M2 limitation. Linux kernel transmission deadlines
bound locally queued work; they cannot recall packets already in the network.

Lab deviations: L53 completes a TLS handshake before dropping the encrypted GET,
then kills the parent and proves the child is alive near its deadline and exits
by deadline +1 s. L53b stops that child near its deadline, proves it remains alive
past it, removes the drop, and checks all outbound TCP payload timestamps for
late retransmissions while the child is still stopped. Quiet windows cover at
least three minimum intervals and check both ClientHello counts and parent
launch traces, with healthy cadence controls. The testing build injects code 3
and code 5 to exercise positive status suffix and suppression controls; parent
traces describe launch decisions, while the resolve unit test covers the actual
GET path suffix. Only testing builds accept the disposable local TLS CA and
handshake pause fixture. Whole-run lab deadline is 1900 s (formerly 1600 s), and
the four CI shards allow 30 min (formerly 25 min) including setup slack.

---

## 14. Mac client (ADR 0021)

All Mac logic is exec-based (`wg-quick`, `pfctl`, `route`, `arp`,
`launchctl`, `osascript`) in `scupper-mac`; rendering is pure in
`scupper-core`. No FFI, no unsafe code.

### Tunnel

**Privileged pieces are root-owned (ADR 0030).** The root helper never
executes anything from the Homebrew prefix, which the installing account
can write. `scupper mac helper install` copies the helper binary and the
tools it runs (`wg`, `wireguard-go`, `wg-quick` and the `bash` it needs)
into `/Library/Application Support/net.scupper/bin/` (root:wheel, 0755,
every parent root-owned and not group- or world-writable) and records their
sha256. The helper runs them by absolute path with `PATH` set to that
directory plus `/usr/bin:/bin:/usr/sbin:/sbin` and an otherwise empty
environment, and refuses to start if a recorded hash or an ownership check
fails. Re-running `helper install` after a Homebrew upgrade refreshes the
copies. The helper takes typed commands (join, leave, status) from the user
agent over a root-owned local socket and never parses HTTP or JSON from the
gateway.

`wg-quick` with `/Library/Application Support/net.scupper/etc/scupper0.conf`
(root, directory 0700):
`Address = 10.99.0.2/32, fd00:99::2/128`, `DNS = 10.99.0.1`,
`AllowedIPs = 0.0.0.0/0, ::/0`, `Endpoint = <gateway public address>:51820`.
wg-quick installs an endpoint host route via the physical interface, which is
what keeps break-glass SSH to the public address working while joined.

### Join / leave

`join`:
1. Persist the join intent (`/Library/Application Support/net.scupper/state/joined`,
   root). Load the anchor in **pre-tunnel** form (block all except UDP to
   the endpoint, TCP 22 to the endpoint address, DHCP/DHCPv6, NDP).
2. Flush pre-existing pf states (`pfctl -F states`, documented as "existing
   connections are reset when you join").
3. Verify the whole evaluation path: pf enabled (`pfctl -s info`); the main
   ruleset still contains `anchor "com.apple/*"` and no earlier `quick`
   rule that could match first; no `skip` flag on `en*` or `utun*`
   (`pfctl -s Interfaces -v`); `pfctl -a com.apple/scupper -sr` matches the
   rendered anchor.
4. `wg-quick up scupper0`; read the utun name from
   `/var/run/wireguard/scupper0.name`.
5. Load the joined anchor (adds the utun pass rules); verify again.
6. Report joined only after step 5 and a fresh handshake.

`leave` (explicit user action only): `wg-quick down`, flush the anchor,
release the pf enable reference (`pfctl -X <token>`, never `pfctl -d`),
remove the join intent. A crash, a lost gateway or a dead provider is
**never** treated as a leave.

While joined the helper re-verifies the whole evaluation path every 5 s and
compares the anchor's utun with `/var/run/wireguard/scupper0.name` and the
running `wireguard-go`. On any difference it loads the pre-tunnel anchor at
once, flushes all states (connections admitted while protection was missing
must not survive its restoration) and joins again. **At boot**, if the join
intent is persisted, the helper (`RunAtLoad`) loads the pre-tunnel anchor
before anything else and then joins; traffic before launchd starts the
helper is not protected (V-05 measures this window).

### pf anchor (`com.apple/scupper`, reached by the stock `anchor "com.apple/*"`; `/etc/pf.conf` is never edited)

```pf
# scupper kill switch, rendered for utun6, physical interfaces { en0 },
# gateway 198.51.100.7, DHCP server 192.0.2.1 (from the current lease)
pass quick on lo0 all
pass out quick on utun6 all keep state (if-bound)
pass in  quick on utun6 all keep state (if-bound)
pass out quick on { en0 } proto udp from any to 198.51.100.7 port 51820 keep state (if-bound)
pass out quick on { en0 } proto tcp from any to 198.51.100.7 port 22 keep state (if-bound)   # break-glass SSH only
pass out quick on { en0 } inet proto udp from any port 68 to { 255.255.255.255, 192.0.2.1 } port 67 keep state (if-bound)
pass in  quick on { en0 } inet proto udp from any port 67 to any port 68
pass out quick on { en0 } inet6 proto udp from fe80::/10 port 546 to ff02::1:2 port 547 keep state (if-bound)
pass in  quick on { en0 } inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546
pass out quick on { en0 } inet6 proto ipv6-icmp icmp6-type { routersol, neighbrsol, neighbradv } keep state (if-bound)
pass in  quick on { en0 } inet6 proto ipv6-icmp icmp6-type { routeradv, neighbrsol, neighbradv }
block drop quick all
```

- States are **interface-bound** (`if-bound`, V-20): a connection admitted
  through the tunnel cannot continue on a physical interface after a route
  change, an anchor loss or a utun-number reuse.
- DHCP and DHCPv6 passes are limited to the physical interfaces and to the
  broadcast address, the lease's server and the DHCPv6 multicast group, so
  they cannot carry traffic to arbitrary hosts (V-21). The anchor is
  re-rendered when the set of physical interfaces or the lease server
  changes.
- **No DNS to the local network while joined:** nothing on a physical
  interface passes except the lines above, so ports 53, 853 and 5353 to LAN
  addresses (a DHCP-supplied resolver, mDNS) are blocked. With `lan_access`
  this stays true (below).

pf is enabled with `pfctl -E`, the reference token stored in
`/var/run/scupper/pf.token`. LAN access (printers, AirDrop) is blocked while
joined. `lan_access = true` (off by default) adds a pass for the directly
connected IPv4 subnet only if it lies inside RFC 1918 or link-local space
and is no larger than /16, plus IPv6 link-local; explicit `block drop quick`
rules for TCP and UDP ports 53, 853 and 5353 to those addresses are rendered
before the LAN pass, so a hostile network cannot receive DNS through it.
While joined, the helper checks `scutil --dns` and re-asserts the tunnel
resolver if the system resolver is not `10.99.0.1`. There is no R1
captive-portal bypass.

### Auto-join (ADR 0021)

The per-user LaunchAgent `net.scupper.agent` (`scupper mac agent run`)
watches `route -n monitor`,
debounces 2 s and fingerprints the network as (interface, default gateway
IP, gateway MAC from `arp`); SSIDs are not used (recent macOS hides them
without location permission). Policy: **untrusted → join; trusted → nothing.**
The trusted list is **empty by default**; unknown or unreadable networks are
untrusted. There is **no auto-leave** in R1: the fingerprint is a
convenience hint, not an authenticated network identity, and a spoofed
router (same gateway IP and MAC) must never be able to remove protection.
The same spoofing can make an untrusted network look trusted and so prevent
an auto-join; that is why the trusted list is empty by default and staying
joined everywhere is the recommended mode. The agent can ask the helper to
join; it asks it to leave only on an explicit user command.
Auto-join is not zero-gap: traffic between a network change and the join is
not protected unless the Mac stays joined.

### Notifications

The user agent posts notifications (`osascript -e 'display notification …'`) for:
joined/left; **gateway unreachable** (client handshake stale > 3 min while
joined: "gateway unreachable, traffic blocked"; when the API or SSH still
answers, the notification adds the gateway's own view, e.g. "gateway
healthy, no client handshake: check the cloud firewall for UDP 51820"); gateway events of severity ≥
warning (from `GET /v1/events?wait=30s`); failover.

### Enrolment and local files

`scupper mac enroll --gateway HOST` generates the device WireGuard key
(`wg genkey`) and a 32-byte API token **on the Mac**, then over SSH runs
`scupper device add …` with the public key and the token's sha256 (a new
config version). Token: `~/.config/scupper/token` (0600, user; any process
of that user can read it, which ADR 0029 bounds); key: inside
`scupper0.conf` (0600 root, root-owned directory). After each `ConfigCommitted` event the agent
saves `GET /v1/config/bundle` to `~/.config/scupper/bundles/` (keeps 10).

### Mac test matrix (reduced, external capture)

join/leave; sleep/wake; Wi-Fi change; Ethernet plug-in; `wg-quick` process
death; agent death; helper death; reboot with a persisted join; pf reload by
macOS (firewall toggle, Internet Sharing); OS update; DHCP option 121
routes more specific than wg-quick's /1 routes (TunnelVision); DHCP DNS
change after a network change; a hostile RA with a Route Information
Option; established TCP and UDP flows across route deletion, sleep/wake,
anchor loss and utun-number reuse. Each case is checked with a capture on a
machine outside the Mac against pass conditions written down beforehand:
what may appear (UDP to the gateway endpoint, TCP 22 to it, DHCP and ND on
the local link) and that nothing else does.

---

## 15. Install, boot, upgrades, migration, rebuild

A manual boot defers only to an initialized supervisor holding the currently
named namespace. If a local CLI writer holds the lease, boot fails; wait for
that writer, or stop scupperd before rerunning after a stale namespace refusal.


### `scupper install` (basic in M2, hardened in M6)

Idempotent and plan-based: `--plan` prints steps, `--check` exits non-zero
on any drift, no flag applies. It never touches `eth0`, sshd, the host
firewall or host sysctls (except the optional `90-scupper.conf`).

1. Preflight: Ubuntu ≥ 22.04 or Debian ≥ 12, kernel ≥ 5.15, x86_64 or arm64,
   root; no foreign netns named `scupper`; **refuse** (exit 1, no override
   in R1) a host with the v1 layout or anything like it: an enabled
   `wg-quick@*` unit, a host link with a configured link name, `table inet
   scupper` in the host ruleset, or a v1 binary at `/usr/local/bin/scupper`
   (ADR 0014 enforced in code); warn if a host firewall (ufw,
   cloud firewall rules visible locally) would block UDP 51820 or exit UDP
   (availability, V-13).
2. Packages: `wireguard-tools nftables iproute2 conntrack`.
3. Users `scupper-edge`, `scupper-probe`, `scupper-alert`; group
   `scupper-admin`; directories and modes.
4. Binaries to `/usr/local/bin` (temp + rename).
5. Config: from `--bundle FILE` (verify `MANIFEST`, restore versions, head,
   selection) or an initial version from flags.
6. Secrets: generate `wg0` if missing and no version in the store names a
   public key for it (new client-facing identity; prints its public key);
   if the store already names one, a missing key file is an error, so a
   re-run never silently changes the client-facing identity or use a file the operator placed; `exit import` per provider
   file; tell the operator to delete downloaded provider files.
7. Units, `systemctl enable --now scupper-net scupperd scupper-edge`.
8. `scupper check`; print the Mac's `scupper0.conf` peer section.

### Units

```ini
# scupper-net.service
[Unit]
Description=scupper data-path namespace
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target scupperd.service scupper-edge.service
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/scupper boot
# no ExecStop: stopping the unit never tears protection down
[Install]
WantedBy=multi-user.target
```

| Unit | Dependencies | Other |
|---|---|---|
| `scupperd.service` | `Wants=` + `After=scupper-net.service network-online.target`; `Upholds=scupper-edge.service` | `Type=notify`, `WatchdogSec=30`, `Restart=always`, `RestartSec=2s`, `StartLimitIntervalSec=0`, `TimeoutStartSec=90` (covers the bounded 60 s wait for the supervisor lease at start), `LimitCORE=0` (inherited by probe and delivery children). scupperd holds a lifetime supervisor lease (`/run/scupper/scupperd.lock`); while it is held, `scupper boot` (and so a manual `systemctl restart scupper-net`) runs no kernel steps and exits 0 with a notice that scupperd owns the namespace, and the CLI never falls back to local mutation. Deliberately `Wants=`, not `Requires=`: if boot failed, scupperd must still start to alert and to retry the boot procedure under its repair budget (which is the same ordered, closed procedure). |
| `scupper-edge.service` | `Requires=` + `BindsTo=` + `After=scupper-net.service` | `NetworkNamespacePath=/run/netns/scupper`, `User=scupper-edge`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `TemporaryFileSystem=/run`, `BindPaths=/run/scupper/edge.sock`, `LimitCORE=0`, `WatchdogSec=30`, `Restart=always`. A failed namespace unit prevents edge from starting; after a rebuild scupperd restarts edge, and every tick it checks that edge runs in the held namespace (§7). |

### `scupper boot` (stops at the first failure; every prefix is closed)

0. Take the writer lock (ADR 0028).
1. If `/run/netns/scupper` exists and holds our links: adopt (verify only).
   Else `ip netns add scupper`; `lo` up.
2. In the namespace: forwarding 0 (v4, v6); all hardening sysctls (§5.4);
   read back.
3. `nft -c -f` then `nft -f` the rendered ruleset of `applied_version`;
   verify the canonical fingerprint.
4. Per WireGuard link: a leftover host link of that name is deleted if it is
   positively ours (kind `wireguard`, down, no peers); any other host link
   with that name stops the boot (closed). `ip link add <if> type wireguard`
   in the host (down),
   `ip link set <if> netns scupper`, `wg set` from secret files, addresses,
   per-link sysctls, `ip link set <if> up`.
5. Routes for the persisted selection: first candidate exit (packets wait
   inside WireGuard until the first handshake) or `unreachable`.
6. Forwarding 1 unless latched or Disconnected; re-apply hardening; read back.
7. Write `/run/scupper/boot.json` (step results); scupperd logs `Boot`.

Requirement "ruleset before forwarding" is met inside the namespace by
steps 2-6. The host `ip_forward` is irrelevant to the client path. The v1
networkd drop-in is not needed in the netns layout (networkd cannot see the
namespace) and is harmless if present.

### Upgrades

Binary swap (temp + rename, keep the previous binary), `systemctl restart
scupperd scupper-edge`. A scupperd restart does not touch the data path (it
adopts links and routes, never recreates them); an edge restart is a DNS gap
of about 1 s. From the Mac this is driven by `scupper deploy` /
`scupper upgrade` below.

### `scupper deploy`: confirm-or-rollback (ADR 0026)

`scupper deploy <gateway> | --host ADDR [--binary FILE] [--yes] [--confirm-timeout 3m]`,
run on the Mac. All gateway steps go over break-glass SSH to the public
address, so a broken tunnel never blocks deploying or rolling back.

| Step | Where | Action |
|---|---|---|
| 1 | Mac | `uname -m` over SSH; select the matching artefact (x86_64 or aarch64 Linux musl) |
| 2 | gateway | copy the release archive (all binaries, unit files and a `MANIFEST` of every installed file with its sha256) to `/usr/local/lib/scupper/deploy/<id>/new/`, verify against the release `SHA256SUMS` (or the local build's sum) |
| 3 | gateway | staged binary runs `install --plan`; Mac shows the plan and the config diff; confirm unless `--yes` (without a TTY and without `--yes`: refuse, exit 1) |
| 4 | gateway | take the deploy lock (ADR 0028; a second deploy is refused while one is pending); snapshot every file the plan touches (binaries, units, sysctl.d, state files) and the current rollback executor into `/usr/local/lib/scupper/deploy/<id>/prev/`; record `/var/lib/scupper/deploy/<id>/pending.json` `{schema: 1, id, phase: "pending", deadline_mono, boot_id, prev_applied_version, revocations: []}` (fsync file and directory); **arm the rollback timer** (below) |
| 5 | gateway | switch: move the new files into place, run `install`, `systemctl daemon-reload`, restart in order `scupper-net` (only if its unit changed; the boot procedure adopts the namespace), `scupperd`, `scupper-edge` |
| 6 | Mac | rejoin if needed; run `scupper check --via api` **and** the Mac's own checks, which do not ask the gateway: an HTTPS exit-IP lookup through the tunnel that must differ from the gateway's public address and from the Mac's own uplink address, and a resolution of a random name through `10.99.0.1` over UDP and TCP (v6 too for v6 clients). Only when both pass does it send `POST /v1/deploy/{id}/confirm` |
| 7 | gateway | confirm, under the deploy lock: if the phase is still `pending`, set it to `confirmed` (durable), then disarm the timer and emit `DeployConfirmed`; if a rollback executor has already set `rolling-back`, the confirmation is refused. Timeout: the gateway rolls back by itself and emits `DeployRolledBack` |

**While a deploy is pending**, config commits are refused
(`409 deploy_pending`) except revocations (`device remove`, token rotation,
`exit disable`, `exit remove`). Those are recorded in `pending.json` and
re-applied on top of the rollback target, so a rollback never restores
access revoked during the window.

**Rollback timer.** Armed with `systemd-run --on-active=<timeout>
--unit=scupper-deploy-rollback-<id>` running
`/usr/local/lib/scupper/deploy/<id>/prev/scupper deploy-rollback <id>` (the previous binary from the snapshot), so it is owned by
systemd and survives any crash of scupperd or edge. A reboot while a
deploy is pending is covered by `scupper-deploy-guard.service` (oneshot,
`Before=scupper-net.service`, `TimeoutStartSec=60`, runs the *previous*
rollback executor from the deploy directory): if a deploy is still
`pending` (its `boot_id` is not the current one), it **always rolls back**
before the boot procedure, because elapsed time across a reboot is not
known reliably; it never starts scupperd itself (scupper-net and scupperd
follow by their normal ordering). The rollback executor is always the
previous binary, never the one under test, and reads only a deliberately
small, stable input (`pending.json` schema 1 and the snapshot directory)
that later releases may not change incompatibly.

**Rollback procedure (fail-closed at every step):**
1. Stop `scupperd` and `scupper-edge`. The data path is kernel state and
   unchanged (I2); DNS pauses (closed).
2. Under the writer and deploy locks, re-check that the deploy id is the
   recorded one and its phase is `pending`; set `rolling-back` (durable);
   restore every file from `deploy/<id>/prev/` (binaries, units, sysctl.d,
   state files); `systemctl daemon-reload`. State-file migrations made by a
   new release write new files, never in place, so the snapshot restores the
   previous state exactly.
3. Commit a new config version with the content of `prev_applied_version`
   plus the revocations recorded during the window (actor
   `DeployRollback`), as `config rollback` does.
4. Start `scupperd`; it converges with the ordered planner (every prefix
   safe); a ruleset change goes through forwarding 0 → load → verify →
   forwarding 1 unless latched or Disconnected, so a failed load stays closed.
5. Start edge; emit `DeployRolledBack{id, reason}`; alert.
A failure at any step leaves the gateway closed and alerting; the heartbeat
reflects the verdict. A first deploy to a fresh host (nothing to roll back
to) skips steps 4 and 7 and says so.

`scupper upgrade [<gateway>] [--version V]`: download the release artefact
and `SHA256SUMS` over HTTPS, verify, then the same deploy flow. On the Mac
itself, upgrades go through Homebrew.

In M2, `deploy --host ADDR` exists without the rollback timer (steps 1-3
and 5): enough for the migration to a fresh host, where the old host is the
rollback. Confirm-or-rollback, `upgrade` and the guard unit arrive in M6.

### `scupper gateway create` (ADR 0027)

`scupper gateway create --provider digitalocean [--region R] [--size S] [--name N] [--yes]`,
run on the Mac:
1. Resolve the cloud API token from `--token REF` (an operator-side secret
   reference, §8: `pass://…`, `keychain:…`, `env:VAR`, `file:PATH`, or any command-defined backend), default
   `env:DIGITALOCEAN_TOKEN` if set, else a hidden prompt on a TTY, else
   refuse (exit 1).
2. Ensure the Mac's SSH public key is registered with the account; generate
   a bootstrap SSH host key pair for this VM on the Mac; create the VM
   (Ubuntu 24.04) with that client key, the bootstrap host key in the
   cloud-init user data (sent over the authenticated cloud API) and a
   creation tag `scupper-run-<random>`; poll until active; read its public
   IPv4.
3. Connect with the bootstrap host key pinned (no trust on first use). The
   first remote operation makes the VM generate new host keys, returns
   their public halves over this authenticated session and deletes the
   bootstrap key and the local copy of the user data; the Mac pins the new
   keys and wipes the bootstrap private key. The cloud metadata service
   keeps serving the user data for the VM's lifetime, which is why the
   bootstrap key is replaced before anything else. No secret is uploaded
   before this step completes.
4. Run `scupper deploy --host <address>` and the guided `install` (or
   `install --bundle` for a rebuild).
5. Print the next step (`scupper mac enroll --gateway <address>`).

Token rules (I6 applies to it as to keys): resolved through
`SecretResolver` (§8); never written to config, events, logs, bundles or the
gateway; never in argv of child processes; held in a `Zeroizing` buffer;
redacted from errors and debug output. It is used only on the Mac, only for
the duration of the command.

Token scope and deletion: the documentation asks for a custom-scoped token
that can create and read droplets, SSH keys and tags but cannot delete
(exact scope names: V-27). `delete_host` deletes only a host that carries
this invocation's creation tag and was created by this invocation, and never
a host whose address equals any configured `gateways.*.endpoint`; without a
delete scope a failed create prints the host to delete by hand. The token
variable and any other credential variables are removed from the
environment of every child process (ssh, deploy, secret backends).

```rust
pub trait CloudProvider {
    fn ensure_ssh_key(&self, public_key: &SshPublicKey) -> Result<SshKeyId, CloudError>;
    fn create_host(&self, req: &HostRequest) -> Result<HostId, CloudError>;   // name, region, size, image, key
    fn wait_ready(&self, id: &HostId, timeout: Duration) -> Result<HostInfo, CloudError>; // public addresses
    fn delete_host(&self, id: &HostId) -> Result<(), CloudError>;            // only hosts tagged by this invocation
}
```

R1 implements `digitalocean` (HTTPS JSON API via `ureq`, base URL
injectable). Tests run it against a local fake API server, so no real token
is needed in development or CI. Other clouds fit behind the trait; a
Terraform example stays R2+.

### Distribution

| Artefact | Target |
|---|---|
| `scupper-<version>-x86_64-unknown-linux-musl.tar.gz` | gateway: `scupper`, `scupperd`, `scupper-edge`, unit files, `MANIFEST` |
| `scupper-<version>-aarch64-unknown-linux-musl.tar.gz` | gateway, same contents |
| `scupper-<version>-aarch64-apple-darwin.tar.gz` | Mac (built on a macOS runner) |
| `SHA256SUMS` | all of the above |

- **Linux install script** (`install.sh` in the repository and release):
  detects the architecture, downloads the artefact and `SHA256SUMS` over
  HTTPS, verifies the sum, installs the binaries to `/usr/local/bin/`, prints
  `scupper install` as the next step. It changes nothing else.
- **Homebrew tap** for the Mac: `brew tap <org>/scupper && brew install scupper`,
  then `scupper mac enroll --gateway <address>`. The formula pins the
  artefact's sha256.
- Checksums detect corruption, not a compromised release host; signing is
  R2.

### Migration from the v1 layout: a fresh host (ADR 0014)

The live v1 gateway is never converted in place.

1. Create a second small cloud VM; `scupper install` there with a new `wg0`
   identity and new provider configs (`exit import`).
2. **Provider sessions:** during the overlap the old gateway's exit and the
   new gateway's exits all count against the provider's session limit. If
   the limit would be exceeded, start the new gateway with `standby = "cold"`
   or one exit until the old one is retired.
3. `scupper mac enroll --gateway <new address>`; add a second Mac profile
   for the new gateway; join it; `scupper check` = 0; run the M2
   acceptance tests (host `ip rule flush`: no effect; `ip -n scupper route
   del default`: 3, then repaired).
4. Rollback = join the old profile again. Keep the old VM about one week,
   then delete it and its provider configs; remove the v1 renderer and
   golden once no v1-layout gateway remains.

This is also the first exercise of the rebuild runbook.

### Gateway rebuild runbook (target: about 10 minutes)

Preconditions: a recent bundle on the Mac (agent copy, or
`scupper config bundle`), the provider dashboard reachable, the cloud
console reachable.

| Step | Action | Time |
|---|---|---|
| 1 | `scupper gateway create --provider digitalocean` (or create a VM with Ubuntu 24.04 and the SSH key by hand) | 2 min |
| 2 | Copy the release binary; `scupper install --plan --bundle bundle.tar` | 1 min |
| 3 | Secrets: generate new provider configs and `exit import` them (or restore key files the operator backed up out of band); generate a new `wg0` identity by default | 3 min |
| 4 | `scupper install --bundle bundle.tar` | 1 min |
| 5 | Mac: update the profile's endpoint (and peer public key if `wg0` is new): `scupper mac enroll --gateway <new address>` re-registers the device | 2 min |
| 6 | Join; `scupper check` = 0; delete the dead VM and revoke its provider configs | 1 min |

Rebuild is tested: M2 performs it for real (the migration), M6 adds a timed
VM rehearsal in CI.

---

## 16. R2+ extension points

| Area | Hook in R1 |
|---|---|
| Several clients, people, router peers | `devices`, `users`, `groups` in the model; per-device addresses and tokens; `antispoof` sets; `client_ifaces` set |
| Onboarding (QR, invite, expiry, revoke) | `device add/remove`; enrolment keeps keys on the device |
| Roles | `Principal → User → Role`; edge asserts principals |
| Policy engine | output restricted to "ordered exit list per (group, destination class)" fed to the same failover machine; a policy can only name exits, so I1 never depends on policy correctness; every evaluation change is an event |
| Per-domain routing | forwarder parses answers into nft sets with timeouts; the renderer declares such sets dynamic, and the exact comparison ignores their elements (never their declaration, type or flags), §5.1 |
| Several providers | `provider` field; exit links are provider-agnostic WireGuard |
| Live TUI, dashboard | `--json` schema and events long-poll; no per-destination history (I5) |
| Signed releases | sums in R1; signing key in R2 |
| Several gateways | site file with `gateways.*`, `site.primary`, site-wide version numbers. The primary pushes signed site versions; secondaries record `last_known_version` and keep running on it; a secondary refuses a push that loosens policy without a matching admin event on the primary. Pushes contain no secrets (schema cannot express them). Load sharing is "per-device primary gateway", not packet balancing. |
| Captive-portal helper (Mac) | explicit, expiring, Mac-only, narrowly scoped exception to I1 |

### High availability (deferred; ADR 0024)

Both options remain open; R1 implements neither. Either way the client stays
fail-closed during a switch (pf holds on the Mac; no gateway ever forwards
outside a VPN exit).

| | (a) Server-side active/standby | (b) Client-side gateway switching |
|---|---|---|
| Shape | two gateways in one region behind a cloud floating/reserved IP; the standby claims the IP through the cloud provider's API when the active fails | the Mac agent holds one profile per gateway and switches when the active gateway's handshake is stale |
| Client identity | **the same client-facing `wg0` identity on both hosts**: a deliberate, documented exception to I6 for that one key | separate identity per gateway |
| Extra secrets | a cloud API token on each gateway (root-only secret ref) | none |
| Exits | separate provider configs per host | separate per host |
| Reach | one region only | across regions and home + cloud; phones switch manually |
| Detection | gateway-to-gateway health + fencing before claiming the IP | client handshake age |

R1 data-model requirements, already met: several `gateways.*` sections
(rejected by R1 validation beyond one); `identities.*` referenceable by
several gateways (rejected in R1); `devices.*.gateways` is a list;
`gateways.*.endpoint` per gateway; events carry `gateway`.

---

## 17. Testing

### Layers

- **Unit (pure core):** parsers (`wg` latest-handshakes and transfer,
  `ip -j route/link/addr/rule`, `nft -j`, `tc -j`) with v1 cases ported and
  fixtures from Ubuntu 22.04/24.04 and Debian 12; JSON canonicalization
  stripping; validation (one negative test per rule, naming the field);
  `Handshake::age` incl. clock skew; `next()` staging; verdict table (v1
  cases plus every new variant); API auth (source mapping, token, Host,
  preflight).
- **Golden:** v1 plus ADR 0032 egress chain in `ruleset.golden`, byte-exact
  (M1 until v1 retirement); netns
  rulesets per milestone gating (one exit v4; two exits mixed v6; R2-shaped
  config rejected); pf anchors; units; `--json` outputs; human output
  (piped form and TTY form rendered with a fixed width). `UPDATE_GOLDEN=1`
  rewrites.
- **CLI interactivity:** every command runs with stdin/stdout not a TTY and
  must never prompt (a prompt attempt fails the test); confirmation-requiring
  commands without `--yes` exit 1; with `--yes` they match the flagged
  golden; pickers and confirmations tested with a scripted pseudo-terminal. CI runs `unshare -rn nft -c -f` on every nft golden; `pfctl -nf`
  on pf goldens (macOS job).
- **Renderer properties:** no uplink name in any netns ruleset; every forward
  `accept` is client→exit or the directional return; deterministic output;
  `iif`/`oif` only for `lo` (R-07).
- **Failover properties:** for random observation streams `active` is always
  a configured exit or `Unreachable`; `Pin(x)` never routes elsewhere than x
  or `Unreachable`; common-mode failures never cause a switch; with
  `failback = manual` no switch away from a Healthy active exit.
- **Planner properties:** every prefix of every plan is `safe`; repair
  actions ⊆ {Restore, Tighten}.
- **Privacy:** every event and metric type serializes without destination or
  domain fields.
- **Input confinement:** secret refs (`../x`, absolute paths, separators,
  symlinked files and directories, wrong kind, wrong owner or mode) and
  bundle archives (path traversal, symlinks, hard links, devices, oversize,
  unknown members) are refused with nothing written; SSH remote requests
  with shell metacharacters, newlines and leading hyphens are rejected or
  passed as data (§10); the edge socket refuses operations outside its set;
  a tunnel principal is refused every high-risk change (ADR 0029).
- **Fake system:** `FakeSystem` implements the `System` trait as an
  in-memory kernel model (links, routes, ruleset hash, sysctls, handshake
  clock, netns inode). Scenarios: route deleted → restored in one tick;
  ruleset flushed → forwarding 0 in the same tick, then restored; budget
  exhausted → forwarding stays 0; exec timeout → watchdog not fed; crash
  between action and bookkeeping → next tick converges; netns name removed
  while edge holds it → re-mount, no rebuild.
- **Network-namespace leak suite** (`cargo xtask leaktest`, root, Linux, from
  M2): namespaces `host` (gateway host, `eth0` veth to `wan`), `scupper`
  (built by the real `scupper boot`), `client` (Mac stand-in, WireGuard peer
  via `wan`), `provA`/`provB` (fake providers: WireGuard server, NAT,
  resolver), `wan` (router + capture point), `internet` (canary HTTP/DNS
  sinks on documentation-range addresses). Clients send canaries with unique
  payload markers. Assertions on pcaps parsed in Rust are **allow-lists of
  packet classes**: the host uplink may carry only WireGuard UDP between
  configured endpoints and the host's own allow-listed traffic (the test's
  SSH, NTP and alert sinks); any other packet fails the case. Canary markers
  are an additional check, not the main one, because DNS encoding,
  fragmentation and ICMP quotations can transform client-derived data; the
  parser reassembles fragments and inspects ICMP quotations and DNS names
  for canary labels. `internet` sees canaries only from provider NAT
  addresses. Every case where recovery is expected runs a positive service
  check (a canary through the exit) before and after the fault. Every case
  has a hard timeout. Runs on
  GitHub-hosted Ubuntu runners and in a local VM via the same xtask.
- **Lab port pinning (deviation from production):** the lab pins the exit WireGuard client to a
  fixed listen port so the uplink allow-list can be an exact 4-tuple across daemon and boot
  restarts. Production exits use ephemeral ports; after a crash, the provider may briefly send to a
  stale port and the host answers ICMP port-unreachable quoting only WireGuard ciphertext. That is
  not a leak (no client-derived plaintext), but the lab does not exercise it.
- **Meta-tests:** product mutations reintroduce non-directional ct accept,
  missing output containment and the bound-probe-only check. M-src is a
  bug-1 symptom oracle control (lab layout): it proves gateway replies are
  visible on the exit and that `iif` keeps them on wg0; it does not exercise
  product code. Planner/renderer and boot trace tests check bug 1's structural
  exclusion: no source-selected rules and no policy rules beyond the baseline.
  Behind R1 namespace isolation, existing L3/L4 are blind to M-ct/M-out.
  Only L19-L3/L4 detect bugs 2 and 3, so L19 must stay in the regular shards;
  the catalog test asserts this requirement.
- **CI:** fmt, clippy `-D warnings`, tests, cargo-deny (licences,
  advisories, duplicates), goldens + `nft -c`, leak suite, musl builds for
  both arches (arm64 unit tests under QEMU), reproducibility check (build
  twice, compare sha256), macOS job for `scupper-mac` and `pfctl -n`, secret
  and private-address scan of the repository.

M2 lab deviations: L2/L11 permit client echo and deny gateway DNS/API
requests because those listeners are deferred to M4 (§5.2). The isolated
`gwhost` has no networkd instance, so L5 records that restart is inapplicable.
L20's IPv6 subtrial widens the renderer's empty IPv6 sets and adds tunnel
addresses while the real daemon is temporarily stopped, then restores the
exact M2 rules and resumes it; M2 configuration still refuses IPv6. L9
crash prefixes are independent simulated boots: their lab-private `/run`
boot-attempt budgets are saved and reset between prefixes; production
retry limits are unchanged.
L19 replays source policy routing in a lab-only table (R1 production has no
client policy rule), and extends L2/L3/L4/L6 with focused provenance, established-flow,
local-output and route-stage subtrials. L3/L4 deliberately add a preferred veth
route so topology isolation cannot mask an nft mutation. L19-L3 establishes a
bidirectional UDP canary through the exit, saves provider-NAT receipts and the
exact ASSURED conntrack tuple (UDP's bidirectional ESTABLISHED state), then pauses
the sender and freezes the real daemon with its testing-only `incomplete-tick`
hook in both control and mutant. It diverts the established replies after reverse
NAT toward the bridge; the original direction still uses the exit. Diverting the
original direction can invalidate the MASQUERADE mapping on an output-interface
change, independently masking the historical nft bug. Immediately before sending,
L19 requires the same established tuple; missing or changed state is a harness
error. The control requires `fwd_dropped` increases and no forbidden bridge
packets; M-ct requires the exact established reply tuple and marker on the bridge
classified as ForbiddenAddress. Conntrack is checked again after measurement.
After unfreezing, the daemon must remove the injected route and restore rules and
service before a catch can be published. In the product, a conntrack flush on
route repair is an additional layer that also masks bug 2; L19 freezes
reconciliation to isolate the nft layer. The bound-probe-only
mutation forges only forwarded route observations; default inventory and the
real bound exit probe remain required. A preinstalled policy rule would fail
baseline-rule inventory first (checked with the fake system), so an xtask-only
System wrapper installs `iif wg0 unreachable` at the first forwarding read,
after topology/default inventory. This models policy drift between check stages
without weakening policy-rule containment. The main default stays intact;
the control requires IPv4 client `RouteWrong(Unreachable)` / exit 3 and the
mutant requires Protected / exit 0. Live policy and independent forwarded
lookups after check prove that the fault remains active in both runs.
M-probe therefore proves that the route stage is the only detector of routing
changes during a check. It does not prove the probe is needed in steady state:
R1's policy-rule and route inventories catch steady-state drift first.

### Leak-test list, staged

| # | Case | Expectation | Milestone |
|---|---|---|---|
| L1 | baseline v4 | works; uplink: WireGuard UDP only | M2 |
| L2 | bug 1: client pings 10.99.0.1, queries gateway services | replies over wg0; nothing to exits or uplink | M2 |
| L3 | bug 2: long TCP flow; kill the active exit (drop its UDP at `wan`), failover disabled | no canary on uplink; flow dies; check 4 | M2 |
| L4 | bug 3: established NAT flows; delete exit link; remote keeps sending; client sends into dead flows | no packet sourced 10.2.0.2 or 10.99.0.0/24 on uplink | M2 |
| L5 | bug 4, host: flush host policy rules and non-default host routes, restart networkd if present | no leak; check stays 0 (deleting the host default route or blocking host UDP is an availability fault, L46) | M2 |
| L6 | bug 4, netns: `ip -n scupper route del default` while a bound probe would pass | check 3 within one tick; repaired; event | M2 |
| L7 | flush netns ruleset during canary stream | no uplink leak; forwarding 0 ≤ 2 s; restored; conntrack flushed; I7 window measured | M2 |
| L8 | host nft flush, host `ip_forward=1`, permissive host table with `dup to … device eth0` | no effect on client traffic | M2 |
| L9 | boot fault injection: kill `scupper boot` after each step (including between `ip link add` and the move, with udev and networkd watching the host link), then canaries and a reboot simulation | never a leak; forwarding never 1 without verified ruleset; the next boot adopts or removes the leftover link and completes | M2 |
| L10 | scupperd SIGKILL and SIGSTOP; edge SIGKILL (M4+) | traffic continues; check 5 (3 for edge/DNS); watchdog restart; heartbeat stops | M2 |
| L11 | isolation: second client stand-in pings client 1, scans gateway; provider side probes gateway ports | all dropped except allowed services from clients | M2 |
| L12 | spoofing: forged client source; gateway peer AllowedIPs widened by hand | WireGuard drops; with widened peer `antispoof` drops and check 2 | M2 |
| L13 | foreign veth into netns (host side with `ip_forward=1`); tc ingress `mirred` redirect from wg0 to it | check 2; link set down and hook removed in the first tick that sees them; capture at the foreign link's host side: client packets only within the detection window, which is measured and must not exceed one tick plus the safety group (§7) | M2 |
| L14 | admin disconnect, then reboot simulation | stays closed until connect | M2 |
| L15 | exit-IP probe returns an uplink address (fake target) | check 2 | M2 |
| L16 | exit down then back (single exit): leave FailClosed by itself (rp_filter, bound probes with `unreachable` default) | 4, then 0 | M2 |
| L17 | `ip netns del scupper` while edge runs; namespace loss with no holder (daemon down: stop → delete → start) | first: re-mount, no second netns, traffic unchanged; second: clean rebuild with a fresh namespace-local marker | M2 |
| L18 | sysctl inheritance: host `rp_filter=2`, `ip_forward=1`, `accept_ra=1` before boot | netns values as §5.4 after boot and after every forwarding toggle | M2 |
| L19 | bug-1 symptom oracle control (lab layout), product mutations (bugs 2-4), bridged topology | typed catches with live evidence; regular-shard nft detectors for bugs 2/3 | M2 |
| L20 | MTU/PMTU: oversized packets client→exit and exit→client | ICMP frag-needed / packet-too-big reach the sender; no other ICMP paths | M2 |
| L21 | failover under load: kill provA | switch ≤ 20 s; zero canaries on uplink; event and alert | M3 |
| L22 | all exits down, then provB returns | 4, then 0 after qualification; fail-closed duration recorded | M3 |
| L23 | common mode: block the probe targets only | no switch; check 3 `CommonModeProbeFailure` | M3 |
| L24 | apply during traffic: add/remove an exit; inject an `nft -f` failure | old ruleset stays; no leak; `applied_version` unchanged | M3 |
| L25 | crash scupperd after each switch step | next tick converges; never a non-exit route | M3 |
| L26 | sticky: preferred exit returns; with `failback=auto` returns after hold | no switch / switch after hold | M3 |
| L27 | pin: pinned exit dies | 4; no switch | M3 |
| L28 | DNS: client queries 192.0.2.53:53 UDP/TCP; DoT TCP/853; UDP/853; DNS during all-exits-down | redirected and answered via provider resolver; 853 rejected; SERVFAIL when down; no DNS on uplink | M4 |
| L29 | edge killed: queries fail; no host DNS fallback | M4 |
| L30 | fragmentation and IPv6 extension headers on port 53 and 853 traffic; forged-source fragments | forcing and antispoof hold | M4 |
| L31 | v6 with v4-only active exit | client gets ICMPv6 unreachable; nothing v6 leaves | M4 |
| L32 | v6 via v6 exit (when V-11 passes) | works; uplink clean | M4 |
| L33 | RA and redirect injection from the client tunnel and from an exit | no route or address change in netns | M4 |
| L34 | non-global destinations: client to 10.2.0.1:80, 192.168.1.1, fe80::1, multicast | dropped | M4 |
| L35 | API: scan from uplink and from provider side (v4, v6); wrong source, missing token, wrong Host, preflight | no response from uplink/provider; 401/403 otherwise | M5 |
| L36 | rebuild rehearsal: fresh VM from a bundle | check 0 within the time budget | M6 |
| L37 | VM reboot of a provisioned image | check 0; uplink capture clean from the first packet | M6 |
| L38 | deploy a deliberately broken build (tunnel down, check ≠ 0); kill scupperd during the window; reboot during the window | no confirmation; rollback at deadline by the previous binary; uplink capture clean throughout; previous revision applied; event recorded | M6 |
| L39 | deploy a good build | confirmed via the tunnel; timer disarmed; no rollback | M6 |
| L40 | M1 lab only (`unshare -rn` or VM, never a live gateway): `systemctl stop nftables` with proton0 down; a netdev `fwd` and an `ip`-family `dup to … device eth0` (nft rejects `dup` in `inet` tables); tc `mirred` on wg0; extra `wg0→eth0` accept; unconstrained ct accept; config that disagrees with the kernel | check 2 in every case; the uplink capture result per the chosen M1 measures (D-1) is recorded | M1 |
| L41 | nft userspace upgraded (recorded nft version changed) while a canonical cache exists | no false `Differs`; re-canonicalized; no forwarding change | M2 |
| L42 | DNS self-test with the upstream broken and the cache warm | check 3 within one self-test interval | M4 |
| L43 | quarantine latch: a recurring foreign link exhausts the budget; then restart scupperd; then reboot | forwarding stays 0 throughout; check 4 `Quarantined`; cleared only by `repair clear` | M2 |
| L44 | concurrent writers: boot retry by scupperd, a manual `systemctl restart scupper-net`, a local `apply` while scupperd restarts | one writer at a time; no stuck boot; every intermediate state closed or exact | M2 |
| L45 | from the installed edge unit, attempt host-mediated resolution (resolved Varlink, D-Bus) | fails; no DNS from the host on the uplink | M4 |
| L46 | availability faults: host default route deleted; host UDP 51820 dropped (ufw); `wg0` listen port taken | no leak; check 4 or 3 `ClientSideBroken` as specified; client-handshake warning; recovery after restore | M2 |
| L47 | failover with established TCP and UDP client flows | TCP gets a reset from the gateway; new flows use the new exit; nothing on the uplink | M3 |
| L48 | cold standby: the active exit handshakes but forwards no payload | a qualifier is brought up; failover, or common-mode when it fails too | M3 |
| L49 | a long-lived DNS flow to an outside resolver across the apply that introduces `dns_redirect` | the old flow is dropped in forward; new queries are redirected | M4 |
| L50 | crash after `Disconnected` is persisted and before the routes change | check 3 `DisconnectNotEffective`, never 4 while a route via an exit exists; then tightened | M2 |
| L51 | deploy edge cases: two deploys at once; confirmation racing the rollback; a device revoked during the window; a deploy that changes a unit file; a build whose own check falsely reports 0 | second deploy refused; exactly one of confirm/rollback; revocation survives rollback; units restored; Mac-side checks refuse to confirm the false-0 build | M6 |
| L52 | an extra main-table route via an exit in the netns | check 3 `RouteWrong`; removed | M2 |
| L53 | heartbeat TLS handshake completes, GET is dropped, parent is killed | child alive near deadline, gone by deadline +1 s; no late TCP payload | M2 |
| L53b | GET queued behind a drop, parent killed and child stopped; separate held GET released with <2 s remaining | no TCP payload after either original deadline; unconditional group kill/reap on every exit path | M2 |
| L54 | client queries `use-application-dns.net` (A, AAAA, HTTPS) | NXDOMAIN from the gateway; no upstream query for it on any exit | M4 |
| L55 | gateway-generated ICMP errors about NATed client flows (undeliverable reply, frag-needed) | nothing with the exit address or client addresses on the uplink, checked after NAT | M1 (lab), M2 |

---

## 18. Failure modes

A full apply closes forwarding before publishing its target version durably.
If the process crashes before verification or rollback, the next start retries
that target under the boot budget and remains closed on failure. The operator
can recover with `scupper apply N` for the previous known-good version. A live
failed apply reports whether the previous version was restored and verified,
or rollback failed and forwarding was closed (or closure could not be verified).

Local control clients must keep the write side open until they receive a reply;
do not shut down the write side after sending a request. Queued disconnects
still execute after a client hangs up because they only tighten policy.

| Failure | Effect | Detection | Response |
|---|---|---|---|
| scupperd crash | no failover, repairs, alerts, heartbeat; data path unchanged | systemd; check 5; heartbeat stops | `Restart=always`; adopts state |
| scupperd hung | as above | watchdog not fed | systemd restarts it; exec timeouts |
| edge crash or hang | no DNS, no tunnel API; forwarding continues | DNS self-test; watchdog; check 3 | systemd restart; CLI falls back to SSH |
| Probe or delivery child hangs | that probe/alert late | timeout | killed; counted as failure |
| Active exit dead | traffic blackholed in that tunnel | probes, handshake | failover ~15 s (hot); else FailClosed |
| All exits dead | fail closed | as above | route unreachable; alert via uplink; recover after qualification |
| Probe targets down | none on the data path | common-mode rule | 3, alert, no switch |
| Provider DNS down | client DNS fails | path probes, DNS self-test | 3; common mode if on all exits |
| Netns ruleset flushed or changed | NAT, isolation, DNS forcing lost; no uplink leak | fingerprint ≤ 2 s | forwarding 0, reload, verify, conntrack flush, forwarding 1 unless latched or Disconnected |
| Netns route changed or deleted | clients cut or on another exit | route compare | restore |
| Foreign link or tc in netns | possible path among tunnels | link/tc scan | down / delete; check 2; alert |
| Netns name deleted (`ip netns del`) while edge runs | namespace, links and routes survive and keep forwarding via exits | stat vs held inode | re-mount from held fd; no rebuild |
| Netns really gone | links destroyed; closed | inode gone | stop edge; rerun boot |
| Hardening sysctl reset (forwarding toggle) | standby probes may fail (rp_filter) | read-back | re-apply |
| networkd restart / unattended-upgrades | none in netns layout; in M1 layout rule 1000 may vanish → clients fail closed | M1: route probe (3) | M1: drop-in prevents it; operator re-adds |
| Host `nftables.service` stop or reload, ufw | netns layout: no effect on containment; ufw may block client UDP (availability). **M1 layout: the stock unit flushes the host ruleset on stop; with the exit down, rule 1000 missing or the gateway disconnected, client traffic follows the main table to the uplink** | netns: stage 4 client side, handshake ages; M1: `check` 2 when run | netns: none needed; M1: lab only, never deployed (§19, D-1) |
| Host or cloud firewall blocks WireGuard UDP | exits: handshakes fail, closed; clients: cannot connect while the gateway side is healthy | exit handshake ages; client handshake ages (warning); stage 4 for local causes; Mac agent notification with the gateway's view | `install --check` warns |
| Host uplink down | handshakes stop; closed | handshake ages | FailClosed; alerts queued until uplink returns |
| **Gateway host lost** (VM deleted, hypervisor failure, region outage) | clients fail closed (Mac pf holds) | Mac agent: "gateway unreachable"; external heartbeat service alerts when pings stop | rebuild from bundle (§15, ~10 min) |
| Reboot | closed until boot finishes | `Boot` event | `scupper boot` |
| `scupper boot` fails mid-way | closed (prefix rule); edge not started | unit failed; scupperd alert | scupperd retries under budget; operator via SSH |
| Invalid config committed | rejected | validation | stays on head |
| Valid config, apply fails | old state kept or re-converged | apply verify | `ApplyFailed`; `applied_version` unchanged |
| Disk full | events and config cannot be written | write errors | refuse config changes; in-memory event; repairs continue; a quarantine latch that cannot be persisted holds in memory |
| Key file missing or wrong mode | that exit cannot come up | load check | exit Down, warning, alert |
| Clock step | handshake ages wrong | future-timestamp check | warning; probes are clock-independent, no false 0; holds, budgets and deadlines use the monotonic clock |
| Conntrack table full | new flows fail | `nf_conntrack_count` vs max | 3 (warning), alert; never bypass conntrack |
| Alert sink down | alerts delayed | sink errors | backoff, cursor; `SinkFailed` after 24 h |
| Heartbeat service down | no dead-man coverage | delivery errors | `HeartbeatFailed` warning |
| Device token leaked (any process of the Mac user can read it) | from the device's tunnel address: the operational API (status, connect/disconnect, exit selection, low-risk config); no device, exit or alert changes (ADR 0029) | events carry the `Device` actor | rotate over SSH |
| Edge compromised (for example through a DNS parsing bug) | can assert device principals for the operational set, observe and stop client DNS; cannot make high-risk changes, reach the uplink or host proxy sockets | – | unprivileged, no keys, minimal filesystem view; splitting DNS and API into two processes is an R2 option |
| Mac tunnel down while joined | Mac traffic blocked by pf | agent handshake check | notification; stays blocked |
| Mac agent or helper crash | agent: no auto-join or notifications; helper: no re-verification; pf rules and states persist | launchd KeepAlive | restart; the helper re-verifies and flushes states after any repaired gap |
| macOS reloads pf.conf or disables pf | protection gap until detection (≤ 5 s, measured in V-05) | 5 s re-verify of the whole evaluation path | pre-tunnel anchor, flush states, rejoin, notify |
| Mac reboot while joined | unprotected until the helper starts | persisted join intent | helper loads the pre-tunnel anchor at load, then joins |
| Deployed binary or config breaks the tunnel, API or check | no confirmation arrives | rollback timer | gateway restores previous binary and revision itself, fail-closed; `DeployRolledBack` alert |
| Crash or reboot during a pending deploy | timer owned by systemd; guard unit at boot | `pending.json` | rollback at deadline, before the boot procedure if needed |
| Rollback itself fails | gateway stays closed | `DeployRolledBack{result: failed}`, heartbeat verdict | operator via break-glass SSH |
| Cloud API token exposure risk | – | – | token only on the Mac, never stored or logged (ADR 0027) |

---

## 19. Milestones

Each milestone ends tested and deployable.

| M | Content | Exit criteria |
|---|---|---|
| **M1 Parity** | Single crate. Pure Rust port of v1 in the v1 layout: `status check connect disconnect rules apply`, exit codes 0-4, v1 verdict order; `V1Config` with v1 defaults (optional `/etc/scupper/v1.toml`); renderer byte-exact to the golden; parsers ported (latest-handshakes, `ip route get` dev); **route probe** (`ip route get 1.1.1.1 from 10.99.0.2 iif wg0` = `dev proton0`); **exact comparison of the whole host ruleset** by kernel canonicalization in an anonymous namespace (§5.1); config cross-check against the kernel; `nft -c` before `apply` renames; exit probe with `SO_BINDTODEVICE`; networkd drop-in with both `ManageForeign*` settings documented; cargo-deny, pinned toolchain, musl x86_64 build. | golden byte-exact; v1 verdict and parser tests ported and green; negative tests **only in an `unshare -rn` lab or a VM** (L40) → 2; V-04 (host), V-23, V-24 recorded; in a VM built in the v1 layout `check` = 0, `ip rule del … priority 1000` → 3, re-added → 0. Not deployed (D-1). |
| **M2 Netns + daemon** | Workspace split; netns layout (§3, §5.2 M2 parts, §5.4); `scupper boot`; scupperd reconcile loop, repairs, budgets, planner; single-exit failover machine; event log; alert sinks (ntfy, webhook); external heartbeat; exit code 5; basic `scupper install`, basic `scupper deploy --host` (no rollback timer) and config version store + bundle; leak harness in CI with L1-L20; migration to a fresh host. | L1-L20, L41, L43, L44, L46, L50, L52, L53, L55 green in CI; fake-system scenarios green, including the latch property; new gateway serving the Mac with `check` = 0 and rebooted twice with `check` = 0 afterwards and a clean uplink capture from the first packet; host `ip rule flush` → still 0; `ip -n scupper route del default` → 3 then repaired; heartbeat observed at the external service and stopping when scupperd is stopped; old gateway kept as rollback. |
| **M3 Exits** | Two exits; full failover machine (sticky, pin, prefer, optional auto failback); hot standby (after V-09) or cold; `exit list/show/use/auto/test/import`. | L21-L27, L47, L48 green; V-09, V-10, V-25 recorded; cold-standby outage measured against its 30-60 s target; real failover on the gateway by blocking one exit's endpoint: switch ≤ 20 s, event and alert delivered. |
| **M4 DNS + IPv6** | Edge with forwarder; `dns_redirect`, 853 rejects, `nonglobal` sets; dual-stack model, v6 fail-closed path; v6 exit only after V-11. | L28-L34, L42, L45, L49, L54 green; Mac resolves via 10.99.0.1; an opportunistic DoT client falls back to 53 and a strict DoT client fails without sending plaintext DNS; v6 on v4-only exit gets ICMPv6 unreachable; V-11, V-12, V-26 recorded. |
| **M5 API + Mac** | Tunnel API and auth; CLI transports; `/metrics`; `scupper mac` join/leave, pf anchor, auto-join, notifications, enrolment, bundle copies. | L35 green; auth unit tests; Mac matrix (§14) passed with external capture against the written pass conditions; V-05, V-06, V-20, V-21 recorded; CLI works identically via local, API and SSH. |
| **M6 Installer + release** | `install` hardening (`--check`, preflight incl. host firewall, idempotence tests); confirm-or-rollback `deploy`, `upgrade`, guard unit; `gateway create --provider digitalocean` with operator-side secret references; distribution (Linux install script, Homebrew tap, artefacts for x86_64/aarch64 Linux musl and aarch64 macOS with `SHA256SUMS`); timed rebuild rehearsal; VM reboot test; reproducible-build check. | L36-L39, L51 green; V-18, V-27 recorded; second `install` run is a no-op; a broken deploy rolls back by itself, including one that changes a unit file and one whose own check falsely reports 0; `gateway create` + `deploy` + `mac enroll` reach `check` = 0 on a fresh VM (DigitalOcean client also green against the fake API in CI); rebuild ≤ ~10 min in rehearsal; two builds bit-identical. |

### Decisions on scope and guarantees

- **D-1 M1 on the v1 layout: lab only.** M1 is the parity port, built and
  tested in a lab namespace and a VM, and never deployed to a gateway that
  carries traffic. The existing v1 gateway is left unchanged; the first
  deployment is M2 on a freshly built host (§16).
- **D-2 Mac enforcement: pf in R1, re-evaluated for R2.** R1 states the
  narrowed guarantee of §1 (enforced while pf evaluates the anchor; removal
  detected and repaired within 5 s; the boot window measured, V-05). R2
  re-evaluates a Network Extension packet tunnel using the V-05 and V-20
  measurements.
- **D-3 Command-defined secret backends: in R1**, under the rules of §8
  (never as root, user-owned config only, argv without shell, minimal
  environment).
- **D-4 `gateway create` stays in R1** with the scoped token and the
  authenticated host-key bootstrap of §15.
- **D-5 High-risk changes are local-socket only** (ADR 0029); the Mac CLI
  sends them over SSH automatically.

---

## 20. Verification tasks

Claims this design relies on that must be shown (netns suite, VM or real
hardware) before anything depends on them.

| ID | Claim to verify | How | Milestone |
|---|---|---|---|
| V-01 | A new netns inherits IPv4 `all`/`default` sysctls (`rp_filter`, `ip_forward`) from the host, and scupper's explicit values override them | L18 | M2 |
| V-02 | With `rp_filter=0`, standby probes bound with `SO_BINDTODEVICE` succeed while the netns default route is `unreachable` or points at another exit (IPv4; for IPv6 see V-22), so the gateway leaves FailClosed by itself | L16, L22 | M2 |
| V-03 | Writing `ip_forward` rewrites per-device `forwarding` and `accept_redirects` and nothing else relevant (in particular not `rp_filter`), and re-applying restores every hardening value | L18 + fake-system test | M2 |
| V-04 | Kernel canonicalization through a throwaway namespace yields identical JSON for live and rendered rulesets on Ubuntu 22.04, 24.04 and Debian 12 (`ifname` sets and `iifname`/`oifname` load without the links); stays `Exact` across an nft userspace upgrade without reboot (L41); `canon` aborts when the namespace switch failed | golden + CI matrix | M1 (host table), M2 (netns) |
| V-05 | The pf sub-anchor `com.apple/scupper` is evaluated via the stock `anchor "com.apple/*"`. For each macOS operation that reloads or changes pf (firewall toggle, Internet Sharing, OS update, sleep/wake, another VPN or pf tool): whether the anchor or its evaluation path is removed, and the measured gap until the helper's repair. Also the unprotected window from boot to the helper's load with a persisted join | Mac matrix with external capture | M5 |
| V-06 | macOS source-address selection with a ULA-only v6 address: how much traffic uses the v6 exit | Mac capture | M4/M5 |
| V-07 | The renderer never emits `iif`/`oif` except for `lo` | property test R-07 | M1 |
| V-08 | The provider drops un-NATed packets from an absent ruleset (informational; I1 does not depend on it) | gateway test with the ruleset removed in a lab namespace | M3 |
| V-09 | The provider account permits two simultaneous WireGuard sessions, both with `10.2.0.2`, and the connection-slot limit (including the migration overlap) | real account | M3 (before hot standby) |
| V-10 | WireGuard handshake cadence on an **idle** hot standby with keepalive 25 s stays below 180 s | real gateway, 24 h | M3 |
| V-11 | Whether the provider configs carry a v6 address and the v6 exit works end to end | real account | M4 |
| V-12 | The forwarder passes the provider's filtered answers unchanged and signed zones resolve through it (no DNSSEC validation in the path) | real gateway | M4 |
| V-13 | Host firewall tools (ufw, cloud firewall) do not block WireGuard UDP for clients and exits; `install --check` detects it | VM | M2 (warning), M6 |
| V-14 | `ip netns del` while edge holds the namespace keeps links and routes alive; the held-fd re-mount restores the name without a second namespace | L17 | M2 |
| V-15 | `BindsTo=`/`Requires=` keep edge from starting without the namespace and stop it with the namespace unit | VM | M2 |
| V-16 | Probes inside the namespace work without any host resolver (`/etc/resolv.conf` → 127.0.0.53 unreachable there) | L1 + probe test | M2 |
| V-17 | `redirect to :53` in the `inet` family works for IPv6 queries on the target kernels | L28 | M4 |
| V-18 | A `systemd-run --on-active` transient timer fires after scupperd and edge are killed, and the guard unit performs or re-arms the rollback after a reboot | L38 in a VM | M6 |
| V-19 | Exact `pass-cli` command, output format and minimum version for reading one field of `pass://vault/item/field`; `PROTON_PASS_AGENT_REASON` accepted; not-logged-in exit status and message detectable | `pass-cli --help` and a test vault; parser unit tests on captured output | M6 |
| V-20 | macOS pf accepts `keep state (if-bound)` and binds states to the utun: established TCP and UDP flows do not pass on a physical interface after a route change, anchor loss or utun-number reuse | Mac capture | M5 |
| V-21 | Whether a non-root macOS process can bind UDP 68/546 while the system DHCP client runs; the restricted DHCP rules still allow lease acquisition and renewal | Mac test | M5 |
| V-22 | An IPv6 socket bound with `SO_BINDTODEVICE` to a standby gets no route while the netns v6 default is `unreachable` or via another exit (expected; standby probes are IPv4 only) | L16 variant | M2 |
| V-23 | `nftables.service` on the target distributions runs `nft flush ruleset` on stop; whether package upgrades restart it; whether a drop-in clearing `ExecStop=` prevents the flush | VM; read-only `systemctl cat nftables` on a v1 gateway | M1 |
| V-24 | Whether systemd-networkd with `ManageForeignRoutes=yes` deletes routes in table 51820 on an unmanaged link | VM | M1 |
| V-25 | `nf_conntrack_tcp_loose` is per network namespace on the target kernels, and with 0 a flushed mid-stream TCP flow is invalid and reset by the forward rule | L47 | M3 |
| V-26 | `TemporaryFileSystem=/run` with `BindPaths=` of a socket works together with `NetworkNamespacePath=` on systemd 249+ and hides resolved and D-Bus from edge | L45 | M4 |
| V-27 | DigitalOcean custom token scopes sufficient to create without delete (exact names); cloud-init on Ubuntu 24.04 accepts injected SSH host keys | fake API + one real run | M6 |
| V-28 | `Upholds=` restarts edge after a `scupper-net` restart; scupperd's inode check restarts edge after a namespace rebuild | VM | M2 |

---

## 21. ADR index

| ADR | Title |
|---|---|
| [0001](adr/0001-dedicated-netns-data-plane.md) | Dedicated network namespace for the data plane, after a pure parity milestone |
| [0002](adr/0002-no-wg-quick-on-gateway.md) | No wg-quick on the gateway |
| [0003](adr/0003-exec-over-netlink.md) | Exec system tools instead of netlink crates |
| [0004](adr/0004-process-model.md) | Process model: boot unit, synchronous root daemon, unprivileged edge in the namespace |
| [0005](adr/0005-built-in-dns-forwarder.md) | Built-in DNS forwarder |
| [0006](adr/0006-block-dot.md) | Block DNS over TLS instead of intercepting it |
| [0007](adr/0007-api-auth.md) | API authentication: WireGuard identity plus device token, plain HTTP |
| [0008](adr/0008-no-ssh-in-tunnel.md) | No SSH inside the tunnel; break-glass SSH to the public address |
| [0009](adr/0009-exit-code-5.md) | Exit code 5: protected but unsupervised |
| [0010](adr/0010-sticky-failover.md) | Sticky failover by default |
| [0011](adr/0011-hot-standby.md) | Hot standby with two exits |
| [0012](adr/0012-config-version-store.md) | The config version store is the source of truth |
| [0013](adr/0013-exact-ruleset-comparison.md) | Exact ruleset comparison by kernel canonicalization |
| [0014](adr/0014-migration-by-fresh-host.md) | Migration by building a fresh host |
| [0015](adr/0015-parity-first.md) | Milestone 1 is a pure v1 parity port |
| [0016](adr/0016-netns-routing-and-gate.md) | Single default route in the namespace; forwarding as the emergency gate |
| [0017](adr/0017-host-namespace-untouched.md) | scupper owns the namespace and nothing in the host |
| [0018](adr/0018-alerts-via-uplink.md) | Alerts and heartbeat leave via the host uplink |
| [0019](adr/0019-jsonl-event-log.md) | JSON Lines event log |
| [0020](adr/0020-probes-resolve-through-exit.md) | Probes resolve names through the exit they test |
| [0021](adr/0021-mac-wg-quick-pf.md) | Mac: wg-quick, pf sub-anchor, fingerprint-based auto-join |
| [0022](adr/0022-polling-reconcile.md) | Level-triggered polling reconcile loop |
| [0023](adr/0023-secret-refs.md) | Secret references: gateway files by name, operator secrets resolved just in time |
| [0024](adr/0024-ha-options-deferred.md) | High availability options, deferred |
| [0025](adr/0025-rebuild-and-heartbeat.md) | Fast rebuild from a config bundle and an external heartbeat |
| [0026](adr/0026-confirm-or-rollback-deploys.md) | Confirm-or-rollback deploys |
| [0027](adr/0027-cloud-provisioning-from-mac.md) | Gateway creation from the Mac with a client-only cloud token |
| [0028](adr/0028-single-writer-and-deploy-transactions.md) | One writer lock; deploys as serialized transactions |
| [0029](adr/0029-risk-classified-mutations.md) | Risk-classified mutations: high-risk changes only over the local socket |
| [0030](adr/0030-mac-root-helper.md) | Mac: a minimal root helper with root-owned tools, a user agent for the rest |
| [0031](adr/0031-quarantine-latch.md) | Persisted quarantine latch after an exhausted repair budget |
| [0032](adr/0032-post-nat-uplink-filter.md) | Drop exit-sourced uplink packets after NAT |
