#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# != 2 || $EUID != 0 ]]; then
    echo "Usage (root, disposable VM only): $0 <scupper-binary> <capture-dir>" >&2
    exit 1
fi
binary=$(realpath -- "$1")
[[ -x $binary ]] || { echo "Binary is not executable: $binary" >&2; exit 1; }
umask 022
mkdir -p -- "$2"
captures=$(realpath -- "$2")

# Refuse to claim anything that a previous run or another service owns.
for ns in gw provider client; do
    if [[ -e /run/netns/$ns || -e /etc/netns/$ns ]]; then
        echo "Namespace or resolver directory already exists: $ns" >&2
        exit 1
    fi
done
host_links=("scg$$" "scp$$" "scc$$")
for link in "${host_links[@]}"; do
    if ip link show dev "$link" &>/dev/null; then
        echo "Host link already exists: $link" >&2
        exit 1
    fi
done
uplink=$(ip -4 route show default | awk 'NR == 1 {for (i=1; i<NF; i++) if ($i == "dev") {print $(i+1); exit}}')
[[ -n $uplink ]] || { echo 'No host default device' >&2; exit 1; }
tag="scupper-lab-$$"
namespaces=()
links=()
resolver_dirs=()
forward_in=()
forward_out=()
nat_added=0
forwarding_changed=0
netns_dir_created=0
private=''
active_case=''
ping_pid=''
tcp_pid=''
dump_pid=''
mismatches=0
last_count=0
results="$captures/results.tsv"
printf 'name\twanted\tgot\tfirst_line\n' > "$results"

cleanup() {
    local code=$? ns link failed=0
    trap - EXIT
    set +e
    stop_traffic || failed=1
    cat "$results"
    for link in "${forward_in[@]}"; do
        iptables -w -D FORWARD -i "$link" -m comment --comment "$tag" -j ACCEPT || failed=1
    done
    for link in "${forward_out[@]}"; do
        iptables -w -D FORWARD -o "$link" -m comment --comment "$tag" -j ACCEPT || failed=1
    done
    if (( nat_added )); then
        iptables -w -t nat -D POSTROUTING -s 172.31.0.0/16 -o "$uplink" \
            -m comment --comment "$tag" -j MASQUERADE || failed=1
    fi
    for ns in "${namespaces[@]}"; do ip netns del "$ns" || failed=1; done
    for link in "${links[@]}"; do
        # A veth vanishes asynchronously when its namespace is deleted: only a link that is
        # still present after a failed delete counts as a cleanup failure.
        if ip link show dev "$link" &>/dev/null; then
            ip link del "$link" 2>/dev/null || ! ip link show dev "$link" &>/dev/null || failed=1
        fi
    done
    for ns in "${resolver_dirs[@]}"; do
        rm -f -- "/etc/netns/$ns/resolv.conf" || failed=1
        rmdir -- "/etc/netns/$ns" || failed=1
    done
    if (( netns_dir_created )); then rmdir /etc/netns || failed=1; fi
    if (( forwarding_changed )); then sysctl -q -w "net.ipv4.ip_forward=$old_forwarding" || failed=1; fi
    if [[ -n $private ]]; then rm -rf -- "$private" || failed=1; fi
    if (( failed )); then
        echo 'Lab cleanup failed; inspect the disposable VM before reusing it' >&2
        if (( code == 0 )); then code=1; fi
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

private=$(mktemp -d)
chmod 0700 "$private"
(
    umask 077
    for key in gw-client gw-exit provider client; do wg genkey > "$private/$key.key"; done
)
gw_client_pub=$(wg pubkey < "$private/gw-client.key")
gw_exit_pub=$(wg pubkey < "$private/gw-exit.key")
provider_pub=$(wg pubkey < "$private/provider.key")
client_pub=$(wg pubkey < "$private/client.key")

# No showconf/dump calls: private keys never enter output or captures.
redact() {
    sed -e "s|$gw_client_pub|PUBKEY1|g" -e "s|$gw_exit_pub|PUBKEY2|g" \
        -e "s|$provider_pub|PUBKEY3|g" -e "s|$client_pub|PUBKEY4|g"
}
capture() {
    local name=$1
    shift
    CAPTURE_CODE=0
    "$@" 2> "$captures/$name.stderr" | redact > "$captures/$name" || CAPTURE_CODE=$?
    printf '%s\n' "$CAPTURE_CODE" > "$captures/$name.exit-code"
}
record() {
    local name=$1 wanted=$2 got=$3 first=$4
    first=${first//$'\t'/ }
    first=${first//$'\r'/ }
    first=${first//$'\n'/ }
    printf '%s\t%s\t%s\t%s\n' "$name" "$wanted" "$got" "$first" >> "$results"
    if [[ $wanted != info && $got != skipped && $got != "$wanted" ]]; then mismatches=$((mismatches + 1)); fi
}
scupper() { timeout 60 ip netns exec gw "$binary" "$@"; }
expect() {
    local wanted=$1 name=$2 first=''
    # Let the fault act on live client traffic before and after check, so a leak has time to
    # reach the capture (the positive control showed a one-second window catches nothing).
    sleep 3
    capture "check-$name.txt" scupper check
    sleep 1
    IFS= read -r first < "$captures/check-$name.txt" || true
    if [[ -z $first ]]; then IFS= read -r first < "$captures/check-$name.txt.stderr" || true; fi
    record "$name" "$wanted" "$CAPTURE_CODE" "$first"
    finish_case "$name" "$wanted" "$CAPTURE_CODE"
}
gw() { ip netns exec gw "$@"; }
provider() { ip netns exec provider "$@"; }
client() { ip netns exec client "$@"; }

# Each background command owns a process group, including the TCP request loop.
# Signal the whole group and escalate after five seconds; always reap the leader.
stop_group() {
    local pid=$1 signal=$2 attempt failed=0
    [[ -n $pid ]] || return 0
    kill -s "$signal" -- "-$pid" 2>/dev/null || true
    for ((attempt = 0; attempt < 50; attempt++)); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL -- "-$pid" 2>/dev/null || true
        failed=1
    fi
    GROUP_STATUS=0
    wait "$pid" 2>/dev/null || GROUP_STATUS=$?
    return "$failed"
}
stop_traffic() {
    local failed=0
    stop_group "$ping_pid" TERM || failed=1
    stop_group "$tcp_pid" TERM || failed=1
    stop_group "$dump_pid" INT || failed=1
    if [[ -n $dump_pid && $GROUP_STATUS != 0 ]]; then
        echo "tcpdump failed (exit $GROUP_STATUS)" >&2
        failed=1
    fi
    ping_pid='' tcp_pid='' dump_pid=''
    return "$failed"
}
begin_case() {
    local name=$1 deadline flow next_flow
    [[ -z $active_case ]] || { echo "Capture still active: $active_case" >&2; return 1; }
    active_case=$name
    # This is the host end of gw's eth0, before the host uplink's NAT.
    setsid tcpdump -ni "${host_links[0]}" -U -w "$captures/$name.pcap" \
        'host 10.99.0.2 or host 10.2.0.2' > /dev/null 2> "$captures/$name-tcpdump.stderr" &
    dump_pid=$!
    deadline=$((SECONDS + 5))
    until grep -q 'listening on' "$captures/$name-tcpdump.stderr"; do
        if ! kill -0 "$dump_pid" 2>/dev/null || (( SECONDS >= deadline )); then
            echo "tcpdump did not start for $name" >&2
            return 1
        fi
        sleep 0.1
    done
    setsid timeout --kill-after=2 240 ip netns exec client \
        stdbuf -oL ping -n -i 0.2 1.1.1.1 > "$captures/$name-ping.txt" 2>&1 &
    ping_pid=$!
    # A rate-limited response keeps an established NAT/TCP flow across the fault.
    # Reconnect if the server closes it; no request depends on a host proxy.
    setsid timeout --kill-after=2 240 ip netns exec client bash -c '
        while :; do
            curl --noproxy "*" -4 --fail --silent --show-error --limit-rate 20k \
                --connect-timeout 10 --max-time 180 --output /dev/null \
                "https://speed.cloudflare.com/__down?bytes=10000000" || true
            sleep 0.2
        done' > "$captures/$name-tcp.txt" 2>&1 &
    tcp_pid=$!
    deadline=$((SECONDS + 25))
    while (( SECONDS < deadline )); do
        flow=$(client_tcp_flow) || flow=''
        if [[ -n $flow ]]; then
            # Check that the same connection persists before injecting the fault.
            sleep 1
            next_flow=$(client_tcp_flow) || next_flow=''
            if [[ $flow == "$next_flow" ]]; then
                printf '%s\n' "$flow" > "$captures/$name-tcp-established.txt"
                return 0
            fi
        fi
        if ! kill -0 "$tcp_pid" 2>/dev/null; then break; fi
        sleep 0.2
    done
    record "$name-tcp-established" 0 1 'no persistent established client HTTPS flow before the fault'
    return 1
}
client_tcp_flow() {
    client ss -Hnt state established | awk '
        $3 ~ /^10[.]99[.]0[.]2:/ && $4 ~ /:443$/ { print $3, $4; found=1 }
        END { exit !found }'
}
finish_case() {
    local name=$1 wanted=$2 check_code=$3 count
    [[ $active_case == "$name" ]]
    # A dead capture cannot establish silence, even if its partial pcap is empty.
    kill -0 "$dump_pid"
    kill -0 "$ping_pid"
    kill -0 "$tcp_pid"
    stop_traffic
    count=$(tcpdump -nn -r "$captures/$name.pcap" \
        2> "$captures/$name-pcap-read.stderr" | wc -l)
    count=${count//[[:space:]]/}
    last_count=$count
    if [[ $name != config-disagreement && $wanted == 2 && $check_code == 2 ]]; then
        record "$name-uplink-packets" info "$count" 'un-NATed uplink packets; check reported 2'
    else
        record "$name-uplink-silent" 0 "$count" 'un-NATed uplink packets'
    fi
    active_case=''
}

# Optional kernel facilities differ between runner images. Skip only explicit
# capability errors; malformed commands and other failures still fail the lab.
optional_fault() {
    local name=$1 reason code
    shift
    capture "fault-$name.txt" "$@"
    code=$CAPTURE_CODE
    if (( code == 0 )); then return 0; fi
    reason=$(< "$captures/fault-$name.txt.stderr")
    if [[ $reason =~ Operation\ not\ supported|Protocol\ not\ supported|Address\ family\ not\ supported|[Uu]nsupported\ family|[Uu]nsupported\ operation|Specified\ qdisc\ kind\ is\ unknown|Table\ does\ not\ exist ]]; then
        record "$name" 2 skipped "$reason"
    else
        record "$name" 2 "fault-failed-$code" "${reason:-fault command failed without stderr}"
    fi
    if ! stop_traffic; then
        record "$name-capture-stop" 0 1 'capture or traffic shutdown failed'
    fi
    active_case=''
    return 1
}

capture nft-version.txt nft --version
capture kernel.txt uname -r
capture nftables-service.txt systemctl cat nftables

old_forwarding=$(sysctl -n net.ipv4.ip_forward)
forwarding_changed=1
sysctl -q -w net.ipv4.ip_forward=1
nat_added=1
# Using only the default uplink excludes every lab veth from masquerading.
iptables -w -t nat -A POSTROUTING -s 172.31.0.0/16 -o "$uplink" \
    -m comment --comment "$tag" -j MASQUERADE
for link in "${host_links[@]}"; do
    forward_in+=("$link")
    iptables -w -I FORWARD -i "$link" -m comment --comment "$tag" -j ACCEPT
    forward_out+=("$link")
    iptables -w -I FORWARD -o "$link" -m comment --comment "$tag" -j ACCEPT
done

new_namespace() {
    local ns=$1
    # A rebuilt gateway is still the same resource for cleanup purposes.
    if [[ " ${namespaces[*]} " != *" $ns "* ]]; then namespaces+=("$ns"); fi
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
}
veth() {
    local ns=$1 host=$2 subnet=$3
    links+=("$host")
    ip link add "$host" type veth peer name eth0 netns "$ns"
    ip addr add "172.31.$subnet.1/24" dev "$host"
    ip link set "$host" up
    ip -n "$ns" addr add "172.31.$subnet.2/24" dev eth0
    ip -n "$ns" link set eth0 up
    ip netns exec "$ns" sysctl -q -w net.ipv4.conf.eth0.rp_filter=0
}
resolver() {
    local ns=$1
    if [[ ! -d /etc/netns ]]; then
        netns_dir_created=1
        mkdir /etc/netns
    fi
    resolver_dirs+=("$ns")
    mkdir "/etc/netns/$ns"
    printf 'nameserver 1.1.1.1\n' > "/etc/netns/$ns/resolv.conf"
}
create_exit() {
    gw ip link add proton0 type wireguard
    gw wg set proton0 private-key "$private/gw-exit.key" peer "$provider_pub" \
        endpoint 172.31.1.2:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 25
    gw ip addr add 10.2.0.2/32 dev proton0
    gw ip link set proton0 up
    gw sysctl -q -w net.ipv4.conf.proton0.rp_filter=0
    # Table = off: only the explicit policy table below gets an exit route.
}
create_gateway() {
    new_namespace gw
    veth gw "${host_links[0]}" 0
    gw ip route add default via 172.31.0.1
    gw ip link add wg0 type wireguard
    gw wg set wg0 private-key "$private/gw-client.key" listen-port 51820 \
        peer "$client_pub" allowed-ips 10.99.0.2/32
    gw ip addr add 10.99.0.1/24 dev wg0
    gw ip link set wg0 up
    gw sysctl -q -w net.ipv4.conf.wg0.rp_filter=0 net.ipv4.ip_forward=1
    create_exit
    gw ip rule add iif wg0 lookup 51820 priority 1000
    gw ip route add default dev proton0 table 51820
}
wait_exit() {
    local deadline=$((SECONDS + 20)) handshake
    while (( SECONDS < deadline )); do
        handshake=$(gw wg show proton0 latest-handshakes | awk 'NR == 1 {print $2}')
        if [[ $handshake =~ ^[0-9]+$ ]] && (( handshake > 0 )); then return 0; fi
        sleep 1
    done
    echo 'proton0 handshake did not arrive within 20 seconds' >&2
    return 1
}
heal() {
    local name=$1 iface
    if ! gw ip link show dev proton0 &>/dev/null; then create_exit; fi
    gw ip link set proton0 up
    for iface in wg0 proton0; do
        gw tc qdisc del dev "$iface" clsact 2>/dev/null || true
        gw tc qdisc del dev "$iface" ingress 2>/dev/null || true
    done
    gw wg set wg0 peer "$client_pub" allowed-ips 10.99.0.2/32
    gw ip rule del priority 1000 2>/dev/null || true
    gw ip rule add iif wg0 lookup 51820 priority 1000
    gw ip route replace default dev proton0 table 51820
    gw nft -f "$private/policy.nft"
    wait_exit
    begin_case "heal-$name"
    expect 0 "heal-$name"
}
capture_links() {
    local prefix=$1 iface
    mkdir -p "$captures/$prefix"
    capture "$prefix/ip-link.json" gw ip -j link show
    for iface in eth0 proton0 wg0; do
        capture "$prefix/ip-addr-$iface.json" gw ip -j addr show dev "$iface"
    done
    for iface in wg0 proton0; do
        capture "$prefix/tc-qdisc-$iface.json" gw tc -j qdisc show dev "$iface"
        capture "$prefix/tc-filter-$iface.json" gw tc -j filter show dev "$iface"
    done
}

new_namespace provider
veth provider "${host_links[1]}" 1
provider ip route add default via 172.31.1.1
provider ip link add wgp type wireguard
provider wg set wgp private-key "$private/provider.key" listen-port 51820 \
    peer "$gw_exit_pub" allowed-ips 10.2.0.2/32
provider ip addr add 10.2.0.1/24 dev wgp
provider ip link set wgp up
provider sysctl -q -w net.ipv4.conf.wgp.rp_filter=0 net.ipv4.ip_forward=1
provider nft -f - <<'NFT'
table ip provider_nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "eth0" masquerade
    }
}
NFT

create_gateway
resolver gw
scupper rules > "$private/policy.nft"
gw nft -f "$private/policy.nft"

new_namespace client
veth client "${host_links[2]}" 2
client ip route add 172.31.0.2/32 via 172.31.2.1
client ip link add wg0 type wireguard
client wg set wg0 private-key "$private/client.key" peer "$gw_client_pub" \
    endpoint 172.31.0.2:51820 allowed-ips 0.0.0.0/0
client ip addr add 10.99.0.2/32 dev wg0
client ip link set wg0 up
client sysctl -q -w net.ipv4.conf.wg0.rp_filter=0
client ip route add default dev wg0
resolver client
wait_exit

begin_case healthy
expect 0 healthy
capture_links healthy
capture healthy/nft-live.json gw nft -j list ruleset
# The anonymous namespace's shell expands $1, passed as a positional argument.
# shellcheck disable=SC2016
capture healthy/nft-want.json timeout 60 ip netns exec gw unshare --net -- \
    bash -o pipefail -c '"$1" rules | nft -f - && nft -j list ruleset' bash "$binary"
capture healthy/ip-default.json gw ip -j route show default
capture healthy/ip-policy-route.txt gw ip route get 1.1.1.1 from 10.99.0.2 iif wg0
capture healthy/wg-handshakes.txt gw wg show proton0 latest-handshakes
capture healthy/wg-allowed-ips.txt gw wg show wg0 allowed-ips
capture healthy/status.txt scupper status
capture healthy/client-exit-ip.txt timeout 20 ip netns exec client \
    curl --noproxy '*' -4 -sS --max-time 15 https://ifconfig.me/ip
record client-curl 0 "$CAPTURE_CODE" "$(head -n 1 "$captures/healthy/client-exit-ip.txt")"
check_ip=$(sed -n 's/^connected through \([^,]*\), kill switch in place$/\1/p' "$captures/check-healthy.txt")
client_ip=$(tr -d '\r\n' < "$captures/healthy/client-exit-ip.txt")
if [[ -n $check_ip && $client_ip == "$check_ip" ]]; then
    record client-exit-matches 0 0 'client and check exit IPs agree'
else
    record client-exit-matches 0 1 'client and check exit IPs differ or check did not report an IP'
fi

begin_case bug-4
gw ip rule del priority 1000
expect 3 bug-4
heal bug-4

begin_case tunnel-deleted
gw ip link del proton0
expect 4 tunnel-deleted
heal tunnel-deleted

begin_case exit-link-down
gw ip link set proton0 down
capture_links case-04
expect 4 exit-link-down
heal exit-link-down

begin_case ruleset-missing-tunnel-down
gw ip link del proton0
gw nft flush ruleset
expect 2 ruleset-missing-tunnel-down
heal ruleset-missing-tunnel-down

begin_case extra-accept
gw nft 'add rule inet scupper forward iifname "wg0" oifname "eth0" accept'
capture case-06-nft.json gw nft -j list ruleset
expect 2 extra-accept
heal extra-accept

# Positive control for the leak detector: with rule 1000 gone and an eth0 accept, client
# traffic really leaves un-NATed via eth0, so the capture must see it.
begin_case leak-control
gw ip rule del priority 1000
gw nft 'add rule inet scupper forward iifname "wg0" oifname "eth0" accept'
expect 2 leak-control
if (( last_count > 0 )); then
    record leak-control-detector-sees-leak 1 1 "$last_count un-NATed packets captured"
else
    record leak-control-detector-sees-leak 1 0 'detector saw nothing during a real leak'
fi
heal leak-control

begin_case unconstrained-ct
gw nft 'add rule inet scupper forward ct state established,related accept'
capture case-07-nft.json gw nft -j list ruleset
expect 2 unconstrained-ct
heal unconstrained-ct

begin_case dup
# nft rejects dup in the inet family ("unsupported family"), so a foreign ip table carries it.
if optional_fault dup gw nft -f - <<'NFT'
table ip foreign_dup {
    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "wg0" dup to 172.31.0.1 device "eth0"
    }
}
NFT
then
    capture case-08-nft.json gw nft -j list ruleset
    expect 2 dup
fi
heal dup

begin_case netdev-fwd
if optional_fault netdev-fwd gw nft -f - <<'NFT'
table netdev foreign {
    chain ingress {
        type filter hook ingress device "wg0" priority 0; policy accept;
        fwd to "eth0"
    }
}
NFT
then
    capture case-09-nft.json gw nft -j list ruleset
    expect 2 netdev-fwd
fi
heal netdev-fwd

begin_case tc-mirred
if optional_fault tc-mirred gw tc qdisc add dev wg0 clsact &&
    optional_fault tc-mirred gw tc filter add dev wg0 ingress matchall action mirred egress redirect dev eth0; then
    capture_links case-10
    # The collector queries root filters; also retain the actual ingress action.
    capture case-10/tc-filter-wg0-ingress.json gw tc -j filter show dev wg0 ingress
    expect 2 tc-mirred
fi
heal tc-mirred

begin_case config-disagreement
gw wg set wg0 peer "$client_pub" allowed-ips 10.99.0.3/32
expect 2 config-disagreement
heal config-disagreement

# Loading a legacy table cannot be undone by flushing it; use a fresh gw to heal.
if command -v iptables-legacy >/dev/null; then
    begin_case legacy-iptables
    if optional_fault legacy-iptables gw iptables-legacy -t mangle -L -n; then
        capture case-11-ip-tables-names.txt gw cat /proc/net/ip_tables_names
        expect 2 legacy-iptables
        # Deleting the host end first; a veth pair otherwise disappears asynchronously.
        ip link del "${host_links[0]}"
        ip netns del gw
        create_gateway
        heal legacy-iptables
    fi
else
    record legacy-iptables 2 skipped 'iptables-legacy is missing'
fi

(( mismatches == 0 ))
