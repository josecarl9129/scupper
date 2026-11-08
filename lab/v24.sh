#!/usr/bin/env bash
# Host-only observations; never modify the main-table default route.
set -euo pipefail
export LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_PAGER=cat

if [[ $# != 1 || $EUID != 0 ]]; then
    echo "Usage (root, disposable VM only): $0 <capture-dir>" >&2
    exit 1
fi
umask 022
mkdir -p -- "$1"
captures=$(realpath -- "$1")
results="$captures/v24.tsv"
printf 'question\tresult\n' > "$results"
record() { printf '%s\t%s\n' "$1" "$2" >> "$results"; }
fail() { record error "$1"; echo "$1" >&2; exit 1; }
service() { timeout --kill-after=5 45 systemctl "$@"; }
net() { timeout --kill-after=2 10 ip "$@"; }

active_code=0
active=$(service is-active systemd-networkd) || active_code=$?
if [[ $active != active ]]; then
    case $active in
        inactive|failed|activating|deactivating|reloading|maintenance|unknown)
            record networkd "skipped: systemd-networkd is $active"
            exit 0
            ;;
        *) fail "Cannot query systemd-networkd (exit $active_code)" ;;
    esac
fi

dropin=/etc/systemd/networkd.conf.d/10-scupper.conf
dropin_created=0
dropin_dir_created=0
link_created=0
networkd_touched=0
private=''
route_present=no
rule_present=no
# Reading all tables succeeds even when table 51820 has ceased to exist.
observe() {
    local routes rules
    routes=$(net -N -4 route show table all) || return $?
    rules=$(net -N -4 rule show) || return $?
    route_present=no rule_present=no
    if grep -Eq '^default dev v24wg .*table 51820( |$)' <<< "$routes"; then route_present=yes; fi
    if grep -Eq '^1000:.* iif v24wg lookup 51820( |$)' <<< "$rules"; then rule_present=yes; fi
}
cleanup() {
    local code=$? failed=0
    trap - EXIT
    set +e
    if (( link_created )); then
        if observe; then
            if [[ $rule_present == yes ]]; then
                net -4 rule del iif v24wg lookup 51820 priority 1000 || failed=1
            fi
            if [[ $route_present == yes ]]; then
                net -4 route del default dev v24wg table 51820 || failed=1
            fi
        else
            failed=1
        fi
        net link del dev v24wg || failed=1
    fi
    if (( dropin_created )); then rm -f -- "$dropin" || failed=1; fi
    if (( dropin_dir_created )); then rmdir -- "${dropin%/*}" || failed=1; fi
    if [[ -n $private ]]; then rm -rf -- "$private" || failed=1; fi
    if (( networkd_touched )); then service restart systemd-networkd || failed=1; fi
    if (( failed )); then
        record cleanup failed
        if (( code == 0 )); then code=1; fi
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'record error "step failed at line $LINENO (exit $?)"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

[[ ! -e $dropin && ! -L $dropin ]] || fail "Refusing existing drop-in: $dropin"
links=$(net -o link show)
if grep -Eq '^[0-9]+: v24wg[:@]' <<< "$links"; then fail 'v24wg already exists'; fi
rules=$(net -N -4 rule show)
if grep -q '^1000:' <<< "$rules"; then fail 'Rule priority 1000 is already occupied'; fi
routes=$(net -N -4 route show table all)
if grep -Eq '(^| )table 51820( |$)' <<< "$routes"; then fail 'Routing table 51820 is already occupied'; fi

private=$(mktemp -d)
chmod 0700 "$private"
(umask 077; timeout --kill-after=2 10 wg genkey > "$private/key")
net link add dev v24wg type wireguard
link_created=1
timeout --kill-after=2 10 wg set v24wg private-key "$private/key"
net addr add 10.250.0.2/32 dev v24wg
net link set dev v24wg up
# Refuse a managed link: the experiment is specifically about foreign state.
deadline=$((SECONDS + 10))
while :; do
    if timeout --kill-after=2 10 networkctl --no-pager status v24wg \
        > "$captures/v24-link.txt" 2> "$captures/v24-link.stderr" &&
        grep -qw unmanaged "$captures/v24-link.txt"; then
        break
    fi
    if (( SECONDS >= deadline )); then fail 'v24wg did not become unmanaged within 10 seconds'; fi
    sleep 0.2
done
net -4 route add default dev v24wg table 51820
net -4 rule add iif v24wg lookup 51820 priority 1000

networkd_touched=1
service restart systemd-networkd
sleep 5
observe
record round-A-table-51820-route-survives "$route_present"
record round-A-rule-1000-survives "$rule_present"

if [[ $route_present == no ]]; then net -4 route add default dev v24wg table 51820; fi
if [[ $rule_present == no ]]; then net -4 rule add iif v24wg lookup 51820 priority 1000; fi
if [[ ! -d ${dropin%/*} ]]; then
    mkdir -- "${dropin%/*}"
    dropin_dir_created=1
fi
dropin_created=1
printf '[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n' > "$dropin"
service restart systemd-networkd
sleep 5
observe
record round-B-table-51820-route-survives "$route_present"
record round-B-rule-1000-survives "$rule_present"
# EXIT cleanup removes only the probe's resources, then restarts networkd.
