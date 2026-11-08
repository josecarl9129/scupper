#!/usr/bin/env bash
# Host-only observations; run after the namespace lab on a disposable VM.
set -euo pipefail
export LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_PAGER=cat

if [[ $# != 1 || $EUID != 0 ]]; then
    echo "Usage (root, disposable VM only): $0 <capture-dir>" >&2
    exit 1
fi
umask 022
mkdir -p -- "$1"
captures=$(realpath -- "$1")
results="$captures/v23.tsv"
printf 'question\tresult\n' > "$results"
dropin=/etc/systemd/system/nftables.service.d/10-noflush.conf
dropin_created=0
dropin_dir_created=0
service_touched=0
probe_owned=0

record() {
    local answer=$2
    answer=${answer//$'\n'/; }
    answer=${answer//$'\t'/ }
    answer=${answer//$'\r'/ }
    printf '%s\t%s\n' "$1" "$answer" >> "$results"
}
fail() { record error "$1"; echo "$1" >&2; exit 1; }
service() { timeout --kill-after=5 45 systemctl "$@"; }
firewall() { timeout --kill-after=2 10 nft "$@"; }
probe_survives() {
    local tables
    tables=$(firewall list tables)
    if grep -qx 'table inet v23probe' <<< "$tables"; then
        record "$1" yes
    else
        record "$1" no
    fi
}
cleanup() {
    local code=$? failed=0 tables
    trap - EXIT
    set +e
    if (( service_touched )); then service stop nftables || failed=1; fi
    if (( probe_owned )); then
        if tables=$(firewall list tables); then
            if grep -qx 'table inet v23probe' <<< "$tables"; then
                firewall delete table inet v23probe || failed=1
            fi
        else
            failed=1
        fi
    fi
    if (( dropin_created )); then
        rm -f -- "$dropin" || failed=1
        service daemon-reload || failed=1
    fi
    if (( dropin_dir_created )); then rmdir -- "${dropin%/*}" || failed=1; fi
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
tables=$(firewall list tables)
if grep -qx 'table inet v23probe' <<< "$tables"; then fail 'v23probe already exists'; fi
service cat nftables > "$captures/v23-unit.txt"
exec_stop=$(awk '/^[[:space:]]*ExecStop=/ { print }' "$captures/v23-unit.txt")
record stock-unit-ExecStop "${exec_stop:-(none)}"

# Establish an inactive baseline so that both trials execute ExecStart/ExecStop.
service_touched=1
service stop nftables
service start nftables
probe_owned=1
firewall add table inet v23probe
service stop nftables
probe_survives stock-stop-v23probe-survives
# A non-flushing stock unit is a valid observation; reset only our probe.
tables=$(firewall list tables)
if grep -qx 'table inet v23probe' <<< "$tables"; then firewall delete table inet v23probe; fi

if [[ ! -d ${dropin%/*} ]]; then
    mkdir -- "${dropin%/*}"
    dropin_dir_created=1
fi
dropin_created=1
printf '[Service]\nExecStop=\n' > "$dropin"
service daemon-reload
service start nftables
firewall add table inet v23probe
service stop nftables
probe_survives noflush-stop-v23probe-survives
rm -- "$dropin"
# Keep ownership until daemon-reload succeeds, including on an error path.
service daemon-reload
dropin_created=0

# Test the package's stock restart policy, without the no-flush override.
service start nftables
# ExecStart may or may not have flushed the table surviving the previous trial.
tables=$(firewall list tables)
if ! grep -qx 'table inet v23probe' <<< "$tables"; then firewall add table inet v23probe; fi
before=$(service show nftables --property=ActiveEnterTimestampMonotonic --value)
[[ $before =~ ^[1-9][0-9]*$ ]] || fail 'No active nftables timestamp before reinstall'
timeout --kill-after=5 180 env DEBIAN_FRONTEND=noninteractive \
    apt-get install --reinstall -y nftables > "$captures/v23-reinstall.txt" 2>&1
after=$(service show nftables --property=ActiveEnterTimestampMonotonic --value)
[[ $after =~ ^[0-9]+$ ]] || fail 'Invalid nftables timestamp after reinstall'
record reinstall-active-timestamp-before "$before"
record reinstall-active-timestamp-after "$after"
if [[ $before != "$after" ]]; then
    record reinstall-unit-restarted yes
else
    record reinstall-unit-restarted no
fi
probe_survives reinstall-v23probe-survives
