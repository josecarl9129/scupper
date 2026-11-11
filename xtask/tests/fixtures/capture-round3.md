# Round 3 capture regression fixtures

`capture-round3-old.pcap` and `capture-round3-new.pcap` are classic Ethernet
pcaps written by tcpdump 4.99.3 / libpcap 1.10.3 from the same deterministic
input stream. `capture-round3.py` constructs that stream and runs both writers:

```console
python3 xtask/tests/fixtures/capture-round3.py /path/to/tcpdump
```

The old writer uses `-U --immediate-mode -s 0`; the fixed writer uses
`-B 16384 -U --immediate-mode -s 0`. Both are unfiltered. Offline `-r` replaces the live `-i`
input so generation needs no privileges. This checks saved records and oracle
classification, not live socket buffering or kernel packet-loss behavior.
The command regression separately fixes the exact production capture arguments.

The first 48 packets contain twelve valid WireGuard data frames per tunnel per
direction, with the lab's two endpoint pairs. The remaining three packets match
the lab's positive-control injection: forbidden source, DNS marker and UDP
payload marker. The test uses the unchanged generated policies, including the
48-packet baseline minimum, both expected WireGuard classes and exact injected
packet checks. It compares the complete old/new oracle reports.
