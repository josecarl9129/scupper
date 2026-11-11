# Saved capture classification fixture

`capture-classification.pcap` is a classic Ethernet pcap written by tcpdump
4.99.3 / libpcap 1.10.3 from deterministic input records. Reproduce it with:

```console
python3 xtask/tests/fixtures/capture-classification.py /path/to/tcpdump
```

Offline `-r` generation needs no live traffic. This fixture proves oracle
classification of saved bidirectional records, not live capture modes,
socket buffering or kernel packet-loss behavior. The command regression
separately pins the exact production capture arguments.

The first 48 packets contain twelve valid WireGuard data frames per tunnel per
direction, with the lab's two endpoint pairs. Three further packets match the
positive-control injection: forbidden source, DNS marker and UDP payload marker.
The test uses the unchanged generated policies, including the 48-packet
baseline minimum, both WireGuard classes and exact injected-packet checks.
