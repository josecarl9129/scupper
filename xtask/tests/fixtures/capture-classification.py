"""Reproduce the saved classification records without root or live traffic.

Usage: python3 xtask/tests/fixtures/capture-classification.py /path/to/tcpdump
Temporary files stay in this directory; only the classification pcap remains.
"""

import ipaddress
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def ip4(source, destination, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
        ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed,
    ))
    checksum = sum(struct.unpack("!10H", header))
    checksum = (checksum & 0xffff) + (checksum >> 16)
    header[10:12] = struct.pack("!H", (~checksum) & 0xffff)
    return bytes(header) + udp


def ethernet(payload, outgoing):
    local = bytes.fromhex("020000000002")
    remote = bytes.fromhex("020000000001")
    return (remote + local if outgoing else local + remote) + b"\x08\x00" + payload


directory = Path(__file__).resolve().parent
marker = b"scupper-canary-00112233445566778899aabbccddeeff"
packets = []
# Twelve records for each tunnel in each direction: a full 48-record baseline.
for _ in range(12):
    for peer, local_port in [("192.0.2.2", 51820), ("203.0.113.2", 51821)]:
        for outgoing in [True, False]:
            src, dst, sport, dport = ("198.51.100.2", peer, local_port, 51820)
            if not outgoing:
                src, dst, sport, dport = dst, src, dport, sport
            wg = b"\x04\x00\x00\x00" + bytes(28)
            packets.append(ethernet(ip4(src, dst, sport, dport, wg), outgoing))

# The same exact three datagrams as the lab's injection_packets helper.
dns = b"SC\x01\x00\x00\x01" + bytes(6)
for label in [marker, b"lab", b"test"]:
    dns += bytes([len(label)]) + label
dns += b"\x00\x00\x01\x00\x01"
for src, dst, sport, dport, payload in [
    ("10.99.0.2", "192.0.2.6", 40001, 8080, marker),
    ("198.51.100.2", "198.51.100.1", 40002, 53, dns),
    ("198.51.100.2", "198.51.100.1", 40003, 8080, marker),
]:
    packets.append(ethernet(ip4(src, dst, sport, dport, payload), True))

with tempfile.TemporaryDirectory(prefix="capture-classification-", dir=directory) as temporary:
    source = Path(temporary) / "traffic.pcap"
    data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
    for i, packet in enumerate(packets):
        data += struct.pack("<IIII", 1700000000 + i, 0, len(packet), len(packet)) + packet
    source.write_bytes(data)
    subprocess.run([
        sys.argv[1], "-n", "-Z", "root", "-U", "--immediate-mode", "-s", "0",
        "-r", str(source), "-w", str(directory / "capture-classification.pcap"),
    ], check=True)
