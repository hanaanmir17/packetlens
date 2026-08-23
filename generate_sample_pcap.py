#!/usr/bin/env python3
"""
generate_sample_pcap.py
------------------------
Crafts a synthetic .pcap file with Scapy so that PacketLens can be
demonstrated end-to-end without needing a real network capture.

The generated capture contains:
  * "Normal" background traffic: several clients completing full TCP
    three-way handshakes with a couple of servers, some UDP (DNS-style)
    request/response pairs, ICMP echo request/reply pairs, and a couple
    of ARP requests.
  * An injected TCP port-scan pattern: a single attacker IP sends lone
    SYN packets (no ACK, no data) to ~40 different destination ports on
    one victim IP within a two-second window, with no completed
    handshakes -- the classic signature the port-scan detector looks for.
  * An injected flood pattern: a single source IP bursts a very large
    number of packets at one destination in under a second, well above
    the average traffic rate of every other pair in the capture -- the
    signature the flood detector looks for.

Usage:
    python generate_sample_pcap.py [output_path]

Default output path: sample_data/sample_capture.pcap
"""
import os
import sys

from scapy.all import wrpcap
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

BASE_TIME = 1_700_000_000.0  # arbitrary fixed epoch so runs are reproducible


def _stamp(pkt, t):
    pkt.time = t
    return pkt


def _eth(pkt):
    """Wrap an L3 packet in an Ethernet frame so the whole capture uses a
    single, consistent link-layer type (DLT_EN10MB) -- pcap files have one
    global linktype, so mixing raw-IP and Ethernet-framed packets would
    make the non-Ethernet ones unreadable."""
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / pkt


def build_normal_traffic(packets, t):
    """A handful of ordinary TCP/UDP/ICMP/ARP flows between a few hosts."""
    clients = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"]
    servers = ["93.184.216.34", "142.250.72.14"]  # example.com-ish, google-ish

    # --- Full TCP handshakes + a little data, repeated a number of times ---
    for i in range(40):
        client = clients[i % len(clients)]
        server = servers[i % len(servers)]
        cport = 40000 + i
        sport = 443 if i % 2 == 0 else 80

        syn = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="S", seq=1000 + i)
        synack = IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="SA", seq=5000 + i, ack=1001 + i)
        ack = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="A", seq=1001 + i, ack=5001 + i)
        data = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="PA", seq=1001 + i, ack=5001 + i) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        finack = IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="FA", seq=5001 + i, ack=1021 + i)
        finlast = IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="A", seq=1021 + i, ack=5002 + i)

        for j, pkt in enumerate([syn, synack, ack, data, finack, finlast]):
            packets.append(_stamp(_eth(pkt), t))
            t += 0.01
        t += 0.15

    # --- UDP "DNS-style" request/response pairs ---
    for i in range(15):
        client = clients[i % len(clients)]
        req = IP(src=client, dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / Raw(load=b"\xaa\xaa\x01\x00\x00\x01example")
        resp = IP(src="8.8.8.8", dst=client) / UDP(sport=53, dport=50000 + i) / Raw(load=b"\xaa\xaa\x81\x80\x00\x01\x00\x01")
        packets.append(_stamp(_eth(req), t)); t += 0.02
        packets.append(_stamp(_eth(resp), t)); t += 0.2

    # --- ICMP echo request/reply pairs ---
    for i in range(10):
        client = clients[i % len(clients)]
        echo = IP(src=client, dst="1.1.1.1") / ICMP(type=8, id=i, seq=1)
        reply = IP(src="1.1.1.1", dst=client) / ICMP(type=0, id=i, seq=1)
        packets.append(_stamp(_eth(echo), t)); t += 0.02
        packets.append(_stamp(_eth(reply), t)); t += 0.3

    # --- A couple of ARP requests (who-has) ---
    for i in range(4):
        arp = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=clients[i % len(clients)], pdst="10.0.0.1", op=1)
        packets.append(_stamp(arp, t)); t += 0.5

    return t


def build_port_scan(packets, t):
    """A single attacker sweeping ~40 ports on one victim with lone SYNs."""
    attacker = "203.0.113.77"
    victim = "10.0.0.50"
    for port in range(20, 60):
        syn = IP(src=attacker, dst=victim) / TCP(sport=51000, dport=port, flags="S", seq=9000 + port)
        packets.append(_stamp(_eth(syn), t))
        t += 0.03  # ~40 ports inside ~1.2 seconds -> well within a 10s window
    return t


def build_flood(packets, t):
    """A single source blasting a victim with far more packets than any
    other pair in the capture sees in the same window."""
    attacker = "198.51.100.23"
    victim = "10.0.0.60"
    for i in range(300):
        pkt = IP(src=attacker, dst=victim) / TCP(sport=6000 + (i % 50), dport=80, flags="S", seq=i)
        packets.append(_stamp(_eth(pkt), t))
        t += 0.005  # 300 packets in 1.5s -> a clear volumetric spike
    return t


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "sample_data", "sample_capture.pcap"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    packets = []
    t = BASE_TIME
    t = build_normal_traffic(packets, t)
    t = build_port_scan(packets, t)
    t = build_flood(packets, t)

    packets.sort(key=lambda p: p.time)

    wrpcap(out_path, packets)
    print(f"Wrote {len(packets)} packets to {out_path}")


if __name__ == "__main__":
    main()
