"""
Shared pytest fixtures for the PacketLens test suite.

The `sample_pcap_path` / `sample_records` fixtures build the same synthetic
capture that `generate_sample_pcap.py` writes to disk (normal traffic +
an injected port scan + an injected flood), so the parser tests exercise
the real Scapy parsing path end-to-end against a deterministic capture.
"""
import os
import sys

import pytest

# Make the project root importable (for `generate_sample_pcap` and `app`).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from generate_sample_pcap import build_normal_traffic, build_port_scan, build_flood, BASE_TIME  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402
from app.parser import parse_pcap  # noqa: E402

EXPECTED_TOTAL_PACKETS = 634
EXPECTED_TCP = 580
EXPECTED_UDP = 30
EXPECTED_ICMP = 20
EXPECTED_ARP = 4


@pytest.fixture(scope="session")
def sample_pcap_path(tmp_path_factory):
    packets = []
    t = BASE_TIME
    t = build_normal_traffic(packets, t)
    t = build_port_scan(packets, t)
    t = build_flood(packets, t)
    packets.sort(key=lambda p: p.time)

    out_dir = tmp_path_factory.mktemp("pcaps")
    out_path = out_dir / "sample_capture.pcap"
    wrpcap(str(out_path), packets)
    return str(out_path)


@pytest.fixture(scope="session")
def sample_records(sample_pcap_path):
    return parse_pcap(sample_pcap_path)
