"""
Tests for app.parser: real Scapy parsing against the synthetic sample
capture (correct total count, correct protocol breakdown), plus pure
aggregation-logic tests against small hand-built record lists.
"""
from app.parser import (
    parse_pcap,
    records_to_dataframe,
    protocol_breakdown,
    traffic_over_time,
    top_n_by_count,
    top_talkers_by_bytes,
    total_packet_count,
    summarize,
)

from tests.conftest import (
    EXPECTED_TOTAL_PACKETS,
    EXPECTED_TCP,
    EXPECTED_UDP,
    EXPECTED_ICMP,
    EXPECTED_ARP,
)


# ---------------------------------------------------------------------------
# Parsing the real, generated sample capture with Scapy
# ---------------------------------------------------------------------------

def test_total_packet_count_matches_generated_capture(sample_records):
    assert len(sample_records) == EXPECTED_TOTAL_PACKETS


def test_protocol_breakdown_counts_are_correct(sample_records):
    df = records_to_dataframe(sample_records)
    breakdown = protocol_breakdown(df)
    assert breakdown["TCP"] == EXPECTED_TCP
    assert breakdown["UDP"] == EXPECTED_UDP
    assert breakdown["ICMP"] == EXPECTED_ICMP
    assert breakdown["ARP"] == EXPECTED_ARP


def test_summarize_total_packets_matches(sample_records):
    summary = summarize(sample_records)
    assert summary["total_packets"] == EXPECTED_TOTAL_PACKETS


def test_record_schema_has_expected_keys(sample_records):
    expected_keys = {
        "index", "timestamp", "src_ip", "dst_ip", "protocol",
        "src_port", "dst_port", "length", "tcp_flags",
    }
    assert expected_keys.issubset(sample_records[0].keys())


def test_tcp_packet_has_ports_and_flags(sample_records):
    tcp_pkt = next(r for r in sample_records if r["protocol"] == "TCP")
    assert tcp_pkt["src_port"] is not None
    assert tcp_pkt["dst_port"] is not None
    assert tcp_pkt["tcp_flags"] is not None


def test_udp_packet_has_ports_no_flags(sample_records):
    udp_pkt = next(r for r in sample_records if r["protocol"] == "UDP")
    assert udp_pkt["src_port"] is not None
    assert udp_pkt["dst_port"] is not None
    assert udp_pkt["tcp_flags"] is None


def test_icmp_packet_has_no_ports(sample_records):
    icmp_pkt = next(r for r in sample_records if r["protocol"] == "ICMP")
    assert icmp_pkt["src_port"] is None
    assert icmp_pkt["dst_port"] is None


def test_arp_packet_has_ips_but_no_ports(sample_records):
    arp_pkt = next(r for r in sample_records if r["protocol"] == "ARP")
    assert arp_pkt["src_ip"] is not None
    assert arp_pkt["dst_ip"] is not None
    assert arp_pkt["src_port"] is None
    assert arp_pkt["dst_port"] is None


def test_packet_lengths_are_positive(sample_records):
    assert all(r["length"] > 0 for r in sample_records)


def test_max_packets_limit_is_respected(sample_pcap_path):
    limited = parse_pcap(sample_pcap_path, max_packets=10)
    assert len(limited) == 10


def test_injected_port_scanner_appears_in_top_sources(sample_records):
    summary = summarize(sample_records)
    ips = {row["value"] for row in summary["top_sources"]}
    assert "203.0.113.77" in ips  # the port-scan attacker IP


def test_injected_flood_source_appears_in_top_talkers(sample_records):
    summary = summarize(sample_records)
    ips = {row["ip"] for row in summary["top_talkers_bytes"]}
    assert "198.51.100.23" in ips  # the flood source IP


# ---------------------------------------------------------------------------
# Pure aggregation-logic tests on small, hand-built record lists
# ---------------------------------------------------------------------------

def _rec(i, ts, src, dst, proto, sport=None, dport=None, length=100, flags=None):
    return {
        "index": i, "timestamp": ts, "src_ip": src, "dst_ip": dst,
        "protocol": proto, "src_port": sport, "dst_port": dport,
        "length": length, "tcp_flags": flags,
    }


def test_total_packet_count_on_empty_dataframe():
    df = records_to_dataframe([])
    assert total_packet_count(df) == 0


def test_protocol_breakdown_simple_counts():
    records = [
        _rec(0, 0.0, "1.1.1.1", "2.2.2.2", "TCP"),
        _rec(1, 0.1, "1.1.1.1", "2.2.2.2", "UDP"),
        _rec(2, 0.2, "1.1.1.1", "2.2.2.2", "TCP"),
    ]
    df = records_to_dataframe(records)
    assert protocol_breakdown(df) == {"TCP": 2, "UDP": 1}


def test_traffic_over_time_bucketing():
    records = [_rec(i, i * 0.5, "1.1.1.1", "2.2.2.2", "TCP") for i in range(10)]
    df = records_to_dataframe(records)
    buckets = traffic_over_time(df, bucket_seconds=1.0)
    assert sum(b["count"] for b in buckets) == 10
    assert len(buckets) == 5


def test_top_n_by_count_orders_by_frequency():
    records = (
        [_rec(i, i, "1.1.1.1", "9.9.9.9", "TCP") for i in range(5)]
        + [_rec(i + 5, i, "2.2.2.2", "9.9.9.9", "TCP") for i in range(2)]
    )
    df = records_to_dataframe(records)
    top = top_n_by_count(df, "src_ip", 10)
    assert top[0] == {"value": "1.1.1.1", "count": 5}
    assert top[1] == {"value": "2.2.2.2", "count": 2}


def test_top_talkers_by_bytes_ranks_by_total_length():
    records = [
        _rec(0, 0.0, "1.1.1.1", "2.2.2.2", "TCP", length=1000),
        _rec(1, 0.1, "3.3.3.3", "2.2.2.2", "TCP", length=100),
        _rec(2, 0.2, "1.1.1.1", "2.2.2.2", "TCP", length=500),
    ]
    df = records_to_dataframe(records)
    talkers = top_talkers_by_bytes(df, 10)
    assert talkers[0]["ip"] == "1.1.1.1"
    assert talkers[0]["bytes"] == 1500
    assert talkers[0]["packets"] == 2
