"""
anomaly.py
----------
Pure, dependency-light anomaly detection logic for PacketLens.

Every function here takes plain packet records (the list-of-dicts produced
by app.parser.parse_pcap, or an equivalent pandas DataFrame) and returns
plain-old-data findings. Nothing in this module touches Flask, the
filesystem, or Scapy directly, so it can be unit tested with small,
hand-built synthetic packet lists.

Two detectors are implemented:

1. Port scan detection (`detect_port_scans`)
   Flags a (source IP, destination IP) pair where the source contacts
   more than `port_threshold` distinct destination ports within a sliding
   `time_window`-second window, and the packets in that window are mostly
   lone SYN packets (flags == "S") rather than completed handshakes
   (SYN, SYN-ACK, ACK). That SYN-only signature is the classic fingerprint
   of a TCP connect/SYN scan (e.g. `nmap -sS`).

2. Flood / volumetric detection (`detect_flood`)
   Flags a (source IP, destination IP) pair whose packet rate in some
   sliding `time_window`-second window is more than `multiplier` times
   the average rate seen across all other (source, destination) pairs in
   the capture, provided it also clears an absolute floor of packets so
   that quiet captures do not produce noise.
"""
from __future__ import annotations

import statistics
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from app.parser import records_to_dataframe, PacketRecord

DEFAULT_PORT_THRESHOLD = 15
DEFAULT_SCAN_WINDOW_SECONDS = 10.0
DEFAULT_MIN_SYN_RATIO = 0.8

DEFAULT_FLOOD_MULTIPLIER = 5.0
DEFAULT_FLOOD_WINDOW_SECONDS = 10.0
DEFAULT_FLOOD_MIN_PACKETS = 50


def _as_dataframe(records) -> pd.DataFrame:
    if isinstance(records, pd.DataFrame):
        return records
    return records_to_dataframe(records)


def _max_sliding_window_count(sorted_times: List[float], window_seconds: float) -> int:
    """Return the largest number of timestamps that fall inside any
    contiguous `window_seconds`-wide window, given a sorted list of times."""
    if not sorted_times:
        return 0
    max_count = 0
    left = 0
    for right in range(len(sorted_times)):
        while sorted_times[right] - sorted_times[left] > window_seconds:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count


def detect_port_scans(
    records: Iterable[PacketRecord],
    port_threshold: int = DEFAULT_PORT_THRESHOLD,
    time_window: float = DEFAULT_SCAN_WINDOW_SECONDS,
    min_syn_ratio: float = DEFAULT_MIN_SYN_RATIO,
) -> List[Dict[str, Any]]:
    """
    Detect TCP port-scan behaviour: a source IP hitting many distinct
    destination ports on one destination IP in a short window, mostly with
    lone SYN packets (no completed three-way handshake).

    Returns a list of finding dicts, one per offending (src_ip, dst_ip) pair.
    """
    df = _as_dataframe(records)
    if df.empty or "protocol" not in df.columns:
        return []

    tcp_df = df[df["protocol"] == "TCP"]
    if tcp_df.empty:
        return []

    findings: List[Dict[str, Any]] = []

    for (src_ip, dst_ip), group in tcp_df.groupby(["src_ip", "dst_ip"], dropna=True):
        if src_ip is None or dst_ip is None:
            continue

        rows = group.sort_values("timestamp")[["timestamp", "dst_port", "tcp_flags"]].to_dict("records")
        n = len(rows)
        if n == 0:
            continue

        best: Optional[Dict[str, Any]] = None
        left = 0
        for right in range(n):
            while rows[right]["timestamp"] - rows[left]["timestamp"] > time_window:
                left += 1
            window_rows = rows[left:right + 1]
            distinct_ports = {r["dst_port"] for r in window_rows if r["dst_port"] is not None}

            if len(distinct_ports) >= port_threshold:
                total = len(window_rows)
                syn_only = sum(1 for r in window_rows if r["tcp_flags"] == "S")
                syn_ratio = syn_only / total if total else 0.0

                if syn_ratio >= min_syn_ratio:
                    if best is None or len(distinct_ports) > best["distinct_ports"]:
                        best = {
                            "distinct_ports": len(distinct_ports),
                            "packets_in_window": total,
                            "syn_ratio": syn_ratio,
                            "start_time": window_rows[0]["timestamp"],
                            "end_time": window_rows[-1]["timestamp"],
                        }

        if best is not None:
            findings.append({
                "type": "port_scan",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "evidence": {
                    "distinct_ports_contacted": best["distinct_ports"],
                    "packets_in_window": best["packets_in_window"],
                    "syn_ratio": round(best["syn_ratio"], 3),
                    "window_seconds": time_window,
                    "start_time": best["start_time"],
                    "end_time": best["end_time"],
                },
                "message": (
                    f"Source {src_ip} contacted {best['distinct_ports']} distinct ports on "
                    f"{dst_ip} within {time_window:.0f}s, {best['syn_ratio'] * 100:.0f}% of those "
                    f"packets were lone SYN packets with no completed handshake. This matches the "
                    f"signature of a TCP port scan (e.g. an nmap SYN scan)."
                ),
            })

    return findings


def detect_flood(
    records: Iterable[PacketRecord],
    multiplier: float = DEFAULT_FLOOD_MULTIPLIER,
    time_window: float = DEFAULT_FLOOD_WINDOW_SECONDS,
    min_packets: int = DEFAULT_FLOOD_MIN_PACKETS,
) -> List[Dict[str, Any]]:
    """
    Detect flood / volumetric behaviour: a (src_ip, dst_ip) pair whose peak
    packet rate in a sliding `time_window`-second window is more than
    `multiplier` times the average peak rate of all other pairs, and which
    also clears an absolute `min_packets` floor.

    Returns a list of finding dicts, one per offending (src_ip, dst_ip) pair.
    """
    df = _as_dataframe(records)
    if df.empty:
        return []

    sub = df.dropna(subset=["src_ip", "dst_ip"])
    if sub.empty:
        return []

    pair_max_counts: Dict[Tuple[str, str], int] = {}
    for (src_ip, dst_ip), group in sub.groupby(["src_ip", "dst_ip"]):
        times = sorted(group["timestamp"].tolist())
        pair_max_counts[(src_ip, dst_ip)] = _max_sliding_window_count(times, time_window)

    if not pair_max_counts:
        return []

    counts = list(pair_max_counts.values())
    average = statistics.mean(counts)

    findings: List[Dict[str, Any]] = []
    if average <= 0:
        return findings

    for (src_ip, dst_ip), max_count in pair_max_counts.items():
        if max_count >= min_packets and max_count > multiplier * average:
            findings.append({
                "type": "flood",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "evidence": {
                    "peak_packets_in_window": max_count,
                    "window_seconds": time_window,
                    "average_peak_across_pairs": round(average, 2),
                    "multiplier_over_average": round(max_count / average, 2),
                },
                "message": (
                    f"Source {src_ip} sent {max_count} packets to {dst_ip} within a single "
                    f"{time_window:.0f}s window — about {max_count / average:.1f}x the average "
                    f"peak rate ({average:.1f} packets) seen across all other source/destination "
                    f"pairs in this capture. This volume spike is consistent with a flood "
                    f"(e.g. a SYN flood or other denial-of-service style burst)."
                ),
            })

    return findings


def run_all_detections(
    records: Iterable[PacketRecord],
    port_scan_kwargs: Optional[Dict[str, Any]] = None,
    flood_kwargs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run every detector and return a combined findings payload."""
    df = _as_dataframe(records)
    port_scans = detect_port_scans(df, **(port_scan_kwargs or {}))
    floods = detect_flood(df, **(flood_kwargs or {}))
    all_findings = port_scans + floods
    return {
        "findings": all_findings,
        "port_scans": port_scans,
        "floods": floods,
        "count": len(all_findings),
    }
