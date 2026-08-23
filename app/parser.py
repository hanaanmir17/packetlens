"""
parser.py
---------
Pure packet-capture parsing and aggregation logic for PacketLens.

This module has NO Flask dependency and can be unit tested in isolation.
It uses Scapy to read real .pcap / .pcapng files and turns each packet
into a flat, JSON-serialisable "packet record" dictionary. Aggregation
helpers then operate on lists of those records (or a pandas DataFrame
built from them) to produce the summaries shown on the dashboard.

Packet record schema
---------------------
{
    "index": int,             # 0-based packet order in the capture
    "timestamp": float,       # epoch seconds (float, sub-second precision)
    "src_ip": str | None,
    "dst_ip": str | None,
    "protocol": str,          # "TCP" | "UDP" | "ICMP" | "ARP" | "OTHER"
    "src_port": int | None,
    "dst_port": int | None,
    "length": int,            # wire length of the packet, in bytes
    "tcp_flags": str | None,  # e.g. "S", "SA", "A", "PA", "FA", "R", ...
}
"""
from __future__ import annotations

from typing import Iterable, List, Dict, Any, Optional

import pandas as pd

# Scapy's layer modules must be imported before any PcapReader/rdpcap call
# is made: Scapy resolves a capture's link-layer type (e.g. Ethernet) to a
# Python class via a registry (conf.l2types) that these imports populate
# as a side effect. That resolution happens once, when the reader is
# opened -- importing the layers lazily *after* opening the reader is too
# late and silently decodes every packet as raw bytes instead of
# Ether/IP/TCP/etc. Importing them here, at module load time, guarantees
# the registry is ready before app.parser ever opens a capture file.
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP

PacketRecord = Dict[str, Any]


def _extract_record(pkt, index: int) -> PacketRecord:
    """Convert a single Scapy packet object into a packet record dict."""
    timestamp = float(pkt.time)
    length = len(pkt)

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if pkt.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = pkt[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = _flags_to_str(tcp_layer.flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp_layer = pkt[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "OTHER"
    elif pkt.haslayer(ARP):
        arp_layer = pkt[ARP]
        src_ip = arp_layer.psrc
        dst_ip = arp_layer.pdst
        protocol = "ARP"
    else:
        protocol = "OTHER"

    return {
        "index": index,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "tcp_flags": tcp_flags,
    }


def _flags_to_str(flags) -> str:
    """Render a Scapy TCP flags field as a short string like 'S', 'SA', 'PA'."""
    try:
        return str(flags)
    except Exception:
        return ""


def parse_pcap(path: str, max_packets: Optional[int] = None) -> List[PacketRecord]:
    """
    Parse a .pcap/.pcapng file at `path` using Scapy and return a list of
    packet record dicts (see module docstring for schema).

    Uses PcapReader for streaming so large files do not need to be fully
    loaded into memory at once. Pass `max_packets` to cap how many packets
    are read (useful for very large captures / quick previews).
    """
    from scapy.utils import PcapReader

    records: List[PacketRecord] = []
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader):
            if max_packets is not None and i >= max_packets:
                break
            try:
                records.append(_extract_record(pkt, i))
            except Exception:
                # Skip any packet scapy cannot fully decode rather than
                # aborting the whole upload.
                continue
    return records


def records_to_dataframe(records: Iterable[PacketRecord]) -> pd.DataFrame:
    """Build a pandas DataFrame from a list of packet records."""
    columns = [
        "index", "timestamp", "src_ip", "dst_ip", "protocol",
        "src_port", "dst_port", "length", "tcp_flags",
    ]
    df = pd.DataFrame(list(records), columns=columns)
    return df


# ---------------------------------------------------------------------------
# Aggregation helpers -- all pure functions of a DataFrame (or record list).
# ---------------------------------------------------------------------------

def total_packet_count(df: pd.DataFrame) -> int:
    return int(len(df))


def protocol_breakdown(df: pd.DataFrame) -> Dict[str, int]:
    """Return {protocol: packet_count}, sorted by count descending."""
    if df.empty:
        return {}
    counts = df["protocol"].value_counts()
    return {str(k): int(v) for k, v in counts.items()}


def traffic_over_time(df: pd.DataFrame, bucket_seconds: float = 1.0) -> List[Dict[str, Any]]:
    """
    Bucket packets into fixed-width time windows and return a list of
    {"bucket_start": float, "count": int} sorted by bucket_start.

    `bucket_seconds` controls the resolution (e.g. 1.0 for per-second,
    60.0 for per-minute). The first packet's timestamp is treated as t=0.
    """
    if df.empty:
        return []
    t0 = df["timestamp"].min()
    bucket_index = ((df["timestamp"] - t0) // bucket_seconds).astype(int)
    grouped = bucket_index.value_counts().sort_index()
    return [
        {"bucket_start": float(t0 + b * bucket_seconds), "count": int(c)}
        for b, c in grouped.items()
    ]


def top_n_by_count(df: pd.DataFrame, column: str, n: int = 10) -> List[Dict[str, Any]]:
    """Return the top-n most frequent values of `column` with their counts."""
    if df.empty or column not in df.columns:
        return []
    series = df[column].dropna()
    if series.empty:
        return []
    counts = series.value_counts().head(n)
    return [{"value": str(k), "count": int(v)} for k, v in counts.items()]


def top_talkers_by_bytes(df: pd.DataFrame, n: int = 10) -> List[Dict[str, Any]]:
    """
    Return the top-n source IPs ranked by total bytes sent (sum of packet
    lengths), as [{"ip": str, "bytes": int, "packets": int}, ...].
    """
    if df.empty:
        return []
    sub = df.dropna(subset=["src_ip"])
    if sub.empty:
        return []
    grouped = sub.groupby("src_ip").agg(
        bytes=("length", "sum"),
        packets=("length", "count"),
    ).sort_values("bytes", ascending=False).head(n)
    return [
        {"ip": str(ip), "bytes": int(row["bytes"]), "packets": int(row["packets"])}
        for ip, row in grouped.iterrows()
    ]


def summarize(records: Iterable[PacketRecord]) -> Dict[str, Any]:
    """Build the full dashboard summary dict from a list of packet records."""
    df = records_to_dataframe(records)
    return {
        "total_packets": total_packet_count(df),
        "protocol_breakdown": protocol_breakdown(df),
        "traffic_over_time": traffic_over_time(df, bucket_seconds=_pick_bucket_size(df)),
        "top_sources": top_n_by_count(df, "src_ip", 10),
        "top_destinations": top_n_by_count(df, "dst_ip", 10),
        "top_talkers_bytes": top_talkers_by_bytes(df, 10),
    }


def _pick_bucket_size(df: pd.DataFrame) -> float:
    """Choose a sensible time-bucket width based on the capture's duration."""
    if df.empty:
        return 1.0
    duration = float(df["timestamp"].max() - df["timestamp"].min())
    if duration <= 60:
        return 1.0
    if duration <= 60 * 30:
        return 5.0
    if duration <= 60 * 60 * 6:
        return 60.0
    return 300.0
