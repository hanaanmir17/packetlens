"""
Tests for app.anomaly: pure detection functions exercised against small,
hand-constructed synthetic packet-record lists (no pcap files involved).

Each detector is tested for both the "should fire" case (a clear,
deliberately-built attack pattern) and the "should stay quiet" case
(clearly normal traffic that must not be flagged as a false positive).
"""
from app.anomaly import detect_port_scans, detect_flood, run_all_detections


def _rec(i, ts, src, dst, proto="TCP", sport=None, dport=None, length=60, flags=None):
    return {
        "index": i, "timestamp": ts, "src_ip": src, "dst_ip": dst,
        "protocol": proto, "src_port": sport, "dst_port": dport,
        "length": length, "tcp_flags": flags,
    }


# ---------------------------------------------------------------------------
# Port scan detection
# ---------------------------------------------------------------------------

def test_port_scan_pattern_is_detected():
    records = [
        _rec(i, i * 0.05, "9.9.9.9", "10.0.0.5", sport=4444, dport=1000 + i, flags="S")
        for i in range(30)
    ]
    findings = detect_port_scans(records, port_threshold=15, time_window=10.0)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "port_scan"
    assert finding["src_ip"] == "9.9.9.9"
    assert finding["dst_ip"] == "10.0.0.5"
    assert finding["evidence"]["distinct_ports_contacted"] >= 15
    assert finding["evidence"]["syn_ratio"] == 1.0


def test_normal_single_service_traffic_is_not_flagged_as_port_scan():
    """A client repeatedly hitting the SAME port (e.g. web browsing) with
    completed handshakes must never be mistaken for a port scan."""
    records = []
    idx = 0
    for i in range(20):
        records.append(_rec(idx, idx * 0.1, "1.1.1.1", "2.2.2.2", sport=5000 + i, dport=80, flags="S")); idx += 1
        records.append(_rec(idx, idx * 0.1, "2.2.2.2", "1.1.1.1", sport=80, dport=5000 + i, flags="SA")); idx += 1
        records.append(_rec(idx, idx * 0.1, "1.1.1.1", "2.2.2.2", sport=5000 + i, dport=80, flags="A")); idx += 1
    findings = detect_port_scans(records, port_threshold=15, time_window=10.0)
    assert findings == []


def test_completed_handshakes_across_many_ports_are_not_flagged():
    """Many distinct ports contacted, but every connection completes a
    real three-way handshake -- this is NOT a scan and must not fire."""
    records = []
    idx = 0
    for port in range(20):
        records.append(_rec(idx, idx * 0.05, "9.9.9.9", "10.0.0.5", sport=4000, dport=port, flags="S")); idx += 1
        records.append(_rec(idx, idx * 0.05, "10.0.0.5", "9.9.9.9", sport=port, dport=4000, flags="SA")); idx += 1
        records.append(_rec(idx, idx * 0.05, "9.9.9.9", "10.0.0.5", sport=4000, dport=port, flags="A")); idx += 1
    findings = detect_port_scans(records, port_threshold=15, time_window=10.0, min_syn_ratio=0.8)
    assert findings == []


def test_port_scan_below_threshold_is_not_flagged():
    records = [
        _rec(i, i * 0.05, "9.9.9.9", "10.0.0.5", sport=4444, dport=1000 + i, flags="S")
        for i in range(5)  # well below the default threshold of 15
    ]
    findings = detect_port_scans(records, port_threshold=15, time_window=10.0)
    assert findings == []


def test_port_scan_spread_outside_time_window_is_not_flagged():
    """The same number of distinct ports, but spread out slowly, should
    not trigger the scan detector (no burst within the window)."""
    records = [
        _rec(i, i * 30.0, "9.9.9.9", "10.0.0.5", sport=4444, dport=1000 + i, flags="S")
        for i in range(20)
    ]
    findings = detect_port_scans(records, port_threshold=15, time_window=10.0)
    assert findings == []


def test_port_scan_detector_ignores_non_tcp_traffic():
    records = [
        _rec(i, i * 0.05, "9.9.9.9", "10.0.0.5", proto="UDP", sport=4444, dport=1000 + i)
        for i in range(30)
    ]
    findings = detect_port_scans(records)
    assert findings == []


def test_port_scan_detector_handles_empty_input():
    assert detect_port_scans([]) == []


# ---------------------------------------------------------------------------
# Flood / volumetric detection
# ---------------------------------------------------------------------------

def test_flood_pattern_is_detected():
    records = []
    idx = 0
    # 20 ordinary, low-volume (src, dst) pairs as a baseline
    for j in range(20):
        for i in range(4):
            records.append(_rec(idx, float(i), f"1.1.1.{j}", "2.2.2.2")); idx += 1
    # one source blasting a victim far above the baseline rate
    for i in range(300):
        records.append(_rec(idx, i * 0.005, "9.9.9.9", "3.3.3.3")); idx += 1

    findings = detect_flood(records, multiplier=5.0, time_window=10.0, min_packets=50)
    assert len(findings) == 1
    assert findings[0]["type"] == "flood"
    assert findings[0]["src_ip"] == "9.9.9.9"
    assert findings[0]["dst_ip"] == "3.3.3.3"
    assert findings[0]["evidence"]["peak_packets_in_window"] == 300


def test_balanced_normal_traffic_is_not_flagged_as_flood():
    records = []
    idx = 0
    for j in range(20):
        for i in range(10):
            records.append(_rec(idx, float(i), f"1.1.1.{j}", "2.2.2.2")); idx += 1
    findings = detect_flood(records, multiplier=5.0, time_window=10.0, min_packets=50)
    assert findings == []


def test_flood_respects_absolute_minimum_packet_floor():
    """A burst that is proportionally large but too small in absolute
    terms should not be flagged -- avoids noise on quiet captures."""
    records = [_rec(i, float(i) * 0.5, "1.1.1.1", "2.2.2.2") for i in range(2)]
    records += [_rec(100 + i, i * 0.01, "9.9.9.9", "3.3.3.3") for i in range(20)]
    findings = detect_flood(records, multiplier=1.0, time_window=10.0, min_packets=50)
    assert findings == []


def test_flood_detector_handles_empty_input():
    assert detect_flood([]) == []


def test_flood_detector_handles_single_pair_no_baseline():
    records = [_rec(i, i * 0.01, "9.9.9.9", "3.3.3.3") for i in range(10)]
    # With only one pair there is nothing to compare against; average
    # equals the pair's own count so it can never exceed multiplier*average.
    findings = detect_flood(records, multiplier=5.0, time_window=10.0, min_packets=5)
    assert findings == []


# ---------------------------------------------------------------------------
# Combined detection entry point
# ---------------------------------------------------------------------------

def test_run_all_detections_reports_port_scan():
    records = [
        _rec(i, i * 0.05, "9.9.9.9", "10.0.0.5", sport=4444, dport=1000 + i, flags="S")
        for i in range(30)
    ]
    result = run_all_detections(records)
    assert result["count"] == len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "port_scan"
    assert result["floods"] == []


def test_run_all_detections_on_clean_traffic_reports_nothing():
    records = []
    idx = 0
    for i in range(10):
        records.append(_rec(idx, idx * 0.1, "1.1.1.1", "2.2.2.2", sport=5000, dport=80, flags="S")); idx += 1
        records.append(_rec(idx, idx * 0.1, "2.2.2.2", "1.1.1.1", sport=80, dport=5000, flags="SA")); idx += 1
        records.append(_rec(idx, idx * 0.1, "1.1.1.1", "2.2.2.2", sport=5000, dport=80, flags="A")); idx += 1
    result = run_all_detections(records)
    assert result["count"] == 0
    assert result["findings"] == []


def test_run_all_detections_finding_messages_are_human_readable():
    records = [
        _rec(i, i * 0.05, "9.9.9.9", "10.0.0.5", sport=4444, dport=1000 + i, flags="S")
        for i in range(30)
    ]
    result = run_all_detections(records)
    message = result["findings"][0]["message"]
    assert "9.9.9.9" in message
    assert "10.0.0.5" in message
    assert isinstance(message, str) and len(message) > 20
