# PacketLens

[![Portfolio Projects](https://img.shields.io/badge/Portfolio-Projects-2088FF?style=flat-square&logo=github&logoColor=white)](https://github.com/users/hanaanmir17/projects/2)

A packet capture analysis web tool. Upload a `.pcap` / `.pcapng` file and PacketLens parses it with Scapy, builds a traffic dashboard, and automatically flags suspicious behavior like port scans and traffic floods.

## Description

PacketLens is a small Flask web application built to demonstrate practical packet-analysis skills: reading real capture files, summarizing traffic the way you would in Wireshark's statistics views, and applying simple, explainable heuristics to catch two common attack patterns — TCP port scans and volumetric floods.

Every packet is genuinely parsed with Scapy (no mock or hardcoded data). The parsing and detection logic live in plain, framework-free Python functions so they can be unit tested directly.

## Features

- Upload a `.pcap` or `.pcapng` file through the browser
- Real parsing with Scapy (`PcapReader`), extracting per packet: timestamp, source/destination IP, protocol (TCP/UDP/ICMP/ARP/other), source/destination ports, packet length, and TCP flags
- Dashboard:
  - Total packet count
  - Protocol breakdown (pie chart)
  - Traffic over time (line chart, auto-bucketed based on capture duration)
  - Top 10 source IPs and top 10 destination IPs by packet count
  - Top talkers by total bytes sent
- Anomaly detection ("Findings" section), implemented as pure, testable functions:
  - **Port scan detection** — flags a source IP that contacts more than a configurable number of distinct destination ports on one destination IP within a short sliding time window, using mostly lone SYN packets (no completed handshake)
  - **Flood detection** — flags a source IP whose packet rate to one destination in a short window is an unusual multiple of the average rate across all other source/destination pairs in the capture
  - Each finding reports the offending IP(s), the supporting evidence (counts, ratios, timing), and a plain-language explanation
- `generate_sample_pcap.py` — crafts a synthetic demo capture (normal TCP/UDP/ICMP/ARP traffic plus an injected port scan and an injected flood) so the app can be demoed without a real network capture

## Tech stack

- **Backend:** Python, Flask
- **Packet parsing:** Scapy
- **Data aggregation:** pandas
- **Frontend:** Tailwind CSS (CDN) + Chart.js (CDN), server renders one page, all data comes from a JSON API endpoint
- **Testing:** pytest

## Project structure

```
packetlens/
├── app/
│   ├── __init__.py        # Flask application factory
│   ├── parser.py          # Scapy parsing + pandas aggregation (pure, no Flask)
│   ├── anomaly.py         # Port-scan / flood detection (pure, no Flask)
│   ├── routes.py          # HTTP routes / JSON API
│   └── templates/
│       └── index.html     # Dashboard UI (Tailwind + Chart.js)
├── tests/
│   ├── conftest.py
│   ├── test_parser.py
│   └── test_anomaly.py
├── sample_data/            # generated sample pcap lands here
├── generate_sample_pcap.py
├── wsgi.py
├── requirements.txt
├── Dockerfile
├── .github/workflows/ci.yml
├── LICENSE
└── README.md
```

## Setup

Requires Python 3.11+.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Scapy note: reading `.pcap`/`.pcapng` files (what this app does) does **not** require raw-socket privileges or root — that is only needed for *live* packet capture. No extra system packages are required to run the app or its tests. `libpcap-dev`/`tcpdump` are installed in the Docker image only so the same image would also work for live-capture use cases.

## Generate a sample capture

```bash
python generate_sample_pcap.py
```

This writes `sample_data/sample_capture.pcap` — a synthetic capture containing normal TCP/UDP/ICMP/ARP traffic, plus an injected port scan (one IP sweeping ~40 ports on a victim with lone SYNs) and an injected flood (one IP bursting 300 packets at a victim well above the capture's average rate).

## Run the app

```bash
python wsgi.py
```

Then open `http://localhost:5000`, upload `sample_data/sample_capture.pcap` (or any real `.pcap`/`.pcapng` file), and view the dashboard and findings.

## Run with Docker

```bash
docker build -t packetlens .
docker run -p 5000:5000 packetlens
```

## Run tests

```bash
pytest -v
```

Tests cover:
- The parser against the generated sample capture (correct total packet count, correct per-protocol counts, correct field extraction)
- Pure aggregation functions (protocol breakdown, time bucketing, top-N, top talkers by bytes) against small hand-built inputs
- Anomaly detection functions against constructed synthetic packet records — verifying both that a clear port-scan/flood pattern is detected and that clearly normal traffic is *not* flagged (no false positives)

## Author

Hanaan Mir
