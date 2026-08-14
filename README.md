# PCAP-Triage

A Python network-forensics tool for offline analysis of `.pcap` / `.pcapng` captures — built to grow from generic traffic statistics into OT/ICS-aware threat detection.

> **Status: early development (Phase 1).** Traffic statistics and SYN-scan detection work today. Industrial protocol support is the next milestone. See [Roadmap](#roadmap) for the honest state of things.

## Features

**Working now**

- Protocol distribution — IPv4, TCP, UDP, ICMP, ARP, DNS
- Unique IP address and port extraction
- Packet size metrics — average, min, max
- SYN port-scan detection with a configurable threshold
- CLI interface via `argparse`

**Known limitations**

- IPv6 packets are not counted separately — they fall into the `Other` bucket
- DNS is only counted over UDP; DNS over TCP (port 53) is missed
- The whole capture is loaded into memory (`rdpcap`), so very large files will not work
- Report export (JSON/CSV/HTML) is a stub, not implemented yet
- No test suite yet

## Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

```bash
git clone https://github.com/cybermaksx/PCAP-Triage.git
cd PCAP-Triage
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

The only dependency is [Scapy](https://scapy.net/) (developed against 2.7.0).

## Usage

```bash
python main.py <capture.pcap>
```

Example:

```bash
python main.py pcaps/test.pcapng
```

### Sample output

```
Reading the pcap file ...
Loaded 40 packets

====================================================================================================
Packet Statistics
====================================================================================================
 Overall packets: 40
 IPv4: 31
 TCP: 25
 UDP: 6
 ICMP: 0
 ARP: 0
 DNS: 6
 Other: 9
 Unique IP: 4
 Unique ports: 9
 Average size: 270 bytes
 Min size: 54 bytes
 Max size: 2894 bytes
====================================================================================================
Unique ip addresses are {'192.168.1.178', '140.82.112.25', '192.168.1.1', '8.219.122.25'}
====================================================================================================
Unique ports which had been interacted in this pcap files are {44128, 38609, 47218, 44340, 53, 55642, 443, 49948, 60478}
====================================================================================================
No SYN scanning detected
Generating report... (coming soon)

 Analysis complete!
```

When a scan is present, the output includes the offending source and the ports it touched:

```
[!] SYN scanning detected from 10.0.0.66: 512 unique ports
    Ports: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, ...]
```

## Roadmap

Phase 1 — generic static analysis:

| Feature | Status |
|---|---|
| Protocol distribution (TCP/UDP/ICMP/ARP/DNS) | Done |
| Unique IP / port extraction | Done |
| Packet size metrics | Done |
| SYN scan detection (threshold-based) | Done |
| CLI via argparse | Done |
| Refactor into single-pass collector + detector modules | Done |
| Graceful error handling for missing / invalid files | Planned |
| JSON report output | Planned |
| ARP spoofing detection (MITM precursor) | Planned |
| Streaming reader for large captures (`PcapReader`) | Planned |
| Unit tests | Planned |

Phase 2 — OT/ICS protocols, the actual goal of this project:

| Feature | Status |
|---|---|
| Modbus/TCP detection + MBAP header parsing | Next up |
| Modbus write-command detection (FC 5/6/15/16/22/23) | Planned |
| Unauthorized Modbus master detection | Planned |
| DNP3 / S7comm parsing | Planned |

Phase 3 — later, no timeline:

| Feature | Status |
|---|---|
| DNS tunneling heuristics (entropy / label length) | Planned |
| TLS JA3 fingerprinting | Planned |
| Beaconing / C2 interval analysis | Planned |
| Real-time capture | Future |
| Web dashboard | Future |
| ML-based anomaly detection | Future |

## Project structure

```
PCAP-Triage/
├── main.py           # Entry point: CLI, file reading, pipeline orchestration
├── context.py        # Stage 1 — collects facts in a single pass over the packets
├── detectors.py      # Stage 2 — turns facts into findings; detector registry
├── report.py         # Stage 3 — all output formatting
├── test.pcapng       # Sample capture
├── requirements.txt
├── README.md
└── LICENSE
```

The code is organised as a three-stage pipeline:

```
pcap file ──> Context ──> findings ──> output
             (facts)    (conclusions)
```

`main.py` walks over the packets exactly once and hands each one to `Context.feed()`.
Detectors then read the collected `Context` rather than the packets themselves, and return
findings in a common format. `report.py` is the only module that prints.

The point of the split is that adding a protocol parser touches `context.py` (collect) and
`detectors.py` (decide, then register in the `DETECTORS` list) — the packet-reading loop and
the existing detectors stay untouched.

## Why OT protocols

Generic pcap statistics and SYN-scan detection are well covered — Zeek, Suricata and tshark do
this faster and better, and plenty of small tools on GitHub do it too. Industrial protocol
parsing is where this project aims to be useful: detecting unexpected write commands to field
devices, unauthorised engineering-station traffic, and protocol-level anomalies that require
understanding what the payload actually means.

That space is not empty either — Zeek has ICS parsers through ICSNPP, and Suricata supports
Modbus. The niche this tool targets is quick, dependency-light triage: a single script you can
run against a capture on someone else's laptop during an incident, without deploying a whole
monitoring stack first.

## Use cases

- **Incident response** — fast triage of a captured file
- **Network audit** — verifying configuration and policy against real traffic
- **Threat hunting** — spotting reconnaissance before exploitation
- **OT/ICS monitoring** — flagging anomalous industrial protocol commands
- **Forensics** — retrospective analysis of stored captures

## Contributing

Areas where help is welcome:

- Additional protocol parsers (DNP3, S7comm, EtherNet/IP)
- Additional detection logic (ARP spoofing, DNS tunneling, beaconing)
- Performance work for large captures
- Report generation and output formats

## License

MIT License — Copyright (c) 2026 CyberMaksX

## Author

**CyberMaksX**
GitHub: [@cybermaksx](https://github.com/cybermaksx)
