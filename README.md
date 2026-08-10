# PCAP-Triage

A Python-based network forensics tool for analyzing `.pcap`/`.pcapng` files — built to grow from static traffic statistics into OT/ICS-aware threat detection.

## Status: Phase 1 (Static Analysis) — in progress

| Feature | Status |
|---|---|
| Protocol distribution (TCP/UDP/ICMP/ARP/DNS) | ✅ Done |
| Unique IP / port extraction | ✅ Done |
| Packet size metrics (avg/min/max) | ✅ Done |
| SYN scan detection (threshold-based) | ✅ Done |
| CLI via argparse (replace hardcoded `pcap_file`) | ⬜ Next |
| Modbus/TCP detection + function code parsing | ⬜ Next |
| JSON threat report output | ⬜ Planned |
| DNS tunneling heuristic (entropy/length) | ⬜ Planned |
| DNP3 / S7comm detection | ⬜ Planned |
| TLS JA3 fingerprinting | ⬜ Planned |
| Real-time capture | ⬜ Future |
| Dashboard (Flask/Django) | ⬜ Future |
| ML anomaly detection | ⬜ Future |

## What to work on right now

**1. CLI (argparse)**
Replace the hardcoded `pcap_file = "test.pcapng"` in `main()` with a proper CLI:
```bash
python main.py -f capture.pcap
```
This unblocks everything else — every new module needs to run against arbitrary files, not just `test.pcapng`.

**2. Modbus/TCP module — the current priority**
This is the OT-security entry point for the project. Workflow:
1. Get a Modbus pcap (Wireshark sample captures, or spin up a `conpot`/OpenPLC honeypot and generate traffic yourself).
2. Open it in Wireshark's hex view before writing any code — manually match bytes to the parsed MBAP header and function code.
3. Parse just the MBAP header (7 bytes) and function code table — not the full spec.
4. Write the parser by hand with `struct` (no protocol libs — same approach as the SYN scanner).
5. Write 3–5 unit tests against real captured bytes as fixtures.
6. Add a `modbus.py` module, wire it into `main.py`, update this README's status table.

**3. After Modbus is solid**
Move to DNS tunneling heuristics (reuses the DNS parsing you already have), then TLS JA3, then DNP3/S7comm. One protocol at a time — don't start the next until the current one has tests and is merged.

## Installation

### Prerequisites
- Python 3.6+
- pip

### Setup
```bash
git clone https://github.com/cybermaksx/PCAP-Triage.git
cd PCAP-Triage
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py -f capture.pcap
```
*(CLI flag above is the target interface — see "What to work on right now" if not yet implemented.)*

### Sample output
```
Reading the pcap file test.pcapng...
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
Unique IP addresses: {'192.168.1.1', '192.168.1.178', '8.219.122.25', '140.82.112.25'}
====================================================================================================
Unique ports: {53, 443, 38609, 44128, 44340, 47218, 49948, 55642, 60478}
====================================================================================================
No SYN scanning detected
Analysis complete!
```

## Project structure

```
PCAP-Triage/
├── main.py          # Entry point, CLI, orchestration
├── modbus.py         # (planned) Modbus/TCP parser and threat checks
├── test.pcapng        # Sample capture for testing
├── tests/             # (planned) unit tests with real byte fixtures
├── README.md
└── requirements.txt
```

## Key functions

### `stat()`
Protocol distribution, unique IPs/ports, packet size metrics.

### `threat_checking(packets)`
SYN port scan detection — configurable threshold (default: 20 ports), source IP tracking, structured threat report.

### `report_generator()`
In development — JSON/CSV/HTML export.

## Why OT protocols

Generic pcap statistics and SYN-scan detection are common — hundreds of similar tools exist on GitHub. Industrial protocol parsing (Modbus, DNP3, S7comm) is what differentiates this project and directly supports OT security work: detecting unexpected write commands on read-only points, unauthorized engineering-station traffic, and protocol anomalies that generic tools miss entirely.

## Security use cases
- **Incident response** — quick triage of captured traffic
- **Network audit** — verify configs and security policies
- **Threat hunting** — spot recon before exploitation
- **OT/ICS monitoring** — flag anomalous industrial protocol commands
- **Forensic analysis** — retrospective capture analysis

## Contributing
- Additional protocol parsers (DNP3, S7comm, EtherNet/IP)
- Additional threat signatures (ARP spoofing, DDoS patterns)
- Performance work for large PCAP files
- Report generation

## License
MIT License — Copyright (c) 2026 CyberMaksX

## Author
**CyberMaksX**
- GitHub: [@cybermaksx](https://github.com/cybermaksx)
