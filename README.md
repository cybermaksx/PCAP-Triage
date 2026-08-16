# PCAP-Triage

A Python network-forensics tool for offline analysis of `.pcap` / `.pcapng` captures — built to grow from generic traffic statistics into OT/ICS-aware threat detection.

> **Status: early development (Phase 1).** Traffic statistics and TCP scan detection (SYN, FIN) work today. Industrial protocol support is the next milestone. See [Roadmap](#roadmap) for the honest state of things.

## Features

**Working now**

- Protocol distribution — IPv4, TCP, UDP, ICMP, ARP, DNS
- Unique IP address and port extraction
- Packet size metrics — average, min, max
- SYN port-scan detection with a configurable threshold
- FIN (stealth) scan detection
- Detector registry — new detections plug in without touching the pipeline
- Graceful handling of missing, unreadable and non-capture files
- CLI interface via `argparse`

**Known limitations**

- Console output is not formatted for a terminal yet — separator lines are wider
  than 80 columns, and IP/port lists are printed as raw Python sets
- A large scan prints its full port list on a single line (thousands of characters)
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
Follow the white rabit
Reading the pcap file ...
Loaded 40 packets

Getting Statistic of the packets [*]

===================================================================
Packet Statistics
===================================================================
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
===================================================================
Unique ip addresses are {'192.168.1.178', '192.168.1.1', '140.82.112.25', '8.219.122.25'}
===================================================================
Unique ports which had been interacted in this pcap files are {44128, 38609, 53, 443}
===================================================================
No Threats detected
Generating report... (coming soon)

 Analysis complete!
```

The separator lines are shortened above for readability — the program currently
emits them at 147 characters, and the port list is not truncated. Both are listed
under [Known limitations](#features).

When a scan is present, every detector reports through the same format:

```
[!] PORT_SCAN (HIGH) from 10.0.0.66
    10.0.0.66 scanned 22 unique ports
    Ports: [20, 21, 22, 23, 24, 25, 26, 27, 28, 29, ...]
[!] FIN_SCAN (HIGH) from 10.0.0.77
    10.0.0.77 sent bare FIN to 44 unique ports
    Ports: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, ...]
```

## Roadmap

Phase 1 — generic static analysis:

| Feature | Status |
|---|---|
| Protocol distribution (TCP/UDP/ICMP/ARP/DNS) | Done |
| Unique IP / port extraction | Done |
| Packet size metrics | Done |
| SYN scan detection (threshold-based) | Done |
| FIN (stealth) scan detection | Done |
| CLI via argparse | Done |
| Refactor into single-pass collector + detector modules | Done |
| Graceful error handling for missing / invalid files | Done |
| Format-agnostic finding output (any detector prints correctly) | Done |
| Readable console formatting (widths, sorted lists, long-list handling) | Planned |
| NULL / XMAS / UDP scan detection | Planned |
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
├── pcaps/            # Sample captures
│   └── test.pcapng
├── requirements.txt
├── README.md
└── LICENSE
```

The code is organised as a three-stage pipeline:

```
pcap file ──> context ──> findings ──> output
             (facts)    (conclusions)
```

`main.py` walks over the packets exactly once and hands each one to `feed()`. The context is
a plain dictionary built by `make_context()`, holding the traffic counters plus one key of
raw material per detector. Detectors then read that dictionary rather than the packets
themselves, and return findings in a common format. `report.py` is the only module that
prints — detectors never do, which is what makes them testable without a capture file.

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

## On AI

Two separate questions get mixed together under this word, so both are answered here.

### How this project is built

I use an AI assistant while working on PCAP-Triage, and I want to be direct about
the shape of that: it explains, reviews and documents — I write the code.

In practice that means the assistant is used for architecture discussion, for
walking through a language feature I have not met before, for reviewing a change
after I make it, and for the English comments in the source files. When it offers
finished code, I ask for the explanation instead. The point of this project is
that I come out of it able to write this kind of tool, not that the tool exists.

That choice has a cost — progress is slower, and some of the commits here are
messier than they would otherwise be. It also produced the discipline the project
actually runs on: capture a baseline before a refactor, diff the output after, and
treat an untested branch as unwritten. Both of those habits came from getting it
wrong first.

### Machine learning inside the tool

ML-based anomaly detection sits in Phase 3 of the roadmap, deliberately last.

Detection here is deterministic and rule-based, and that is a design decision
rather than a limitation to be outgrown. An alert from this tool has to say which
source address, which function code and which packet number, because the person
reading it has to decide whether to act on a live process. "Anomaly score 0.87" is
not something an operator can act on, and it is not something the analyst can
argue with afterwards.

There is a second reason specific to industrial networks. OT traffic is unusually
repetitive — the same masters polling the same registers on a fixed cycle — which
genuinely does make it good ground for baselining. But a baseline learned from a
capture that already contains the intrusion teaches the model that the intrusion is
normal. Getting that right needs known-clean reference traffic, which is exactly
what an incident responder arriving at an unfamiliar site does not have.

So: explicit rules first, tested and explainable. Statistical baselining later, on
top of them, and never as a replacement for them.

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
