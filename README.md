# PCAP-Triage

A Python network-forensics tool for offline analysis of `.pcap` / `.pcapng` captures — built to grow from generic traffic statistics into OT/ICS-aware threat detection.

> **Status: early development (Phase 1).** Traffic statistics, IPv4/IPv6 accounting and three
> scan detectors (SYN, FIN, UDP) work today, with a pytest suite covering them. Industrial
> protocol support is the next milestone. See [Roadmap](#roadmap) for the honest state of things.

## Features

**Working now**

- Protocol distribution — IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, counted independently
  per OSI layer, so TCP carried over IPv6 is counted as both
- Unique IPv4 and IPv6 address extraction, plus unique ports
- Packet size metrics — average, min, max
- SYN port-scan detection with a configurable threshold
- FIN (stealth) scan detection
- UDP scan detection, inferred from the target's ICMP port-unreachable replies
- Detector registry — new detections plug in without touching the pipeline
- Terminal-aware report — width read from the terminal, addresses sorted numerically
  and laid out in columns, consecutive ports folded into ranges, colour emitted only
  when stdout is a TTY
- Graceful handling of missing, unreadable and non-capture files
- CLI interface via `argparse`
- pytest suite — 31 tests over the collector, the detectors and the registry contract

**Known limitations**

- IPv6 addresses are collected into their own set rather than alongside IPv4, so any
  consumer has to read two keys instead of one
- ICMPv6 is not counted — `ICMP in packet` matches ICMP over IPv4 only
- DNS is only counted over UDP; DNS over TCP (port 53) is missed
- The whole capture is loaded into memory (`rdpcap`), so very large files will not work
- Report export (JSON/CSV/HTML) is a stub, not implemented yet
- Error messages are printed to stdout and the process still exits 0, so a failed run
  is indistinguishable from a successful one to any script wrapping it
- UDP scan detection depends on the target answering. Linux rate-limits ICMP
  unreachable replies to roughly one per second, which can suppress most of the
  evidence on a fast scan

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

The only runtime dependency is [Scapy](https://scapy.net/) (developed against 2.7.0).

To run the test suite as well:

```bash
pip install -r requirements-dev.txt
```

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
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   P C A P - T R I A G E                                                      ║
║   follow the white rabbit                                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

  · reading pcaps/udpscan.pcapng
  ✓ loaded 873 packets
  · collecting facts
  · running detectors

OVERVIEW
────────────────────────────────────────────────────────────────────────────────
    Packets                   873
    Unique IPv4 hosts          15
    Unique IPv6 hosts           0
    Unique ports              132
    Packet size         42–7066 bytes (avg 208)

PROTOCOLS
────────────────────────────────────────────────────────────────────────────────
    TCP   499  █████████████████████████████████                          57.2%
    UDP   227  ███████████████                                            26.0%
    ICMP  101  ███████                                                    11.6%
    ARP    46  ███                                                         5.3%
    DNS    28  ██                                                          3.2%

    network layer:  IPv4 827  ·  IPv6 0  ·  ARP 46  ·  other 0

ADDRESSES
────────────────────────────────────────────────────────────────────────────────
  IPv4 (15)
    18.97.36.68      34.107.243.93    109.176.239.0    109.176.239.69
    140.82.114.25    142.251.156.119  146.75.121.91    149.154.167.92
    160.79.104.10    192.168.1.1      192.168.1.6      192.168.1.99
    192.168.1.100    192.168.1.111    192.168.1.255
  IPv6 (0)
    none

PORTS SEEN (132)
────────────────────────────────────────────────────────────────────────────────
    7, 9, 17, 19, 49, 53, 67-69, 80, 88, 111, 120, 123  (+118 more)

FINDINGS (1)
────────────────────────────────────────────────────────────────────────────────
    ▸ UDP_SCAN  HIGH  from 192.168.1.99
      192.168.1.99 sent UDP to 93 unique ports
      ports  7, 9, 17, 19, 49, 67-69, 80, 88, 111, 120, 123, 135-139  (+75 more)

  ✓ analysis complete
```

The report adapts to the terminal: separators and bars are sized to the current
width, and long address and port lists are truncated rather than wrapped. Colour
is emitted only when stdout is a TTY, so piping the output into a file or into
`grep` yields clean text.

Consecutive ports are folded into ranges, which matters at scale — the full-range
SYN scan in `pcaps/synscan.pcapng` reports its 65 535 ports as `1-65535` instead of
a single 447 000-character line.

Every detector reports through the same format, so a capture containing several
techniques prints them uniformly, most severe first:

```
FINDINGS (2)
────────────────────────────────────────────────────────────────────────────────
    ▸ PORT_SCAN  HIGH  from 192.168.1.99
      192.168.1.99 scanned 65535 unique ports
      ports  1-65535

    ▸ FIN_SCAN  HIGH  from 192.168.1.99
      192.168.1.99 sent bare FIN to 100 unique ports
      ports  7, 9, 13, 21-23, 25-26, 37, 53, 79-81, 88, 106  (+83 more)
```

### Running the tests

```bash
python -m pytest -m "not slow"    # 26 tests, ~0.1 s
python -m pytest                  # 31 tests, ~45 s
```

The `-m` matters: a bare `pytest` does not put the project directory on the module
search path and fails to import `context`. The five tests marked `slow` are the ones
that parse `synscan.pcapng`, which is 131 428 packets.

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
| Readable console formatting (widths, sorted lists, long-list handling) | Done |
| UDP scan detection (ICMP port-unreachable analysis) | Done |
| IPv4 / IPv6 accounting split by OSI layer | Done |
| Unit tests (pytest) | Done |
| NULL / XMAS scan detection | Planned |
| JSON report output | Planned |
| ARP spoofing detection (MITM precursor) | Planned |
| Streaming reader for large captures (`PcapReader`) | Planned |
| Non-zero exit code and stderr for failures | Planned |

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
├── main.py                   # Entry point: CLI, file reading, pipeline orchestration
├── context.py                # Stage 1 — collects facts in a single pass over the packets
├── detectors.py              # Stage 2 — turns facts into findings; detector registry
├── report.py                 # Stage 3 — all output formatting
├── tests/
│   ├── conftest.py           # Shared fixtures: one parsed context per capture
│   ├── test_context.py       # Counter accuracy and the layer-coverage invariant
│   └── test_detectors.py     # Thresholds, finding schema, registry contract
├── pcaps/                    # Sample captures
│   ├── test.pcapng           # 40 packets, mixed IPv4/IPv6, no scan
│   ├── finscan.pcapng        # 221 packets, FIN scan
│   ├── synscan.pcapng        # 131 428 packets, full-range SYN scan
│   └── udpscan.pcapng        # 873 packets, UDP scan
├── pytest.ini
├── requirements.txt
├── requirements-dev.txt
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
the shape of that.

The default is that I write the code and the assistant explains, reviews and
documents: architecture discussion, walking through a language feature I have not
met before, reviewing a change after I make it, and the English comments in the
source files. When it offers finished code, I usually ask for the explanation
instead. The point of this project is that I come out of it able to write this
kind of tool, not that the tool exists.

Where I set that default aside, it is worth naming rather than blurring. Three
parts of this repository were written by the assistant at my request: the
formatting layer in `report.py`, the test suite under `tests/`, and the OSI
layer-separation fix in `context.py` after I had spent an evening failing to land
it myself. The detectors — the part this project exists to teach me — are mine.

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
