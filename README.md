# PCAP-Triage

A Python network-forensics tool for offline analysis of `.pcap` / `.pcapng` captures — built to grow from generic traffic statistics into OT/ICS-aware threat detection.

> **Status: Phase 1 complete.** Traffic statistics, IPv4/IPv6 accounting, five scan
> detectors (SYN, FIN, UDP, NULL, XMAS), ARP spoofing and DNS tunneling detection work
> today. Every finding says when it started and ended, which Wireshark frame to look at,
> and in what order the ports were hit. All of it sits on top of a streaming reader that
> keeps memory flat on large captures, a machine-readable JSON mode and a pytest suite.
>
> **Phase 2 has started:** Modbus/TCP is parsed and summarised — masters, slaves,
> function codes, writes, exceptions and malformed traffic on port 502. Detectors on
> top of it are next. See [Roadmap](#roadmap) for the honest state of things.

## Features

**Working now**

- Protocol distribution — IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, Modbus, counted independently
  per OSI layer, so TCP carried over IPv6 is counted as both
- Unique IPv4 and IPv6 address extraction, plus unique ports
- Packet size metrics — average, min, max
- SYN port-scan detection with a configurable threshold
- FIN (stealth) scan detection
- UDP scan detection, inferred from the target's ICMP port-unreachable replies
- NULL scan detection — TCP packets with no flags set at all, which no working stack sends
- XMAS scan detection — TCP packets carrying FIN+PSH+URG together, a combination no
  legitimate stack produces
- ARP spoofing detection — one IPv4 address claimed by more than one MAC, the signature
  of a machine inserting itself into the path between two hosts. The attack is dated
  from the moment the *second* MAC appears, since the first is normally the real owner
- DNS tunneling detection — a domain with both unusually long labels and an unusually
  large number of distinct names, the shape of data smuggled out inside DNS queries
- Timing on every finding — start and end time (UTC), the Wireshark frame number of the
  first and last packet (`frame.number == N` jumps straight to it), duration, and probe
  rate in ports per second
- Scan order — the order in which a scanner first touched each port, with a tag saying
  whether the walk was `sequential` (`nmap -r`, a hand-written script) or `randomised`
  (nmap's default)
- Modbus/TCP parsing — the MBAP header is decoded and validated by a parser of its own
  (`modbus.py`), not by scapy, so malformed and non-Modbus traffic on port 502 is
  counted instead of silently mislabelled. The report gets a `MODBUS` block: every
  master with its request count, number of distinct function codes, writes and target
  devices; function codes by name; exceptions per device; malformed frames by number
- Full mode (`--full`) — lifts every truncation limit and prints a per-packet timeline
  for each finding
- Detector registry — new detections plug in without touching the pipeline
- JSON output mode (`--json`) — the full result as one structured document, versioned
  by a `schema_version` field and ordered deterministically so two runs of the same
  capture produce identical text
- Terminal-aware report — width read from the terminal, addresses sorted numerically
  and laid out in columns, consecutive ports folded into ranges, colour emitted only
  when stdout is a TTY
- Streaming packet reader (`PcapReader`) — packets are parsed one at a time and
  discarded, so peak memory does not grow with file size: a 12 MB / 131 428-packet
  capture went from 696 MB to 89 MB
- Graceful handling of missing, unreadable and non-capture files — reported on stderr
  with a non-zero exit code, so a wrapping script can tell a failed run from an
  empty one
- CLI interface via `argparse`
- pytest suite — 212 tests over the collector, the Modbus parser, the detectors, the
  registry contract and all output modes. Modbus expectations are taken from tshark,
  not from the code under test

**Known limitations**

- IPv6 addresses are collected into their own set rather than alongside IPv4, so any
  consumer has to read two keys instead of one
- ICMPv6 is not counted — `ICMP in packet` matches ICMP over IPv4 only
- DNS is only counted over UDP; DNS over TCP (port 53) is missed
- Modbus is recognised on port 502 only. Real installations do move it; the parser
  itself ignores ports, but nothing yet decides that a stream on another port is Modbus
- One Modbus message per TCP segment is assumed. Several messages packed into one
  segment, or one message split across two, are counted as malformed — there is no TCP
  stream reassembly
- Modbus over UDP and Modbus RTU-over-TCP are not recognised
- The Modbus block reports; it does not judge yet. A function-code sweep is plainly
  visible in it (128 codes from one master), but no detector raises a finding for it
- Packets themselves are streamed, but `stats['packet_sizes']` still keeps one entry
  per packet, so memory has not been made fully constant in file size. Only min, max
  and the average are read back from that list
- ARP spoofing is judged over the whole capture with no baseline: an address that
  changed hands via DHCP looks the same as an attack, and a spoof already underway
  before the capture started is invisible if the real host stays silent throughout
- Colour is decided by whether stdout is a terminal, so piping the JSON into a parser
  also strips the colour from the banner, which is on stderr and still on screen
- Redirecting both streams into one file (`> out.txt 2>&1`) interleaves them out of
  order, because stderr is unbuffered while a redirected stdout is not. On a terminal
  the order is correct
- CSV and HTML export are not implemented
- The scan order is the order of first appearance **in the file**, while `start` is the
  earliest **timestamp**. Captures merged from several interfaces can hold a packet
  stamped slightly earlier than the one before it (`finscan.pcapng`, frames 11 and 12),
  and then the two disagree on which packet came first
- The per-port timeline keeps one entry for every distinct (scanner, port) pair, so a
  full-range scan costs around 65 000 small entries of memory. Fine at the sizes tested
  here, not yet bounded
- UDP scan detection depends on the target answering. Linux rate-limits ICMP
  unreachable replies to roughly one per second, which can suppress most of the
  evidence on a fast scan. The same limit shows up in the probe rate: `udpscan.pcapng`
  reports `1 ports/s`, which is the target's reply rate, not the scanner's speed. The
  times on a UDP finding are those of the ICMP replies, not of the probes themselves
- NULL and XMAS detection fire on a single packet by design, so a broken stack or a
  middlebox rewriting flags will produce a finding where there is no scan
- The NULL, FIN and XMAS scans they detect are themselves ineffective against Windows,
  which answers RST regardless of port state — an attacker probing a Windows host is
  more likely to use a technique this tool does not yet cover

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
python main.py <capture.pcap> [--json] [--full]
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
  · collecting facts
  ✓ read 873 packets
  · running detectors

OVERVIEW
────────────────────────────────────────────────────────────────────────────────
    Packets                   873
    Unique IPv4 hosts          15
    Unique IPv6 hosts           0
    Unique ports              132
    Packet size         42–7066 bytes (avg 208)
    First packet        2026-08-19 01:16:45.802 UTC
    Last packet         2026-08-19 01:18:28.713 UTC  (102.91 s)

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
      start  2026-08-19 01:16:48.464 UTC  (frame 10)
      end    2026-08-19 01:18:19.089 UTC  (frame 765)
      span   90.625 s  ·  1 ports/s
      order  32815 → 515 → 5060 → 2000 → 1025 → 445 … (+87)  [randomised]

  ✓ analysis complete
```

The report adapts to the terminal: separators and bars are sized to the current
width, and long address, port and order lists are truncated rather than wrapped. Colour
is emitted only when stdout is a TTY, so piping the output into a file or into
`grep` yields clean text.

Consecutive ports are folded into ranges, which matters at scale — the full-range
SYN scan in `pcaps/synscan.pcapng` reports its 65 535 ports as `1-65535` instead of
a single 447 000-character line.

Every detector reports through the same format, so findings from different
techniques print uniformly. Each line is printed only when the finding carries the
data for it — an ARP finding has no ports, a scan finding has no MACs. The `FINDINGS`
block from `synscan.pcapng` and from `arpspoof.pcapng`:

```
FINDINGS (1)
────────────────────────────────────────────────────────────────────────────────
    ▸ PORT_SCAN  HIGH  from 192.168.1.99
      192.168.1.99 scanned 65535 unique ports
      ports  1-65535
      start  2026-08-14 22:09:38.880 UTC  (frame 35)
      end    2026-08-14 22:10:20.197 UTC  (frame 131404)
      span   41.317 s  ·  1586 ports/s
      order  8888 → 8080 → 5900 → 587 → 25 → 554 → 199 … (+65528)  [randomised]
```

```
FINDINGS (2)
────────────────────────────────────────────────────────────────────────────────
    ▸ MITM_ATTACK  HIGH  from 192.168.1.6
      192.168.1.6 claimed by 2 MACs: 00:0c:29:de:ad:be, 4c:0f:3e:25:87:80
      start  2026-09-08 22:32:59.364 UTC  (frame 5)
      order  4c:0f:3e:25:87:80 → 00:0c:29:de:ad:be
```

Times are printed in UTC so a report means the same moment on every machine it is
passed to. Wireshark can be switched to match under *View → Time Display Format →
UTC Date and Time of Day*.

Where a capture contains several techniques they are listed together in one block,
most severe first.

### Modbus

`pcaps/modbus_test.pcap` holds three unrelated captures merged into one: a 2004
walk through many function codes, a 2006 sweep of all 128 function codes against an
internet-facing device, and the first 40 seconds of a 2012 SCADA session. The
`MODBUS` block from it:

```
MODBUS
────────────────────────────────────────────────────────────────────────────────
    Requests                  566
    Responses                 573
    Malformed on 502            6  frames 76, 78, 80, 82, 111, 113

  Masters (4)
    10.0.0.9             6 req    4 FC    3 writes  → 10.0.0.3 [10]
    10.0.0.57           12 req    3 FC    0 writes  → 10.0.0.3 [10], 10.0.0.8 [10]
    10.1.1.234         407 req    3 FC   20 writes  → 10.10.5.85 [255]
    192.168.66.235     141 req  128 FC    6 writes  → 166.161.16.230 [1]

  Function codes (128)
      4  Read Input Registers                  317
      3  Read Holding Registers                 73
      6  Write Single Register                  22
    ...

  Exceptions
    10.0.0.3         11      4  Gateway Target Device Failed to Respond
    10.0.0.8          5      5  Acknowledge
                      6      5  Server Device Busy
    166.161.16.230    1    104  Illegal Function
                      2      8  Illegal Data Address
                      3     18  Illegal Data Value
```

The number in brackets is the unit id. A master using 128 distinct function codes
while the others use three or four, answered mostly with *Illegal Function*, is a
device being fingerprinted. `--full` adds every write with its frame number and time.

A message counts as Modbus only if its MBAP header is self-consistent: protocol id 0,
a length field between 2 and 254 that matches the bytes actually present. Anything
else carrying data on port 502 is listed as malformed rather than dropped — scanners
send garbage on purpose, and a device answering in another protocol is itself a fact.
This occasionally disagrees with Wireshark: frames 91–109 above are valid MBAP
exception responses that Wireshark shows as plain data.

### Full output

```bash
python main.py pcaps/finscan.pcapng --full
```

The default report is cut to fit one screen. `--full` removes every limit — all
addresses, every port range, the complete order — and adds a timeline under each
finding, one line per probe, in the order it happened:

```
      timeline
        frame  11  2026-08-14 22:12:05.867 UTC     +0.000s  → 8080
        frame  12  2026-08-14 22:12:05.867 UTC     +0.000s  → 445
        frame  15  2026-08-14 22:12:05.867 UTC     +0.000s  → 5900
        frame  16  2026-08-14 22:12:05.867 UTC     +0.000s  → 199
        ...
```

The `+s` column is time since the first probe, which makes bursts and pauses visible
without subtracting timestamps by hand. On a full-range scan this is tens of thousands
of lines, so page it:

```bash
python main.py pcaps/synscan.pcapng --full | less -R
```

`--full` only changes the human report. Detectors always return everything; the
truncation happens in `report.py` alone, and `--json` carries the complete data either
way.

### JSON output

```bash
python main.py pcaps/test.pcapng --json
```

Prints the whole result as one document instead of the human report — the two modes are
mutually exclusive, since mixing framed text into the stream would make it unparseable:

```json
{
  "schema_version": 1,
  "file": "pcaps/test.pcapng",
  "packets": 40,
  "stats": {
    "protocols": {
      "tcp": 29,
      "udp": 6,
      "icmp": 0,
      "arp": 0,
      "dns": 6
    },
    "layers": {
      "ipv4": 31,
      "ipv6": 9,
      "arp": 0,
      "other": 0
    },
    "unique_ipv4": [
      "8.219.122.25",
      "140.82.112.25",
      "192.168.1.1",
      "192.168.1.178"
    ],
    "unique_ipv6": [
      "2a02:4e0:2dc0:1fb5:9017:c87a:fbc1:2",
      "2a0b:21c0:c002:3:3::16",
      "fe80::9217:c8ff:fe7a:fbc1",
      "ff02::1:ffaa:7e64",
      "ff02::1:ffd3:d108"
    ],
    "unique_ports": [
      53,
      443,
      38609,
      44128,
      44340,
      47218,
      49948,
      55642,
      60478,
      60620
    ],
    "packet_size": {
      "min": 54,
      "max": 2894,
      "avg": 270
    },
    "first_ts": 1785670164.6610777,
    "last_ts": 1785670168.6524422
  },
  "findings": []
}
```

`schema_version` is there so a consumer can detect a breaking change instead of failing
silently on a renamed key. Address and port lists are sorted, so committing the output of
successive runs produces meaningful diffs rather than reordering noise. Detector findings
travel through unchanged — the same dictionaries the detectors return, which is the payoff
of forbidding them to print.

Times in the JSON are epoch seconds (`first_ts`, and `start` / `end` on each finding), so
a consumer converts one number rather than parsing a formatted string. Every scan finding
also carries its full `timeline` — a list of `{"port", "time", "frame"}` in the order the
ports were hit — with or without `--full`.

The banner and the progress lines go to stderr, not stdout, so they stay on screen while
only the JSON travels through a pipe or a redirect:

```bash
python main.py capture.pcap --json | jq '.findings[].source'
python main.py capture.pcap --json > result.json
```

Writing the file is left to the shell rather than to a `--output` flag: redirection already
handles overwrite, append, permissions and paths, and keeping the result on stdout is what
lets the same command feed a pipe instead.

### Running the tests

```bash
python -m pytest -m "not slow"    # 207 tests, ~1 s
python -m pytest                  # 212 tests, ~45 s
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
| NULL scan detection (flagless TCP) | Done |
| XMAS scan detection (FIN+PSH+URG) | Done |
| JSON report output (`--json`) | Done |
| ARP spoofing detection (MITM precursor) | Done |
| Streaming reader for large captures (`PcapReader`) | Done |
| Non-zero exit code and stderr for failures | Done |
| DNS tunneling detection (label length + unique names) | Done |
| Start / end time, frame numbers and scan order on findings | Done |
| Full untruncated report with per-packet timeline (`--full`) | Done |

Phase 2 — OT/ICS protocols, the actual goal of this project:

| Feature | Status |
|---|---|
| Modbus/TCP detection + MBAP header parsing | Done |
| Modbus function-code sweep detection | Next up |
| Modbus write-command detection (FC 5/6/15/16/22/23) | Next up |
| Unauthorized Modbus master detection | Planned |
| DNP3 / S7comm parsing | Planned |

Phase 3 — later, no timeline:

| Feature | Status |
|---|---|
| DNS tunneling: entropy scoring on top of the current thresholds | Planned |
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
├── modbus.py                 # Modbus/TCP: MBAP parser, function and exception tables
├── tests/
│   ├── conftest.py           # Shared fixtures: one parsed context per capture
│   ├── test_context.py       # Counter accuracy and the layer-coverage invariant
│   ├── test_detectors.py     # Thresholds, finding schema, registry contract
│   ├── test_modbus.py        # MBAP parser on hand-built bytes, no capture needed
│   └── test_report.py        # JSON validity and which stream each helper writes to
├── pcaps/                    # Sample captures
│   ├── test.pcapng           # 40 packets, mixed IPv4/IPv6, no scan
│   ├── newtest.pcapng        # 883 packets, ordinary home traffic, no findings
│   ├── finscan.pcapng        # 221 packets, FIN scan
│   ├── synscan.pcapng        # 131 428 packets, full-range SYN scan
│   ├── udpscan.pcapng        # 873 packets, UDP scan
│   ├── arpspoof.pcapng       # 5 packets, ARP spoofing of two hosts
│   ├── dnstunnel.pcapng      # 212 packets, DNS tunnel
│   └── modbus_test.pcap      # 1 700 packets, three Modbus captures (2004/2006/2012)
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

`main.py` walks over the packets exactly once and hands each one to `feed()`, together with
its position in the file — that position becomes the frame number every finding points at.
The context is a plain dictionary built by `make_context()`, holding the traffic counters
plus one key of raw material per detector. For the scan detectors that raw material is a
record per source address: first and last time and frame, and a `port -> (time, frame)`
dict whose insertion order is the order the ports were first hit. Detectors then read that dictionary rather than the packets
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
- Additional detection logic (beaconing, DHCP spoofing)
- Performance work for large captures
- Report generation and output formats

## License

MIT License — Copyright (c) 2026 CyberMaksX

## Author

**CyberMaksX**
GitHub: [@cybermaksx](https://github.com/cybermaksx)
