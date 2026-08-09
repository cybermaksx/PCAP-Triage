```markdown
# PCAP-Triage

A lightweight network traffic analysis tool for packet capture (PCAP) files with real-time threat detection capabilities.

## Overview

PCAP-Triage is a Python-based network forensics tool that analyzes PCAP files (`.pcap`, `.pcapng`) to provide comprehensive statistics and detect potential security threats. Designed with scalability in mind, this tool can evolve from analyzing static captures to real-time network monitoring.

## Features

### 📊 Packet Statistics
- **Protocol Distribution**: TCP, UDP, ICMP, ARP, DNS breakdown
- **Network Intelligence**: Unique IP addresses and port identification
- **Traffic Metrics**: Packet size analysis (average, min, max)
- **Comprehensive Counting**: Total packet count with protocol categorization

### 🔍 Threat Detection
- **SYN Port Scanning Detection**: Identifies potential reconnaissance activities
- **Threshold-based Alerts**: Configurable detection sensitivity
- **Structured Threat Reporting**: JSON-formatted threat intelligence

### 🚀 Planned Features (Roadmap)
- Real-time packet capture and analysis
- Web-based dashboard for visualization
- Exportable reports in multiple formats (JSON, CSV, HTML)
- Additional threat signatures:
  - DDoS pattern detection
  - ARP spoofing detection
  - Malicious traffic identification
  - Suspicious port scanning beyond SYN

## Installation

### Prerequisites
- Python 3.6+
- pip package manager

### Dependencies
```bash
pip install scapy
```

### Setup
```bash
# Clone the repository
git clone https://github.com/cybermaksx/PCAP-Triage.git
cd PCAP-Triage

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python main.py
```

### Configuration
Currently, the tool analyzes a default PCAP file named `test.pcapng`. To analyze a different file, modify the `pcap_file` variable in the `main()` function:

```python
pcap_file = "your_file.pcap"  # Change this line
```

### Sample Output
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

## Project Structure

```
PCAP-Triage/
├── main.py          # Main application logic
├── test.pcapng      # Sample PCAP file for testing
├── README.md        # This file
└── requirements.txt # Python dependencies
```

## Key Functions

### `stat()`
Analyzes packet data and returns comprehensive statistics including:
- Protocol distribution
- Unique IP addresses and ports
- Packet size metrics

### `threat_checking(packets)`
Implements SYN port scanning detection with:
- Configurable threshold (default: 20 ports)
- Source IP tracking
- Detailed threat reporting

### `report_generator()`
Currently in development - will provide:
- Exportable reports in multiple formats
- Interactive visualization options

## Roadmap to Real-Time Analysis

This tool is designed to evolve into a real-time network monitoring system (SIEM-like capability):

### Phase 1: Static Analysis (Current)
- ✅ PCAP file processing
- ✅ Basic statistics
- ✅ SYN scanning detection

### Phase 2: Real-Time Capture (Planned)
- Live packet sniffing with Scapy
- Streaming data processing
- Continuous monitoring

### Phase 3: Dashboard & Visualization (Planned)
- Web-based interface (Flask/Django)
- Real-time statistics updates
- Alert notifications

### Phase 4: Advanced Analytics (Future)
- Machine learning for anomaly detection
- Threat intelligence integration
- Automated incident response

## Security Use Cases

- **Incident Response**: Quick triage of captured traffic during security incidents
- **Network Audit**: Verify network configurations and security policies
- **Threat Hunting**: Identify reconnaissance activities before exploitation
- **Forensic Analysis**: Retrospective analysis of network captures

## Contributing

Contributions are welcome! Areas for contribution:
- Additional threat detection signatures
- Performance optimizations for large PCAP files
- GUI development
- Report generation enhancements
- Documentation improvements

## License

MIT License

Copyright (c) 2026 CyberMaksX

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Author

**CyberMaksX**

- GitHub: [@cybermaksx](https://github.com/cybermaksx)

---
