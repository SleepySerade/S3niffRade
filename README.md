# S3niffRade - Network Packet Analyzer with Threat Detection

S3niffRade is a powerful network packet analyzer with built-in threat detection capabilities. It monitors network traffic in real-time, analyzes packets for suspicious patterns, and alerts users to potential security threats such as ARP spoofing, DNS tunneling, and port scanning.

![S3niffRade Dashboard](https://i.imgur.com/placeholder.png)

## Features

- **Real-time Packet Capture**: Capture and analyze network packets using Scapy
- **Threat Detection**: Identify common network attacks and suspicious activities
- **Web Dashboard**: Visualize network traffic and security alerts in real-time
- **Detailed Statistics**: Track protocol distribution, top talkers, and more
- **Filtering Capabilities**: Filter and search through packets and alerts
- **Exportable Results**: Save analysis results to JSON for further investigation

## Threat Detection Capabilities

S3niffRade can detect the following types of suspicious network activities:

### ARP Spoofing Detection
- Identifies inconsistent ARP mappings (IP-to-MAC)
- Detects when a single MAC address claims multiple IP addresses
- Alerts on potential Man-in-the-Middle attacks

### DNS Tunneling Detection
- Identifies unusually long domain names
- Detects high-entropy (randomized) domain names
- Monitors for high-frequency DNS queries
- Identifies base64-encoded subdomains

### Port Scanning Detection
- Detects horizontal port scans (multiple ports on same host)
- Identifies scans targeting common vulnerable services
- Recognizes sequential port scanning patterns
- Alerts on both TCP and UDP scanning activities

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/S3niffRade.git
   cd S3niffRade
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Run S3niffRade with default settings:

```
python packet_analyzer.py
```

### Command-line Options

- `-i, --interface`: Specify the network interface to capture packets from
- `-o, --output`: Specify an output file to save results
- `-d, --dashboard`: Enable the web dashboard
- `-l, --list-interfaces`: List available network interfaces
- `-v, --verbose`: Enable verbose output

### Examples

Capture packets on a specific interface:
```
python packet_analyzer.py -i eth0
```

Enable the web dashboard:
```
python packet_analyzer.py -d
```

Save results to a file:
```
python packet_analyzer.py -o results.json
```

List available network interfaces:
```
python packet_analyzer.py -l
```

## Dashboard

The web dashboard provides a real-time visualization of network traffic and security alerts. It includes:

- **Packet Statistics**: Total packet count and protocol distribution
- **Top Talkers**: Most active source and destination IP addresses
- **Security Alerts**: Real-time display of detected threats
- **Recent Packets**: Live packet capture with filtering capabilities

Access the dashboard by opening a web browser and navigating to:
```
http://localhost:5000
```

## Project Structure

```
S3niffRade/
├── packet_analyzer.py     # Main script
├── dashboard.py           # Web dashboard implementation
├── requirements.txt       # Python dependencies
├── detectors/             # Threat detection modules
│   ├── __init__.py
│   ├── arp_spoof.py       # ARP spoofing detector
│   ├── dns_tunnel.py      # DNS tunneling detector
│   └── port_scan.py       # Port scanning detector
├── static/                # Dashboard static files (auto-generated)
└── templates/             # Dashboard templates (auto-generated)
```

## Requirements

- scapy==2.5.0
- flask==2.3.3
- flask-socketio==5.3.6
- pandas==2.1.0
- plotly==5.17.0
- dash==2.13.0
- colorama==0.4.6

## Note on Permissions

Packet capturing typically requires administrative/root privileges. Run the script with appropriate permissions:

- On Windows: Run as Administrator
- On Linux/macOS: Use sudo

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational purposes and legitimate network monitoring only. Always ensure you have proper authorization before monitoring any network.