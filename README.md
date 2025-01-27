# Network Segmentation Testing Tool

A comprehensive bash script for testing and analyzing network segmentation, designed for network security professionals and system administrators.

## Overview

This tool performs a series of tests to evaluate network segmentation effectiveness, including port scanning, protocol analysis, VLAN configuration checks, and routing analysis. It generates detailed reports that help identify potential security vulnerabilities in network segmentation.

## Features

### 1. Comprehensive Port Scanning
- Full TCP port scan with service detection
- UDP port scanning for common services
- Detailed service version detection
- Custom port list optimization

### 2. Protocol-Specific Analysis
- SCTP (Stream Control Transmission Protocol) scanning
- DCCP (Datagram Congestion Control Protocol) detection
- IGMP (Internet Group Management Protocol) discovery
- ARP mapping

### 3. Network Segmentation Tests
- VLAN configuration analysis
- CDP/DTP traffic detection
- Trunk port identification
- Network isolation verification

### 4. Security Analysis
- SSL/TLS certificate analysis
- OS fingerprinting
- Network path analysis
- Application protocol detection

### 5. Performance Metrics
- Bandwidth testing
- Latency measurements
- Path analysis using MTR

## Prerequisites

### Required Tools

#### Debian/Ubuntu
sudo apt-get install nmap tcpdump traceroute mtr arp-scan netcat-traditional iproute2 iperf3
#### RHEL/CentOS
sudo yum install nmap tcpdump traceroute mtr arp-scan nc iproute iperf3
#### macOS (using Homebrew)
brew install nmap tcpdump mtr arp-scan netcat iperf3

### Optional Tools
- testssl.sh (for SSL/TLS analysis)
- ash
- git clone https://github.com/drwetter/testssl.sh.git
- cd testssl.sh
- chmod +x testssl.sh
- sudo cp testssl.sh /usr/local/bin/

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/network-segmentation-test.git
```

2. Make the script executable:
```
chmod +x SegmentationTests.sh
```
## Usage

1. Basic usage:
```
sudo ./SegmentationTests.sh -t TARGET_IP -n TARGET_NETWORK -i INTERFACE
```

2. Example:
```
sudo ./SegmentationTests.sh -t 192.168.1.100 -n 192.168.1.0/24 -i eth0
```

## Output

The script generates a comprehensive report including:
- Port scan results (TCP/UDP)
- Protocol-specific findings
- VLAN configuration analysis
- Routing information
- Network isolation test results
- Security recommendations

Reports are saved in markdown format at:


## Test Descriptions

### 1. Full Port Scan
Performs comprehensive TCP and UDP port scans to identify open services and potential communication paths between network segments.

### 2. Protocol-Specific Scans
- **SCTP Scan**: Identifies telecommunications signaling channels
- **DCCP Check**: Detects streaming media services
- **IGMP Discovery**: Maps multicast group memberships

### 3. Network Segmentation Analysis
- **VLAN Tests**: Checks for VLAN hopping vulnerabilities
- **Routing Analysis**: Identifies unauthorized routes
- **Isolation Tests**: Verifies segment separation

### 4. Security Checks
- **SSL/TLS Analysis**: Evaluates certificate security
- **OS Detection**: Identifies operating systems
- **Path Analysis**: Maps network routes

## Security Considerations

- Requires root/sudo privileges
- May trigger IDS/IPS alerts
- Should be used with proper authorization
- Can generate significant network traffic

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Aswin Gopalakrishnan

## Acknowledgments

- Nmap Project
- TestSSL.sh Project
- MTR Project
- Various open-source networking tools

## Disclaimer

This tool is for network testing and security assessment purposes only. Users must ensure they have proper authorization before testing any network infrastructure.
