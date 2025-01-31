# SegmentationTester

## Overview
SegmentationTester is a Bash script designed to perform comprehensive network segmentation testing. It utilizes various network protocols to scan and analyze target IPs, providing detailed reports on network security and performance.

## Features
- Multi-protocol scanning including TCP, UDP, SCTP, DCCP, and IGMP.
- OS fingerprinting and service version detection.
- Network path analysis using traceroute and mtr.
- Performance metrics evaluation like latency and bandwidth.
- Detailed logging with color-coded output.
- Organized output directories for easy access to results.

## Prerequisites
- **nmap**: Required for network scanning.
- **tcpdump**: Used for monitoring IGMP traffic.
- **mtr**: Utilized for network path analysis.

## Usage
Run the script with the following options:
```
./SegmentationTests.sh -t <target_ips> -i <interface> [-n <network>] [-d <directory>]
```
- `-t`: Comma-separated list of target IPs (required).
- `-i`: Network interface to use (required).
- `-n`: Target network (optional).
- `-d`: Output directory (optional, defaults to `./segmentation_test_<timestamp>`).

## Output Structure
The script organizes results into the following directories:
- `scans/tcp`, `scans/udp`, `scans/sctp`, etc.
- `security/os_fingerprint`
- `network_layers/traceroute`, `network_layers/path_analysis`
- `app_protocols/http`, `app_protocols/dns`, `app_protocols/ssh`
- `performance/bandwidth`, `performance/latency`
- `reports`
- `ping_sweep`

## Example
To run a test on IPs `192.168.1.1,192.168.1.2` using interface `eth0`, execute:
```
./SegmentationTests.sh -t 192.168.1.1,192.168.1.2 -i eth0
```

## Notes
- Ensure you have the necessary permissions to run network scans.
- The script logs all activities in `scan.log` within the specified directory.

## License
This project is licensed under the MIT License.
