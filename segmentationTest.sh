#!/bin/bash

# Use standard path setting
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

# Add argument parsing
usage() {
    echo "Usage: $0 [-t TARGET_IP] [-n TARGET_NETWORK] [-i INTERFACE] [-d DIRECTORY]"
    echo "  -t : Target IP address"
    echo "  -n : Target network in CIDR notation (e.g., 192.168.1.0/24)"
    echo "  -i : Network interface to use"
    echo "  -d : Output directory (optional, will prompt if not provided)"
    echo "Example: $0 -t 192.168.1.100 -n 192.168.1.0/24 -i eth0"
    exit 1
}

# Parse command line arguments
while getopts "t:n:i:d:h" opt; do
    case $opt in
        t) TARGET_IP="$OPTARG" ;;
        n) TARGET_NETWORK="$OPTARG" ;;
        i) ETH="$OPTARG" ;;
        d) DIRECTORY="$OPTARG" ;;
        h) usage ;;
        ?) usage ;;
    esac
done

# Validate required arguments
if [ -z "$TARGET_IP" ] || [ -z "$TARGET_NETWORK" ] || [ -z "$ETH" ]; then
    echo "ERROR: Missing required arguments"
    usage
fi

# Prompt for work folder if not provided
if [ -z "$DIRECTORY" ]; then
    read -p "Enter the name of the work folder (default: segmentation_test): " DIRECTORY
    DIRECTORY=${DIRECTORY:-segmentation_test}
fi

# Create the output directory
mkdir -p "$DIRECTORY"

cat << "EOF"

   _____                                    __        __  _                ______          __ 
  / ___/___  ____ _____ ___  ___ _      __/ /_____ _/ /_(_)___  ____    /_  __/__  ___ / /_
  \__ \/ _ \/ __ `/ __ `__ \/ _ \ | /| / / __/ __ `/ __/ / __ \/ __ \    / / / _ \(_-</ __/
 ___/ /  __/ /_/ / / / / / /  __/ |/ |/ / /_/ /_/ / /_/ / /_/ / / / /   / / /  __/___/\__/
/____/\___/\__, /_/ /_/ /_/\___/|__/|__/\__/\__,_/\__/_/\____/_/ /_/   /_/  \___/         
          /____/                                                                             

                                By Aswin Gopalakrishnan

EOF

check_interface()
{
    # Check if ifconfig is available
    if ! command -v ifconfig > /dev/null 2>&1; then
        echo "ERROR: ifconfig command not found. Please install net-tools."
        exit 1
    fi

    # Ensure network interfaces exist
    if ! ifconfig | grep -q ":"; then
        echo "ERROR: No network interfaces detected. Check your network configuration."
        exit 1
    fi

    echo -en "Report the Network Interface: "
    read -r ETH

    # Validate interface input
    if [ -z "$ETH" ]; then
        echo "ERROR: Network interface cannot be empty."
        exit 1
    fi

    # Create temporary file for interfaces
    mkdir -p "$TMP_PATH"
    ifconfig | grep : | cut -d: -f1 | grep -v ' ' > "$TMP_PATH/eths"

    # Check if interface exists
    isInFile=$(grep -Fxc "$ETH" "$TMP_PATH/eths")

    # Loop for interface validation with max attempts
    local max_attempts=3
    local attempt=1

    while [ "$isInFile" -eq 0 ] && [ "$attempt" -le "$max_attempts" ]; do
        echo "WARNING!! Network Interface '$ETH' is invalid!"
        echo "Available interfaces:"
        cat "$TMP_PATH/eths"
        echo -en "Report the Network Interface (Attempt $attempt/$max_attempts): "
        read -r ETH
        isInFile=$(grep -Fxc "$ETH" "$TMP_PATH/eths")
        attempt=$((attempt + 1))
    done

    # Final validation
    if [ "$isInFile" -eq 0 ]; then
        echo "ERROR: Maximum interface selection attempts reached. Exiting."
        exit 1
    fi

    # Additional interface validation
    if ! ip link show "$ETH" > /dev/null 2>&1; then
        echo "ERROR: Unable to access network interface $ETH. Check permissions or interface status."
        exit 1
    fi
}
	
init_directories()
{
	# Validate output directory input
	if [ -z "$DIRECTORY" ]; then
		echo -en "Provide a target directory: "
		read -r DIRECTORY
	fi

	# Validate directory path
	if [ -z "$DIRECTORY" ]; then
		echo "ERROR: Directory path cannot be empty."
		exit 1
	fi

	# Remove trailing slash if present
	DIRECTORY="${DIRECTORY%/}"

	# Create base directory
	if [ ! -d "$DIRECTORY" ]; then
		echo "Directory $DIRECTORY does not exist. Attempting to create..."
		if ! mkdir -p "$DIRECTORY"; then
			echo "ERROR: Unable to create directory $DIRECTORY. Check permissions."
			exit 1
		fi
	fi

	# Define and create all required subdirectories
	PING_PATH="$DIRECTORY/scans/icmp"
	TCP_PATH="$DIRECTORY/scans/tcp"
	UDP_PATH="$DIRECTORY/scans/udp"
	SCTP_PATH="$DIRECTORY/scans/sctp"
	DCCP_PATH="$DIRECTORY/scans/dccp"
	IGMP_PATH="$DIRECTORY/scans/igmp"
	ARP_PATH="$DIRECTORY/scans/arp"
	SECURITY_PATH="$DIRECTORY/security"
	SSL_PATH="$DIRECTORY/security/ssl"
	OS_PATH="$DIRECTORY/security/os_fingerprint"
	NETWORK_PATH="$DIRECTORY/network_layers"
	APP_PATH="$DIRECTORY/app_protocols"
	PERF_PATH="$DIRECTORY/performance"
	TMP_PATH="$DIRECTORY/tmp"

	# Create all subdirectories
	for dir in \
		"$PING_PATH" \
		"$TCP_PATH" \
		"$UDP_PATH" \
		"$SCTP_PATH" \
		"$DCCP_PATH" \
		"$IGMP_PATH" \
		"$ARP_PATH" \
		"$SECURITY_PATH" \
		"$SSL_PATH" \
		"$OS_PATH" \
		"$NETWORK_PATH/traceroute" \
		"$NETWORK_PATH/path_analysis" \
		"$APP_PATH/http" \
		"$APP_PATH/dns" \
		"$APP_PATH/ssh" \
		"$PERF_PATH/bandwidth" \
		"$PERF_PATH/latency" \
		"$TMP_PATH"; do
		if ! mkdir -p "$dir"; then
			echo "ERROR: Failed to create directory: $dir"
			exit 1
		fi
	done

	# Verify all directories were created
	for dir in \
		"$PING_PATH" \
		"$TCP_PATH" \
		"$UDP_PATH" \
		"$SCTP_PATH" \
		"$DCCP_PATH" \
		"$IGMP_PATH" \
		"$ARP_PATH" \
		"$SECURITY_PATH" \
		"$SSL_PATH" \
		"$OS_PATH" \
		"$NETWORK_PATH" \
		"$APP_PATH" \
		"$PERF_PATH" \
		"$TMP_PATH"; do
		if [ ! -d "$dir" ]; then
			echo "ERROR: Directory verification failed for: $dir"
			exit 1
		fi
	done

	# Export paths for use in other functions
	export PING_PATH TCP_PATH UDP_PATH SCTP_PATH DCCP_PATH IGMP_PATH ARP_PATH
	export SECURITY_PATH SSL_PATH OS_PATH NETWORK_PATH APP_PATH PERF_PATH TMP_PATH
}

init_vars() {
    # Use command line arguments instead of prompting
    if [ -z "$DIRECTORY" ]; then
        DIRECTORY="./segmentation_test_$(date +%Y%m%d_%H%M%S)"
    fi
    
    init_directories
    
    # Validate interface
    if ! ip link show "$ETH" > /dev/null 2>&1; then
        echo "ERROR: Invalid interface $ETH"
        exit 1
    fi
    
    # Validate IP format
    if ! echo "$TARGET_IP" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' > /dev/null; then
        echo "ERROR: Invalid IP address format"
        exit 1
    fi

    # Validate CIDR format
    if ! echo "$TARGET_NETWORK" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' > /dev/null; then
        echo "ERROR: Invalid CIDR notation format"
        exit 1
    fi

    # Use TARGET_NETWORK for scope
    echo "$TARGET_NETWORK" > "$TMP_PATH/scope.txt"
    SCOPE="$TMP_PATH/scope.txt"

    rm -f "$TCP_PATH/hosts_complete_tcp.txt"
    rm -f "$UDP_PATH/hosts_complete_udp.txt"
    echo "TCP Hosts Scan Complete" > "$TCP_PATH/hosts_complete_tcp.txt"
    echo "UDP Hosts Scan Complete" > "$UDP_PATH/hosts_complete_udp.txt"
}

split_machines()
{
	num_hosts=$(wc -l < "$PING_PATH/alivemachines.txt")
	num_hosts_list=$(( $num_hosts > 4 ? $(($num_hosts/4)) : 1 ))

	split "$PING_PATH/alivemachines.txt" -d -l $num_hosts_list "$TMP_PATH/list"

	num_lists=$(ls "$TMP_PATH/" | grep -c "list")
}

merge_ping_sweep()
{
	IP_REGEX="([0-9]{1,3}[\.]){3}[0-9]{1,3}"

	cat $PING_PATH/ping_sweep* | grep "report for" | grep -Eo $IP_REGEX | sort -u > $PING_PATH/alivemachines.txt

	split_machines
}

ping_sweep() {
    echo "Executing PING Sweep"
    nmap -sn -PE -e "$ETH" -iL "$SCOPE" -oA "$PING_PATH/ping_sweep" > /dev/null
    merge_ping_sweep
}

# Add cleanup function and trap
cleanup() {
    echo -e "\nCleaning up temporary files..."
    rm -rf "$TMP_PATH" 2>/dev/null
    rm -f "$PING_PATH/ping_sweep"* 2>/dev/null
    exit 1
}

trap cleanup SIGINT SIGTERM

# Fix disk space check function
check_disk_space() {
    # Check if DIRECTORY is set
    if [ -z "$DIRECTORY" ]; then
        echo "ERROR: Output directory not set"
        exit 1
    fi

    local required_space=5120  # 5GB in MB
    # Fix df command and integer comparison
    local available_space=$(df -m "$DIRECTORY" 2>/dev/null | awk 'NR==2 {print $4}')
    
    # Validate available_space is a number
    if ! [[ "$available_space" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Could not determine available disk space"
        exit 1
    fi
    
    if [ "$available_space" -lt "$required_space" ]; then
        echo "ERROR: Insufficient disk space. Required: ${required_space}MB, Available: ${available_space}MB"
        exit 1
    fi
}

# Enhanced dependency check
check_dependencies() {
    echo "Checking required dependencies..."
    
    # Define required tools
    local REQUIRED_TOOLS=(
        "nmap"          # For port scanning and service detection
        "tcpdump"       # For packet capture and analysis
        "ping"          # For basic connectivity tests
        "traceroute"    # For network path analysis
        "mtr"           # For advanced path analysis
        "arp-scan"      # For ARP mapping
        "nc"            # For netcat tests
        "ip"            # For routing information
        "iperf3"        # For bandwidth testing
        "testssl.sh"    # For SSL/TLS analysis (optional)
    )
    
    local MISSING_TOOLS=()
    
    # Check each tool
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            MISSING_TOOLS+=("$tool")
        fi
    done
    
    # If tools are missing, provide installation instructions
    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        echo "ERROR: The following required tools are missing:"
        printf '%s\n' "${MISSING_TOOLS[@]}"
        echo ""
        echo "Installation instructions:"
        echo "For Debian/Ubuntu:"
        echo "sudo apt-get install nmap tcpdump traceroute mtr arp-scan netcat-traditional iproute2 iperf3"
        echo ""
        echo "For RHEL/CentOS:"
        echo "sudo yum install nmap tcpdump traceroute mtr arp-scan nc iproute iperf3"
        echo ""
        echo "For testssl.sh:"
        echo "git clone https://github.com/drwetter/testssl.sh.git"
        echo "cd testssl.sh"
        echo "chmod +x testssl.sh"
        echo "sudo cp testssl.sh /usr/local/bin/"
        
        exit 1
    fi
    
    echo "All required dependencies are installed."
}

# Add progress indicator function
show_progress() {
    local pid=$1
    local delay=0.5
    local spin='-\|/'
    local i=0
    
    while ps -p $pid > /dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] " "${spin:$i:1}"
        sleep $delay
    done
    printf "\r    \r"
}

# Fix protocol scanning functions syntax
sctp_scan() {
    echo "Performing SCTP Protocol Scan..."
    local SCTP_DIR="${DIRECTORY}/scans/sctp"
    mkdir -p "$SCTP_DIR"
    
    {
        echo "SCTP Protocol Scan Results"
        echo "-------------------------"
        echo "Target: $TARGET_IP"
        echo "Date: $(date)"
        echo ""
        
        # Run nmap scan with both XML and normal output
        nmap -Pn -sY --top-ports 1000 "$TARGET_IP" \
            -oX "$SCTP_DIR/sctp_scan.xml" \
            -oN "$SCTP_DIR/sctp_scan.nmap" 2>&1
        
        echo "Nmap SCTP Scan Output:"
        echo "----------------------"
        if [ -f "$SCTP_DIR/sctp_scan.nmap" ]; then
            cat "$SCTP_DIR/sctp_scan.nmap"
        else
            echo "No nmap output generated"
        fi
    } > "$SCTP_DIR/sctp_scan.txt"
}

dccp_scan() {
    echo "Performing DCCP Port Check..."
    local DCCP_DIR="${DIRECTORY}/scans/dccp"
    mkdir -p "$DCCP_DIR"
    
    {
        echo "DCCP Port Check Results"
        echo "----------------------"
        echo "Target: $TARGET_IP"
        echo "Date: $(date)"
        echo ""
        
        # Run nmap scan with both XML and normal output
        nmap -Pn -sS -p 33 -sV "$TARGET_IP" \
            -oX "$DCCP_DIR/dccp_scan.xml" \
            -oN "$DCCP_DIR/dccp_scan.nmap" 2>&1
            
        echo "Nmap DCCP Port Check Output:"
        echo "--------------------------"
        if [ -f "$DCCP_DIR/dccp_scan.nmap" ]; then
            cat "$DCCP_DIR/dccp_scan.nmap"
        else
            echo "No nmap output generated"
        fi
        
        echo ""
        echo "Note: This scan checks port 33, which is commonly used by DCCP."
        echo "An open port 33 might indicate DCCP service, but is not conclusive."
    } > "$DCCP_DIR/dccp_scan.txt"
}

igmp_discovery() {
    echo "Performing IGMP Multicast Group Discovery..."
    local IGMP_DIR="${DIRECTORY}/scans/igmp"
    mkdir -p "$IGMP_DIR"
    
    {
        echo "IGMP Multicast Group Discovery Results"
        echo "------------------------------------"
        echo "Target Network: $TARGET_NETWORK"
        echo "Date: $(date)"
        echo ""
        
        # Run nmap scan with both XML and normal output
        nmap -Pn --send-ip -sL -n "$TARGET_NETWORK" \
            -oX "$IGMP_DIR/igmp_groups.xml" \
            -oN "$IGMP_DIR/igmp_groups.nmap" 2>&1
            
        echo "Nmap IGMP Discovery Output:"
        echo "-------------------------"
        if [ -f "$IGMP_DIR/igmp_groups.nmap" ]; then
            cat "$IGMP_DIR/igmp_groups.nmap"
        else
            echo "No nmap output generated"
        fi
    } > "$IGMP_DIR/igmp_groups.txt"
}

arp_mapping() {
    echo "Performing ARP Network Mapping..."
    if ! arp-scan --localnet > "${DIRECTORY}/scans/arp/arp_map.txt" 2>/dev/null; then
        echo "WARNING: ARP scan failed"
        mkdir -p "${DIRECTORY}/scans/arp"
        echo "ARP scan failed" > "${DIRECTORY}/scans/arp/arp_map.txt"
    fi
}

# Security Scanning Functions
ssl_analysis() {
	echo "Performing SSL/TLS Certificate Analysis..."
	
	# Check for different possible testssl locations
	TESTSSL_CMD=""
	for cmd in "testssl.sh" "/usr/bin/testssl" "/usr/local/bin/testssl.sh" "$HOME/testssl.sh/testssl.sh"; do
		if command -v "$cmd" >/dev/null 2>&1; then
			TESTSSL_CMD="$cmd"
			break
		fi
	done

	if [ -z "$TESTSSL_CMD" ]; then
		echo "WARNING: testssl not found, skipping SSL analysis"
		echo "SSL analysis skipped - testssl not found" > "$SSL_PATH/ssl_analysis.txt"
		return
	fi

	if ! "$TESTSSL_CMD" --quiet --color 0 "$TARGET_IP" > "$SSL_PATH/ssl_analysis.txt" 2>/dev/null; then
		echo "WARNING: SSL analysis failed"
		echo "SSL analysis failed" > "$SSL_PATH/ssl_analysis.txt"
	fi
}

os_fingerprint() {
    echo "Performing OS Fingerprinting..."
    if ! nmap -Pn -O "$TARGET_IP" -oX "${DIRECTORY}/security/os_fingerprint/os_details.xml" > /dev/null 2>&1; then
        echo "WARNING: OS fingerprinting failed"
        mkdir -p "${DIRECTORY}/security/os_fingerprint"
        echo "OS detection failed" > "${DIRECTORY}/security/os_fingerprint/os_details.xml"
    fi
}

# Network Analysis Functions
network_path_analysis() {
	echo "Performing Network Path Analysis..."
	traceroute "$TARGET_IP" > "$NETWORK_PATH/traceroute/path_trace.txt"
	mtr -r "$TARGET_IP" > "$NETWORK_PATH/path_analysis/mtr_report.txt"
}

# Application Protocol Scanning
app_protocol_scan() {
    echo "Scanning for Application Protocols..."
    
    # HTTP/HTTPS scan
    nmap -Pn -sS -p 80,443 -sV "$TARGET_IP" -oX "${DIRECTORY}/app_protocols/http/http_scan.xml" > /dev/null 2>&1
    
    # DNS scan
    nmap -Pn -sU -p 53 -sV "$TARGET_IP" -oX "${DIRECTORY}/app_protocols/dns/dns_scan.xml" > /dev/null 2>&1
    
    # SSH scan
    nmap -Pn -sS -p 22 -sV "$TARGET_IP" -oX "${DIRECTORY}/app_protocols/ssh/ssh_scan.xml" > /dev/null 2>&1
}

# Update pre_scan_check to use absolute paths
pre_scan_check() {
    local scan_dirs=(
        "${DIRECTORY}/scans/sctp"
        "${DIRECTORY}/scans/dccp"
        "${DIRECTORY}/scans/igmp"
        "${DIRECTORY}/scans/arp"
        "${DIRECTORY}/security/ssl"
        "${DIRECTORY}/security/os_fingerprint"
        "${DIRECTORY}/app_protocols/http"
        "${DIRECTORY}/app_protocols/dns"
        "${DIRECTORY}/app_protocols/ssh"
        "${DIRECTORY}/network_layers/traceroute"
        "${DIRECTORY}/network_layers/path_analysis"
        "${DIRECTORY}/performance/bandwidth"
        "${DIRECTORY}/performance/latency"
    )

    for dir in "${scan_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo "Creating directory: $dir"
            if ! mkdir -p "$dir"; then
                echo "ERROR: Failed to create directory: $dir"
                exit 1
            fi
        fi
    done
}

# Test for common bypass ports
test_bypass_ports() {
    echo "Testing Common Bypass Ports..."
    local BYPASS_DIR="${DIRECTORY}/segmentation"
    mkdir -p "$BYPASS_DIR"
    
    {
        echo "Common Bypass Ports Test Results"
        echo "-------------------------------"
        echo "Testing ports commonly used to bypass network segmentation"
        echo "Date: $(date)"
        echo "Target: $TARGET_IP"
        echo ""
        
        # Save both XML and normal output
        nmap -Pn -sS -p 21,22,23,25,53,80,443,445,3389,5900,8080,8443 \
            -sV "$TARGET_IP" -oX "$BYPASS_DIR/bypass_ports.xml" \
            -oN "$BYPASS_DIR/bypass_ports.nmap" 2>&1
            
        # Include the nmap output directly
        if [ -f "$BYPASS_DIR/bypass_ports.nmap" ]; then
            cat "$BYPASS_DIR/bypass_ports.nmap"
        fi
    } > "$BYPASS_DIR/bypass_ports.txt"
}

# Test VLAN configuration
test_vlan_config() {
    echo "Testing VLAN Configuration..."
    local VLAN_FILE="${DIRECTORY}/segmentation/vlan_test.txt"
    mkdir -p "${DIRECTORY}/segmentation"
    
    {
        echo "VLAN Configuration Test Results"
        echo "------------------------------"
        echo "Checking for DTP and trunk ports"
        echo "Interface: $ETH"
        echo "Date: $(date)"
        echo ""
        
        timeout 30 sudo tcpdump -i "$ETH" -nn -v '(vlan or esp or ip[6:2] & 0x2000 != 0)' -c 100 2>&1
    } > "$VLAN_FILE"
}

# Analyze routing
analyze_routing() {
    echo "Analyzing Routing..."
    local ROUTE_FILE="${DIRECTORY}/segmentation/routing.txt"
    mkdir -p "${DIRECTORY}/segmentation"
    
    {
        echo "Routing Analysis Results"
        echo "-----------------------"
        echo "Date: $(date)"
        echo "Target: $TARGET_IP"
        echo ""
        
        echo "Current Routing Table:"
        ip route
        
        echo -e "\nRoute to Target:"
        ip route get "$TARGET_IP"
    } > "$ROUTE_FILE"
}

# Test network isolation
test_network_isolation() {
    echo "Testing Network Isolation..."
    local ISOLATION_FILE="${DIRECTORY}/segmentation/isolation.txt"
    mkdir -p "${DIRECTORY}/segmentation"
    
    {
        echo "Network Isolation Test Results"
        echo "-----------------------------"
        echo "Testing connectivity to common internal services"
        echo "Date: $(date)"
        echo "Target: $TARGET_IP"
        echo ""
        
        echo "Testing common Windows/Internal ports:"
        for port in 135 137 138 139 445 3389; do
            echo -n "Port $port: "
            timeout 2 nc -zv -w 2 "$TARGET_IP" $port 2>&1 || echo "closed/filtered"
        done
    } > "$ISOLATION_FILE"
}

# Update comprehensive_segmentation_test to include new functions
comprehensive_segmentation_test() {
    # Validate target is set
    if [ -z "$TARGET_IP" ] || [ -z "$TARGET_NETWORK" ]; then
        echo "ERROR: TARGET_IP and TARGET_NETWORK must be set before running segmentation test!"
        exit 1
    fi
    
    # Ensure all scan directories exist
    pre_scan_check
    
    # Start with full TCP/UDP scan
    echo "Starting full port scan..."
    nmap_full_scan
    
    # Run other protocol tests
    sctp_scan
    dccp_scan
    igmp_discovery
    arp_mapping
    ssl_analysis
    os_fingerprint
    network_path_analysis
    performance_metrics
    app_protocol_scan
    
    # Run segmentation-specific tests
    echo "Starting Network Segmentation Tests..."
    test_bypass_ports
    test_vlan_config
    analyze_routing
    test_network_isolation
    
    echo "Network Segmentation Tests Completed"
}

# Define port lists as global variables
TCP_PORTS="11,13,15,17,19-23,25,37,42,53,66,69-70,79-81,88,98,109-111,113,118-119,123,135,139,143,220,256-259,264,371,389,411,443,445,464-465,512-515,523-524,540,548,554,563,580,593,636,749-751,873,900-901,990,992-993,995,1080,1114,1214,1234,1352,1433,1494,1508,1521,1720,1723,1755,1801,2000-2001,2003,2049,2301,2401,2447,2690,2766,3128,3268-3269,3306,3372,3389,4100,4443-4444,4661-4662,5000,5432,5555-5556,5631-5632,5634,5800-5802,5900-5901,6000,6112,6346,6387,6666-6667,6699,7007,7100,7161,7777-7778,7070,8000-8001,8010,8080-8081,8100,8888,8910,9100,10000,12345-12346,20034,21554,32000,32768-32790"
UDP_PORTS="7,13,17,19,37,53,67-69,111,123,135,137,161,177,407,464,500,517-518,520,1434,1645,1701,1812,2049,3527,4569,4665,5036,5060,5632,6502,7778,15345"

nmap_full_scan() {
    echo "Executing TCP and UDP Port Scan"
    local TCP_DIR="${DIRECTORY}/scans/tcp"
    local UDP_DIR="${DIRECTORY}/scans/udp"
    
    mkdir -p "$TCP_DIR" "$UDP_DIR"

    # TCP scan with specific ports
    echo "Starting TCP scan on specified ports..."
    {
        echo "TCP Port Scan Results"
        echo "--------------------"
        echo "Target: $TARGET_IP"
        echo "Ports: $TCP_PORTS"
        echo "Date: $(date)"
        echo ""
        
        nmap -Pn -sS -p"$TCP_PORTS" -sV "$TARGET_IP" \
            -oX "$TCP_DIR/full_tcp_scan.xml" \
            -oN "$TCP_DIR/full_tcp_scan.nmap" 2>&1
            
        if [ -f "$TCP_DIR/full_tcp_scan.nmap" ]; then
            cat "$TCP_DIR/full_tcp_scan.nmap"
        fi
    } > "$TCP_DIR/tcp_scan.txt"

    # UDP scan with specific ports
    echo "Starting UDP scan on specified ports..."
    {
        echo "UDP Port Scan Results"
        echo "--------------------"
        echo "Target: $TARGET_IP"
        echo "Ports: $UDP_PORTS"
        echo "Date: $(date)"
        echo ""
        
        nmap -Pn -sU -p"$UDP_PORTS" -sV "$TARGET_IP" \
            -oX "$UDP_DIR/udp_scan.xml" \
            -oN "$UDP_DIR/udp_scan.nmap" 2>&1
            
        if [ -f "$UDP_DIR/udp_scan.nmap" ]; then
            cat "$UDP_DIR/udp_scan.nmap"
        fi
    } > "$UDP_DIR/udp_scan.txt"

    echo "TCP and UDP Port Scans Completed"
    
    # Create a summary of open ports
    {
        echo "Open Ports Summary"
        echo "-----------------"
        echo "Date: $(date)"
        echo ""
        echo "TCP Open Ports:"
        grep "open" "$TCP_DIR/tcp_scan.txt" || echo "No open TCP ports found"
        echo ""
        echo "UDP Open Ports:"
        grep "open" "$UDP_DIR/udp_scan.txt" || echo "No open UDP ports found"
    } > "${DIRECTORY}/scans/open_ports_summary.txt"
}

# Add logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $level: $message" | tee -a "$DIRECTORY/scan.log"
}

# Add validation for root privileges at the start of the script
validate_privileges() {
    if [[ $UID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root!"
        exit 1
    fi
}

# Modify main function to use new features
main() {
    validate_privileges
    
    # Start logging
    log_message "INFO" "Starting network segmentation test"
    
    # Initialize variables first
    init_vars
    
    # Then check dependencies and disk space
    check_dependencies
    check_disk_space
    
    comprehensive_segmentation_test

    generate_segmentation_reportping
	log_message "INFO" "Scan completed successfully"
    echo "Final report is available at: ${DIRECTORY}/SEGMENTATION_TEST_SUMMARY.txt"
    echo "You can view it using: cat ${DIRECTORY}/SEGMENTATION_TEST_SUMMARY.txt"

}

generate_segmentation_report() {
    local REPORT_FILE="${DIRECTORY}/SEGMENTATION_TEST_SUMMARY.txt"
    
    {
        echo "# Network Segmentation Test Report"
        echo "=================================="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Target IP: $TARGET_IP"
        echo "Target Network: $TARGET_NETWORK"
        echo "Interface: $ETH"
        echo ""
        
        echo "# 1. Full Port Scan Results"
        echo "## Description"
        echo "A comprehensive port scan helps identify open services and potential"
        echo "communication paths between network segments. This test includes both"
        echo "TCP and UDP scans to map available services."
        echo ""
        
        echo "## 1.1 TCP Full Scan"
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "nmap -Pn -sS -p\"$TCP_PORTS\" -sV \"$TARGET_IP\""
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/scans/tcp/full_tcp_scan.nmap" ]; then
            cat "${DIRECTORY}/scans/tcp/full_tcp_scan.nmap"
        else
            echo "TCP full scan results not available"
        fi
        echo ""
        
        echo "## 1.2 UDP Scan"
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "nmap -Pn -sU -p\"$UDP_PORTS\" -sV \"$TARGET_IP\""
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/scans/udp/udp_scan.nmap" ]; then
            cat "${DIRECTORY}/scans/udp/udp_scan.nmap"
        else
            echo "UDP scan results not available"
        fi
        echo ""
        
        echo "# 2. Protocol-Specific Scans"
        echo "## Description"
        echo "These scans check for alternative protocols that might bypass traditional"
        echo "network segmentation controls. SCTP, DCCP, and IGMP protocols can sometimes"
        echo "provide unexpected communication paths."
        echo ""
        
        echo "## 2.1 SCTP Scan"
        echo "### Description"
        echo "SCTP (Stream Control Transmission Protocol) is often used in telecommunications"
        echo "signaling. Open SCTP ports might indicate cross-segment communication channels."
        echo ""
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "nmap -Pn -sY --top-ports 1000 \"$TARGET_IP\""
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/scans/sctp/sctp_scan.nmap" ]; then
            cat "${DIRECTORY}/scans/sctp/sctp_scan.nmap"
        else
            echo "SCTP scan results not available"
        fi
        echo ""
        
        echo "## 2.2 DCCP Port Check"
        echo "### Description"
        echo "DCCP (Datagram Congestion Control Protocol) is designed for streaming media"
        echo "and other real-time applications. Its presence might indicate unauthorized"
        echo "streaming services across segments."
        echo ""
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "nmap -Pn -sS -p 33 -sV \"$TARGET_IP\""
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/scans/dccp/dccp_scan.nmap" ]; then
            cat "${DIRECTORY}/scans/dccp/dccp_scan.nmap"
        else
            echo "DCCP scan results not available"
        fi
        echo ""
        
        echo "## 2.3 IGMP Discovery"
        echo "### Description"
        echo "IGMP (Internet Group Management Protocol) is used for multicast group"
        echo "management. Multicast groups can span multiple network segments and"
        echo "potentially bypass segmentation controls."
        echo ""
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "nmap -Pn --send-ip -sL -n \"$TARGET_NETWORK\""
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/scans/igmp/igmp_groups.nmap" ]; then
            cat "${DIRECTORY}/scans/igmp/igmp_groups.nmap"
        else
            echo "IGMP discovery results not available"
        fi
        echo ""
        
        echo "# 3. Network Segmentation Analysis"
        echo "## Description"
        echo "These tests examine the effectiveness of network segmentation by checking"
        echo "VLAN configurations, routing tables, and network isolation."
        echo ""
        
        echo "## 3.1 VLAN Configuration"
        echo "### Description"
        echo "Analyzes VLAN setup and checks for potential VLAN hopping vulnerabilities"
        echo "by monitoring CDP/DTP traffic and trunk port configurations."
        echo ""
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "tcpdump -i \"$ETH\" -nn -v '(vlan or esp or ip[6:2] & 0x2000 != 0)'"
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/segmentation/vlan_test.txt" ]; then
            cat "${DIRECTORY}/segmentation/vlan_test.txt"
        else
            echo "VLAN test results not available"
        fi
        echo ""
        
        echo "## 3.2 Routing Analysis"
        echo "### Description"
        echo "Examines routing tables and paths to identify potential unauthorized"
        echo "routes between network segments."
        echo ""
        echo "### Commands Used:"
        echo "\`\`\`bash"
        echo "ip route"
        echo "ip route get \"$TARGET_IP\""
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/segmentation/routing.txt" ]; then
            cat "${DIRECTORY}/segmentation/routing.txt"
        else
            echo "Routing analysis results not available"
        fi
        echo ""
        
        echo "## 3.3 Network Isolation"
        echo "### Description"
        echo "Tests connectivity to common internal services to verify proper network"
        echo "isolation between segments."
        echo ""
        echo "### Command Used:"
        echo "\`\`\`bash"
        echo "nc -zv -w 2 \"$TARGET_IP\" [PORT]"
        echo "\`\`\`"
        echo ""
        echo "### Results:"
        if [ -f "${DIRECTORY}/segmentation/isolation.txt" ]; then
            cat "${DIRECTORY}/segmentation/isolation.txt"
        else
            echo "Network isolation test results not available"
        fi
        echo ""
        
        echo "# Summary and Recommendations"
        echo "## Key Findings"
        echo "1. Review any open ports for necessary business functions"
        echo "2. Verify all detected protocols align with security policies"
        echo "3. Check VLAN configurations for potential vulnerabilities"
        echo "4. Validate routing tables for proper segmentation"
        echo ""
        echo "## Recommendations"
        echo "1. Close unnecessary ports and services"
        echo "2. Disable unused protocols"
        echo "3. Implement strict VLAN access controls"
        echo "4. Regular review of routing policies"
        echo "5. Monitor for unauthorized cross-segment traffic"
        echo ""
        
        echo "End of Report"
        echo "Generated on: $(date '+%Y-%m-%d %H:%M:%S')"
        
    } > "$REPORT_FILE"
    
    echo "Report generated successfully at: $REPORT_FILE"
    echo "You can view it using: cat $REPORT_FILE"
}

# Enhanced performance metrics with timeout
performance_metrics() {
    echo "Collecting Network Performance Metrics..."
    
    # Bandwidth test with timeout
    echo "Running bandwidth test..."
    timeout 30 iperf3 -c "$TARGET_IP" -t 10 > "$PERF_PATH/bandwidth/bandwidth.txt" 2>/dev/null || {
        echo "WARNING: Bandwidth test failed or timed out"
        echo "Test failed or timed out" > "$PERF_PATH/bandwidth/bandwidth.txt"
    }
    
    # Latency test with timeout
    echo "Running latency test..."
    timeout 30 ping -c 100 "$TARGET_IP" > "$PERF_PATH/latency/ping_results.txt" 2>/dev/null || {
        echo "WARNING: Latency test failed or timed out"
        echo "Test failed or timed out" > "$PERF_PATH/latency/ping_results.txt"
    }
}

main "$@"
