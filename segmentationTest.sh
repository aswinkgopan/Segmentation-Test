#!/bin/bash

# Color codes for logging
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
RED="\e[31m"
BOLD="\e[1m"
RESET="\e[0m"

# Default TCP and UDP ports to scan

SCTP_PORTS="7,9,20-22,80,179,443,1021,1022,1167,1720,1812,1813,2049,2225,2427,2904,2905,2944,2945,3097,3565,3863-3868,4195,4333,4502,4711,4739,4740,5060,5061,5090,5091,5215,5445,5672,5675,5868,5910-5912,5913,6701-6706,6970,7626,7701,7728,8282,8471,9082,9084,9899-9902,11997-11999,14001,20049,25471,29118,29168,29169,30100,36412,36422-36424,36443,36444,36462,38412,38422,38462,38472"
TCP_PORTS="7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
UDP_PORTS="53,67,123,135,137-138,161,445,631,1434"

# Logging function with colorized output
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${timestamp} ${BOLD}${GREEN}[INFO]${RESET} ${message}" | tee -a "${DIRECTORY}/scan.log"
            ;;
        "WARN")
            echo -e "${timestamp} ${BOLD}${YELLOW}[WARN]${RESET} ${message}" | tee -a "${DIRECTORY}/scan.log"
            ;;
        "ERROR")
            echo -e "${timestamp} ${BOLD}${RED}[ERROR]${RESET} ${message}" | tee -a "${DIRECTORY}/scan.log"
            ;;
        "DEBUG")
            echo -e "${timestamp} ${BOLD}${BLUE}[DEBUG]${RESET} ${message}" | tee -a "${DIRECTORY}/scan.log"
            ;;
    esac
}

# Usage function
usage() {
    echo "Usage: $0 -t <target_ips> -i <interface> [-n <network>] [-d <directory>]"
    echo "  -t  Comma-separated list of target IPs (required)"
    echo "  -i  Network interface to use (required)"
    echo "  -n  Target network (optional)"
    echo "  -d  Output directory (optional, defaults to ./segmentation_test_<timestamp>)"
    exit 1
}

# Initialize directories
init_directories() {
    local base_dirs=(
        "scans/tcp"
        "scans/udp"
        "scans/sctp"
        "scans/dccp"
        "scans/igmp"
        "scans/arp"
        "security/os_fingerprint"
        "network_layers/traceroute"
        "network_layers/path_analysis"
        "app_protocols/http"
        "app_protocols/dns"
        "app_protocols/ssh"
        "performance/bandwidth"
        "performance/latency"
        "reports"
        "ping_sweep"
    )
    
    for dir in "${base_dirs[@]}"; do
        mkdir -p "${DIRECTORY}/${dir}"
    done
}

# Merge ping sweep results
merge_ping_sweep() {
    local PING_PATH="${DIRECTORY}/ping_sweep"
    cat "${PING_PATH}/ping_sweep_n.txt" \
        "${PING_PATH}/ping_sweep_s.txt" \
        "${PING_PATH}/ping_sweep_a.txt" \
        "${PING_PATH}/ping_sweep_u.txt" \
        "${PING_PATH}/ping_sweep_y.txt" \
        "${PING_PATH}/ping_sweep_e.txt" \
        "${PING_PATH}/ping_sweep_p.txt" \
        "${PING_PATH}/ping_sweep_m.txt" \
        "${PING_PATH}/ping_sweep_o.txt" > "${PING_PATH}/ping_sweep_merged.txt"
}

# Ping sweep function
ping_sweep() {
    log "INFO" "Executing Ping Sweep"
    local PING_PATH="${DIRECTORY}/ping_sweep"
    
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_n.txt" -sn -n --packet-trace --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_s.txt" -sn -n --packet-trace -PS"${TCP_PORTS}" --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_a.txt" -sn -n --packet-trace -PA"${TCP_PORTS}" --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_u.txt" -sn -n --packet-trace -PU"${UDP_PORTS}" --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_y.txt" -sn -n --packet-trace -PY"${SCTP_PORTS}" --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_e.txt" -sn -n --packet-trace -PE --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_p.txt" -sn -n --packet-trace -PP --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_m.txt" -sn -n --packet-trace -PM --disable-arp-ping > /dev/null &
    nmap -T3 -e "${ETH}" -iL "${SCOPE}" -oN "${PING_PATH}/ping_sweep_o.txt" -sn -n --packet-trace -PO2 --disable-arp-ping> /dev/null &
    
    wait
    merge_ping_sweep
    log "INFO" "Finished Ping Sweep"
}

# Protocol-specific test functions
run_sctp_scan() {
    local target_ip=$1
    local host_dir=$2
    
    log "DEBUG" "Running SCTP scan for ${target_ip}"
    {
        echo "SCTP Protocol Scan Results"
        echo "-------------------------"
        echo "Target: ${target_ip}"
        echo "Date: $(date)"
        echo
        
        nmap -Pn -sY --top-ports 1000 "${target_ip}" \
            -oX "${host_dir}/sctp_scan.xml" \
            -oN "${host_dir}/sctp_scan.txt" 2>&1
    } > "${host_dir}/sctp_results.txt"
}

run_dccp_scan() {
    local target_ip=$1
    local host_dir=$2
    
    log "DEBUG" "Running DCCP scan for ${target_ip}"
    {
        echo "DCCP Protocol Scan Results"
        echo "-------------------------"
        echo "Target: ${target_ip}"
        echo "Date: $(date)"
        echo
        
        # Use SCTP INIT scan for DCCP (verify support)
        nmap -Pn -sY -p 33 -sV "${target_ip}" \
            -oX "${host_dir}/dccp_scan.xml" \
            -oN "${host_dir}/dccp_scan.txt" 2>&1
    } > "${host_dir}/dccp_results.txt"
}

run_igmp_discovery() {
    local target_ip=$1
    local host_dir=$2
    
    log "DEBUG" "Running IGMP discovery for ${target_ip}"
    {
        echo "IGMP Discovery Results"
        echo "---------------------"
        echo "Target: ${target_ip}"
        echo "Date: $(date)"
        echo
        
        # Monitor IGMP traffic
        timeout 30 tcpdump -i "${ETH}" -n "igmp" -c 100 2>&1
        
        # Additional IGMP group membership test
        nmap -Pn --send-ip -sL -n "${target_ip}/24" \
            -oX "${host_dir}/igmp_scan.xml" \
            -oN "${host_dir}/igmp_scan.txt" 2>&1
    } > "${host_dir}/igmp_results.txt"
}

# Run tests for a single host
run_host_tests() {
    local target_ip=$1
    local host_dir="${DIRECTORY}/hosts/${target_ip}"
    mkdir -p "${host_dir}/protocols"
    
    log "INFO" "Starting tests for host: ${target_ip}"
    
    # Run basic tests
    {
        # TCP/UDP Scan
        log "DEBUG" "Running TCP/UDP scan for ${target_ip}"
        nmap -Pn -sS -sU -p T:${TCP_PORTS},U:${UDP_PORTS} -sV "${target_ip}" \
            -oX "${host_dir}/port_scan.xml" \
            -oN "${host_dir}/port_scan.txt"
            
        # OS Fingerprinting
        log "DEBUG" "Running OS fingerprinting for ${target_ip}"
        nmap -Pn -O "${target_ip}" -oX "${host_dir}/os_fingerprint.xml"
        
        # Service Version Detection
        log "DEBUG" "Running service detection for ${target_ip}"
        nmap -Pn -sV --version-intensity 5 "${target_ip}" \
            -oX "${host_dir}/service_versions.xml"
            
        # Network Path Analysis
        log "DEBUG" "Running network path analysis for ${target_ip}"
        traceroute "${target_ip}" > "${host_dir}/traceroute.txt"
        mtr -r "${target_ip}" > "${host_dir}/mtr_report.txt"
        
        # Performance Metrics
        log "DEBUG" "Running performance tests for ${target_ip}"
        timeout 30 ping -c 10 "${target_ip}" > "${host_dir}/latency.txt"
        
    } 2>&1 | tee "${host_dir}/test_output.log"
    
    # Run protocol-specific tests
    run_sctp_scan "${target_ip}" "${host_dir}/protocols"
    run_dccp_scan "${target_ip}" "${host_dir}/protocols"
    run_igmp_discovery "${target_ip}" "${host_dir}/protocols"
    
    log "INFO" "Completed tests for host: ${target_ip}"
}

# Generate per-host report
generate_host_report() {
    local target_ip=$1
    local host_dir="${DIRECTORY}/hosts/${target_ip}"
    local report_file="${host_dir}/host_report.md"
    
    log "INFO" "Generating report for host: ${target_ip}"
    
    {
        echo "# Host Analysis Report: ${target_ip}"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo
        
        echo "## Port Scan Results"
        if [ -f "${host_dir}/port_scan.txt" ]; then
            echo "### Open Ports:"
            grep "open" "${host_dir}/port_scan.txt" || echo "No open ports found"
        fi
        
        echo
        echo "## Protocol Tests"
        
        echo "### SCTP Results"
        if [ -f "${host_dir}/protocols/sctp_results.txt" ]; then
            grep "open" "${host_dir}/protocols/sctp_results.txt" || echo "No SCTP ports found"
        fi
        
        echo "### DCCP Results"
        if [ -f "${host_dir}/protocols/dccp_results.txt" ]; then
            grep "open" "${host_dir}/protocols/dccp_results.txt" || echo "No DCCP ports found"
        fi
        
        echo "### IGMP Analysis"
        if [ -f "${host_dir}/protocols/igmp_results.txt" ]; then
            echo "IGMP traffic detected:"
            grep "IGMP" "${host_dir}/protocols/igmp_results.txt" || echo "No IGMP traffic detected"
        fi
        
        echo
        echo "## OS Detection Results"
        if [ -f "${host_dir}/os_fingerprint.xml" ]; then
            echo "### Detected Operating System:"
            xmllint --xpath "//os/osmatch/@name" "${host_dir}/os_fingerprint.xml" 2>/dev/null || echo "OS detection failed"
        fi
        
        echo
        echo "## Network Path Analysis"
        if [ -f "${host_dir}/traceroute.txt" ]; then
            echo "### Traceroute Results:"
            cat "${host_dir}/traceroute.txt"
        fi
        
        echo
        echo "## Performance Metrics"
        if [ -f "${host_dir}/latency.txt" ]; then
            echo "### Latency Statistics:"
            grep "rtt" "${host_dir}/latency.txt" || echo "No latency data available"
        fi
        
    } > "${report_file}"
    
    log "INFO" "Report generated for host: ${target_ip}"
}

# Generate final summary report
generate_summary_report() {
    local summary_file="${DIRECTORY}/SUMMARY_REPORT.md"
    
    log "INFO" "Generating summary report"
    
    {
        echo "# Network Segmentation Test Summary Report"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo
        
        echo "## Test Environment"
        echo "* Interface: ${ETH}"
        echo "* Target Network: ${TARGET_NETWORK}"
        echo "* Number of Hosts Tested: ${#TARGET_IP_ARRAY[@]}"
        echo
        
        echo "## Ping Sweep Results"
        if [ -f "${DIRECTORY}/ping_sweep/ping_sweep_merged.txt" ]; then
            echo "### Hosts Discovered:"
            cat "${DIRECTORY}/ping_sweep/ping_sweep_merged.txt" || echo "No hosts discovered"
        fi
        
        echo
        echo "## Per-Host Summary"
        for ip in "${TARGET_IP_ARRAY[@]}"; do
            local host_dir="${DIRECTORY}/hosts/${ip}"
            echo "### Host: ${ip}"
            echo "#### Protocol Analysis:"
            
            echo "##### SCTP Results:"
            if [ -f "${host_dir}/protocols/sctp_results.txt" ]; then
                cat "${host_dir}/protocols/sctp_results.txt" || echo "No SCTP ports found"
            else
                echo "No SCTP results available."
            fi
            
            echo "##### DCCP Results:"
            if [ -f "${host_dir}/protocols/dccp_results.txt" ]; then
                cat "${host_dir}/protocols/dccp_results.txt" || echo "No DCCP ports found"
            else
                echo "No DCCP results available."
            fi
            
            echo "##### IGMP Results:"
            if [ -f "${host_dir}/protocols/igmp_results.txt" ]; then
                cat "${host_dir}/protocols/igmp_results.txt" || echo "No IGMP traffic detected"
            else
                echo "No IGMP results available."
            fi
            
            echo
            echo "#### Open Ports:"
            if [ -f "${host_dir}/port_scan.txt" ]; then
                cat "${host_dir}/port_scan.txt" || echo "No open ports found"
            fi
            echo
            echo "#### OS Detection:"
            if [ -f "${host_dir}/os_fingerprint.xml" ]; then
                xmllint --xpath "//os/osmatch/@name" "${host_dir}/os_fingerprint.xml" 2>/dev/null || echo "OS detection failed"
            fi
            echo
            echo "#### Network Path Analysis:"
            if [ -f "${host_dir}/traceroute.txt" ]; then
                cat "${host_dir}/traceroute.txt"
            fi
            echo
            echo "#### Performance Metrics:"
            if [ -f "${host_dir}/latency.txt" ]; then
                grep "rtt" "${host_dir}/latency.txt" || echo "No latency data available"
            fi
            echo
        done
        
        echo "## Security Recommendations"
        echo "1. Review and disable unnecessary open ports"
        echo "2. Implement strict firewall rules"
        echo "3. Monitor for unauthorized cross-segment traffic"
        echo "4. Disable unused protocols (SCTP, DCCP, IGMP if not needed)"
        echo "5. Regular security assessments"
        
    } > "${summary_file}"
    
    log "INFO" "Summary report generated at: ${summary_file}"
}

# Main execution
main() {
    if [[ $UID -ne 0 ]]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi
    
    # Parse arguments
    while getopts "t:n:i:d:h" opt; do
        case $opt in
            t) TARGET_IPS="$OPTARG" ;;
            n) TARGET_NETWORK="$OPTARG" ;;
            i) ETH="$OPTARG" ;;
            d) DIRECTORY="$OPTARG" ;;
            h|?) usage ;;
        esac
    done
    
    # Validate arguments
    if [ -z "$TARGET_IPS" ] || [ -z "$ETH" ]; then
        log "ERROR" "Missing required arguments"
        usage
    fi
    
    # Set default directory if not specified
    DIRECTORY=${DIRECTORY:-"./segmentation_test_$(date +%Y%m%d_%H%M%S)"}
    
    # Initialize
    init_directories
    IFS=',' read -r -a TARGET_IP_ARRAY <<< "$TARGET_IPS"
    
    log "INFO" "Starting network segmentation tests"
    log "INFO" "Output directory: ${DIRECTORY}"
    
    # Perform ping sweep
    SCOPE="${DIRECTORY}/target_ips.txt"
    echo "${TARGET_IPS}" | tr ',' '\n' > "${SCOPE}"
    ping_sweep
    
    # Test each host
    for ip in "${TARGET_IP_ARRAY[@]}"; do
        run_host_tests "$ip"
        generate_host_report "$ip"
    done
    
    # Generate final report
    generate_summary_report
    
    log "INFO" "All tests completed successfully"
    echo -e "\n${BOLD}${GREEN}Test completed!${RESET}"
    echo -e "Summary report available at: ${BOLD}${DIRECTORY}/SUMMARY_REPORT.md${RESET}"
}

# Run main function with all arguments
main "$@"
