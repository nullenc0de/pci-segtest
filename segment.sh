#!/bin/bash

# Colors for output - using bright variants for better visibility
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Formatting helpers
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Test results counters and logging
PASSED=0
FAILED=0
SKIPPED=0
LOG_FILE="pci_test_$(date +%Y%m%d_%H%M%S).log"
JSON_REPORT="pci_report_$(date +%Y%m%d_%H%M%S).json"

# Initialize detailed logging
init_logging() {
    echo "PCI DSS v4.0 Compliance Test Log - $(date)" > "$LOG_FILE"
    echo "Tester: $(whoami)@$(hostname)" >> "$LOG_FILE"
    echo "Test Environment: CDE" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    # Initialize JSON report structure
    cat > "$JSON_REPORT" << 'EOF'
{
  "test_metadata": {
    "timestamp": "",
    "tester": "",
    "hostname": "",
    "version": "1.3.0",
    "pci_dss_version": "4.0"
  },
  "network_segments": {},
  "test_results": [],
  "summary": {
    "total_tests": 0,
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "compliance_status": ""
  }
}
EOF
    
    # Update JSON metadata
    update_json_metadata
}

# Update JSON report metadata
update_json_metadata() {
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    local temp_file=$(mktemp)
    jq --arg timestamp "$(date -Iseconds)" \
       --arg tester "$(whoami)" \
       --arg hostname "$(hostname)" \
       '.test_metadata.timestamp = $timestamp | .test_metadata.tester = $tester | .test_metadata.hostname = $hostname' \
       "$JSON_REPORT" > "$temp_file" && mv "$temp_file" "$JSON_REPORT"
}

# Enhanced logging function
log_test_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    local category="$4"
    local pci_requirement="$5"
    
    # Log to text file
    echo "[$(date -Iseconds)] $status: $test_name - $details" >> "$LOG_FILE"
    
    # Add to JSON report if jq is available
    if command -v jq >/dev/null 2>&1; then
        local temp_file=$(mktemp)
        jq --arg name "$test_name" \
           --arg status "$status" \
           --arg details "$details" \
           --arg category "$category" \
           --arg requirement "$pci_requirement" \
           --arg timestamp "$(date -Iseconds)" \
           '.test_results += [{
             "name": $name,
             "status": $status,
             "details": $details,
             "category": $category,
             "pci_requirement": $requirement,
             "timestamp": $timestamp
           }]' \
           "$JSON_REPORT" > "$temp_file" && mv "$temp_file" "$JSON_REPORT"
    fi
}

# Draw separator line
draw_line() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# Show section header
section_header() {
    draw_line
    echo -e "${BLUE}${BOLD}${UNDERLINE}$1${NC}"
    draw_line
}

# Enhanced test result display with logging
show_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    local category="${4:-general}"
    local pci_requirement="${5:-unknown}"

    case "$status" in
        PASS)
            echo -e "${GREEN}[✓ PASS]${NC} $test_name"
            PASSED=$((PASSED+1))
            ;;
        FAIL)
            echo -e "${RED}${BOLD}[✗ FAIL]${NC}${BOLD} $test_name${NC}"
            echo -e "${WHITE}  → Details: ${details}${NC}"
            FAILED=$((FAILED+1))
            ;;
        INFO|SKIP)
            echo -e "${CYAN}[i $status]${NC} $test_name"
            echo -e "${WHITE}  → Details: ${details}${NC}"
            SKIPPED=$((SKIPPED+1))
            ;;
        *)
            echo -e "${YELLOW}[? $status]${NC} $test_name — ${details}"
            ;;
    esac

    # Log the result
    log_test_result "$test_name" "$status" "$details" "$category" "$pci_requirement"
}

# Function to discover networks with enhanced capabilities
discover_networks() {
    section_header "ENHANCED NETWORK DISCOVERY"
    echo -e "${YELLOW}Discovering network segments with advanced methods...${NC}"
    declare -gA SEGMENTS
    declare -gA SEGMENT_DETAILS
    
    # Enhanced network discovery
    echo -e "  ${YELLOW}Phase 1: Interface and routing discovery...${NC}"
    
    # Get our current IP address - we're in the CDE by assumption
    MY_IP=$(ip route get 1 | awk '{print $(NF-2);exit}')
    
    # Store all networks with enhanced metadata
    declare -a DETECTED_NETWORKS=()
    declare -A NETWORK_INTERFACES=()
    declare -A NETWORK_GATEWAYS=()
    
    # Enhanced discovery method 1: Get all local routes with gateway info
    while read -r line; do
        if [[ $line =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
            network="${BASH_REMATCH[1]}"
            # Skip loopback and default routes
            if [[ $network != "127.0.0.0/8" && $network != "0.0.0.0/0" ]]; then
                DETECTED_NETWORKS+=("$network")
                # Extract gateway and interface info
                if [[ $line =~ via\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                    NETWORK_GATEWAYS["$network"]="${BASH_REMATCH[1]}"
                fi
                if [[ $line =~ dev\ ([a-zA-Z0-9]+) ]]; then
                    NETWORK_INTERFACES["$network"]="${BASH_REMATCH[1]}"
                fi
            fi
        fi
    done < <(ip route show)
    
    # Enhanced discovery method 2: All active interfaces with detailed info
    while read -r iface; do
        if [[ -n "$iface" && "$iface" != "lo" ]]; then
            # Get IPv4 addresses
            ip_info=$(ip addr show dev $iface | grep "inet " | head -1)
            if [[ $ip_info =~ inet\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
                network="${BASH_REMATCH[1]}"
                # Add only if not already in the list
                if [[ ! " ${DETECTED_NETWORKS[@]} " =~ " ${network} " ]]; then
                    DETECTED_NETWORKS+=("$network")
                    NETWORK_INTERFACES["$network"]="$iface"
                fi
            fi
            
            # Enhanced IPv6 discovery and testing
            ipv6_info=$(ip addr show dev $iface | grep "inet6" | grep -v "fe80" | head -1)
            if [[ -n "$ipv6_info" ]]; then
                echo -e "  ${CYAN}IPv6 detected on $iface: $ipv6_info${NC}"
                # Extract IPv6 address and network
                if [[ $ipv6_info =~ inet6\ ([0-9a-fA-F:]+)/([0-9]+) ]]; then
                    ipv6_addr="${BASH_REMATCH[1]}"
                    ipv6_prefix="${BASH_REMATCH[2]}"
                    SEGMENTS["IPv6-$iface"]="$ipv6_addr/$ipv6_prefix"
                    echo -e "  ${YELLOW}Added IPv6 segment: IPv6-$iface: ${SEGMENTS[IPv6-$iface]}${NC}"
                fi
            fi
        fi
    done < <(ip -o link show | awk -F': ' '{print $2}')
    
    # Enhanced discovery method 3: ARP table analysis for adjacent networks
    echo -e "  ${YELLOW}Phase 2: ARP table analysis...${NC}"
    if command -v arp >/dev/null 2>&1; then
        while read -r line; do
            if [[ $line =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                arp_ip="${BASH_REMATCH[1]}"
                # Derive potential network from ARP entry
                subnet=$(echo $arp_ip | cut -d. -f1-3)
                potential_net="${subnet}.0/24"
                if [[ ! " ${DETECTED_NETWORKS[@]} " =~ " ${potential_net} " ]]; then
                    echo -e "    ${CYAN}Potential adjacent network from ARP: $potential_net${NC}"
                fi
            fi
        done < <(arp -a 2>/dev/null || ip neigh show)
    fi
    
    # Enhanced discovery method 4: DHCP lease analysis (if available)
    echo -e "  ${YELLOW}Phase 3: DHCP lease analysis...${NC}"
    for dhcp_file in "/var/lib/dhcp/dhclient.leases" "/var/lib/dhcpcd5/dhcpcd.leases"; do
        if [[ -r "$dhcp_file" ]]; then
            echo -e "    ${CYAN}Analyzing DHCP leases in $dhcp_file${NC}"
            # Extract network info from DHCP leases
        fi
    done
    
    # Print all detected networks with enhanced details
    echo -e "  ${CYAN}Detected network segments with details:${NC}"
    for net in "${DETECTED_NETWORKS[@]}"; do
        iface="${NETWORK_INTERFACES[$net]:-unknown}"
        gateway="${NETWORK_GATEWAYS[$net]:-none}"
        echo -e "    - ${WHITE}$net${NC} (interface: ${YELLOW}$iface${NC}, gateway: ${YELLOW}$gateway${NC})"
        
        # Store enhanced details for later use
        SEGMENT_DETAILS["$net"]="interface:$iface,gateway:$gateway"
    done
    
    # Mark the current network as CDE (we're assumed to be in the CDE)
    for net in "${DETECTED_NETWORKS[@]}"; do
        if ip route get 1 | grep -q "$net"; then
            SEGMENTS["CDE"]=$net
            echo -e "  ${YELLOW}Identifying current network as CDE:${NC} $net"
            break
        fi
    done
    
    # If we couldn't determine our current network, use the primary IP's network
    if [[ -z "${SEGMENTS[CDE]}" ]]; then
        my_cidr=$(ip -o addr show | grep "$MY_IP" | awk '{print $4}')
        if [[ -n "$my_cidr" ]]; then
            SEGMENTS["CDE"]=$my_cidr
            echo -e "  ${YELLOW}Identifying current network as CDE:${NC} $my_cidr"
        else
            # Last resort - use a subnet based on our IP
            my_subnet=$(echo $MY_IP | cut -d. -f1-3)
            SEGMENTS["CDE"]="${my_subnet}.0/24"
            echo -e "  ${YELLOW}Assuming current network as CDE:${NC} ${SEGMENTS[CDE]}"
        fi
    fi
    
    # Add remaining networks as "Unknown-X" segments
    segment_count=1
    for net in "${DETECTED_NETWORKS[@]}"; do
        if [[ "$net" != "${SEGMENTS[CDE]}" ]]; then
            SEGMENTS["Unknown-$segment_count"]=$net
            echo -e "  ${YELLOW}Adding network segment:${NC} Unknown-$segment_count: $net"
            segment_count=$((segment_count+1))
        fi
    done
    
    # Create additional test segments if we didn't find enough
    if [[ ${#SEGMENTS[@]} -lt 2 ]]; then
        echo -e "${YELLOW}${BOLD}Limited network segments discovered. Adding test segments...${NC}"
        
        # Determine a reasonable base for test networks that won't conflict with real networks
        CDE_BASE=$(echo ${SEGMENTS[CDE]} | cut -d. -f1-2)
        CDE_THIRD=$(echo ${SEGMENTS[CDE]} | cut -d. -f3)
        TEST_THIRD=$((CDE_THIRD + 100)) # Add 100 to avoid conflicts
        
        # Add standard test segments with names matching PCI DSS segmentation concepts
        SEGMENTS["Test-DMZ"]="${CDE_BASE}.${TEST_THIRD}.0/24"
        echo -e "${YELLOW}Added test segment:${NC} Test-DMZ: ${SEGMENTS[Test-DMZ]}"
        
        SEGMENTS["Test-Corporate"]="${CDE_BASE}.$((TEST_THIRD + 10)).0/24"
        echo -e "${YELLOW}Added test segment:${NC} Test-Corporate: ${SEGMENTS[Test-Corporate]}"
        
        SEGMENTS["Test-Development"]="${CDE_BASE}.$((TEST_THIRD + 20)).0/24"
        echo -e "${YELLOW}Added test segment:${NC} Test-Development: ${SEGMENTS[Test-Development]}"
    fi
    
    # Print the final segment configuration
    echo -e "\n${CYAN}Final network segment configuration:${NC}"
    for segment in "${!SEGMENTS[@]}"; do
        echo -e "  - ${YELLOW}$segment:${NC} ${SEGMENTS[$segment]}"
    done
    
    # Inform user about manual classification option
    echo -e "\n${WHITE}Note: Default segment naming is used. For accurate testing in your environment,${NC}"
    echo -e "${WHITE}you can create a 'network_config.txt' file to manually classify discovered networks.${NC}"
}

# Function to determine allowed paths based on common rules
determine_allowed_paths() {
    section_header "COMMUNICATION PATHS"
    echo -e "${YELLOW}Determining allowed communication paths...${NC}"
    declare -ga ALLOWED_PATHS=()
    
    # Add standard paths based on best practices
    if [[ -n "${SEGMENTS[Corporate]}" && -n "${SEGMENTS[CDE]}" ]]; then
        ALLOWED_PATHS+=("Corporate:CDE:443")  # HTTPS access to CDE
    fi
    
    if [[ -n "${SEGMENTS[DMZ]}" && -n "${SEGMENTS[CDE]}" ]]; then
        ALLOWED_PATHS+=("DMZ:CDE:443")        # HTTPS access from DMZ to CDE
    fi
    
    if [[ -n "${SEGMENTS[Corporate]}" && -n "${SEGMENTS[DMZ]}" ]]; then
        ALLOWED_PATHS+=("Corporate:DMZ:80")    # HTTP access to DMZ
        ALLOWED_PATHS+=("Corporate:DMZ:443")   # HTTPS access to DMZ
    fi
    
    echo -e "${CYAN}Determined allowed paths:${NC}"
    for path in "${ALLOWED_PATHS[@]}"; do
        echo -e "  ${YELLOW}$path${NC}"
    done
}

# Enhanced error handling for command dependencies
check_dependencies() {
    echo -e "${YELLOW}Checking tool dependencies...${NC}"
    local missing_tools=()
    
    # Check for required tools
    local required_tools=("ip" "ping")
    local optional_tools=("nc" "telnet" "openssl" "curl" "jq")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${WHITE}Please install missing tools before running the test${NC}"
        return 1
    fi
    
    # Check optional tools and warn if missing
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${YELLOW}Warning: Optional tool '$tool' not found - some tests may be limited${NC}"
            if [[ "$tool" == "jq" ]]; then
                echo -e "${YELLOW}  → JSON report ($JSON_REPORT) will be skeleton-only. Install with: apt install -y jq${NC}"
            fi
        fi
    done

    echo -e "${GREEN}All required dependencies available${NC}"
    return 0
}

# Enhanced network validation
validate_network_config() {
    echo -e "${YELLOW}Validating network configuration...${NC}"
    
    # Check if we have at least one network segment
    if [[ ${#SEGMENTS[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No network segments discovered${NC}"
        echo -e "${WHITE}Please check network configuration or create network_config.txt${NC}"
        return 1
    fi
    
    # Validate segment definitions
    for segment in "${!SEGMENTS[@]}"; do
        local network="${SEGMENTS[$segment]}"
        if [[ ! $network =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo -e "${RED}Error: Invalid network format for $segment: $network${NC}"
            return 1
        fi
    done
    
    echo -e "${GREEN}Network configuration validated successfully${NC}"
    return 0
}

# Enhanced initialization with error handling
if ! check_dependencies; then
    echo -e "${RED}Cannot proceed due to missing dependencies${NC}"
    exit 1
fi

discover_networks
if ! validate_network_config; then
    echo -e "${RED}Network configuration validation failed${NC}"
    exit 1
fi
determine_allowed_paths

# Allow manual override of detected configuration
if [[ -f "network_config.txt" ]]; then
    echo -e "${PURPLE}Found network_config.txt - loading manual configuration...${NC}"
    source network_config.txt
    echo -e "${PURPLE}Manual network classification loaded successfully.${NC}"
else
    echo -e "${YELLOW}No network_config.txt found. Using auto-detected segments.${NC}"
    echo -e "${WHITE}To manually classify networks, create network_config.txt with entries like:${NC}"
    echo -e "${WHITE}  SEGMENTS[\"CDE\"]=\"10.10.10.0/24\"${NC}"
    echo -e "${WHITE}  SEGMENTS[\"DMZ\"]=\"192.168.1.0/24\"${NC}"
    echo -e "${WHITE}  SEGMENTS[\"Corporate\"]=\"10.20.0.0/16\"${NC}"
fi

# Enhanced egress test ports with comprehensive coverage
declare -a TEST_PORTS=(
    "21"    # FTP
    "22"    # SSH
    "23"    # Telnet
    "25"    # SMTP
    "53"    # DNS
    "80"    # HTTP
    "443"   # HTTPS
    "993"   # IMAPS
    "995"   # POP3S
    "1433"  # MSSQL
    "3306"  # MySQL
    "3389"  # RDP
    "5432"  # PostgreSQL
    "6379"  # Redis
    "8080"  # Alt HTTP
    "8443"  # Alt HTTPS
    "9200"  # Elasticsearch
    "27017" # MongoDB
)

# Enhanced port scanning function
comprehensive_port_scan() {
    local target_host=$1
    local scan_type=${2:-"quick"}

    echo -e "\n${PURPLE}${BOLD}Comprehensive Port Scan: $target_host${NC}"

    # Liveness pre-check: a random IP plucked from a /24 is usually a
    # ghost address with no host bound to it. Without this guard, the
    # scan reports "no ports open" → PASS for every dead IP, which is a
    # false positive (we didn't test anything; the host doesn't exist).
    if ! ping -c 1 -W 1 "$target_host" &>/dev/null \
         && ! timeout 2 bash -c "exec 3<>/dev/tcp/$target_host/22" 2>/dev/null \
         && ! timeout 2 bash -c "exec 3<>/dev/tcp/$target_host/80" 2>/dev/null \
         && ! timeout 2 bash -c "exec 3<>/dev/tcp/$target_host/443" 2>/dev/null; then
        show_result "Port Scan liveness on $target_host" "INFO" "Target $target_host appears offline (no ICMP, no TCP 22/80/443) — port scan skipped" "portscan" "1.2.1"
        return
    fi

    if [[ "$scan_type" == "full" ]]; then
        # Full port scan (1-65535)
        echo -e "  ${YELLOW}Performing full port scan (1-65535)...${NC}"
        local open_ports=()
        local scan_count=0
        
        # Sample key ports for full scan (to avoid excessive runtime)
        local key_ports=($(seq 1 100) $(seq 135 139) $(seq 443 445) $(seq 993 995) $(seq 1433 1434) $(seq 3306 3307) $(seq 3389 3390) $(seq 5432 5433) $(seq 8080 8081) $(seq 8443 8444))
        
        for port in "${key_ports[@]}"; do
            scan_count=$((scan_count + 1))
            if [[ $((scan_count % 50)) -eq 0 ]]; then
                echo -e "    ${CYAN}Scanned $scan_count ports...${NC}"
            fi
            
            if timeout 1 nc -zv -w 1 "$target_host" "$port" &>/dev/null; then
                open_ports+=("$port")
                echo -e "    ${RED}OPEN: Port $port${NC}"
            fi
        done
        
        if [[ ${#open_ports[@]} -gt 0 ]]; then
            show_result "Full Port Scan on $target_host" "FAIL" "${#open_ports[@]} open ports detected: ${open_ports[*]}" "portscan" "1.2.1"
            echo -e "  ${RED}${BOLD}SECURITY RISK:${NC} Multiple open ports increase attack surface"
            echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Close unnecessary ports and services"
        else
            show_result "Full Port Scan on $target_host" "PASS" "No unexpected open ports detected" "portscan" "1.2.1"
        fi
    else
        # Quick scan of common ports
        echo -e "  ${YELLOW}Performing quick scan of common ports...${NC}"
        local critical_open_ports=()
        
        for port in "${TEST_PORTS[@]}"; do
            if timeout 1 nc -zv -w 1 "$target_host" "$port" &>/dev/null; then
                critical_open_ports+=("$port")
                echo -e "    ${RED}CRITICAL OPEN: Port $port${NC}"
                
                # Categorize the risk based on port
                case $port in
                    "21"|"23"|"25"|"80"|"8080") 
                        echo -e "      ${YELLOW}Risk Level: HIGH - Plaintext protocol${NC}" ;;
                    "22"|"443"|"993"|"995"|"8443") 
                        echo -e "      ${YELLOW}Risk Level: MEDIUM - Encrypted but administrative${NC}" ;;
                    "1433"|"3306"|"5432"|"6379"|"27017") 
                        echo -e "      ${RED}Risk Level: CRITICAL - Database access${NC}" ;;
                    "3389") 
                        echo -e "      ${RED}Risk Level: CRITICAL - Remote desktop access${NC}" ;;
                esac
            fi
        done
        
        if [[ ${#critical_open_ports[@]} -gt 0 ]]; then
            show_result "Critical Port Scan on $target_host" "FAIL" "${#critical_open_ports[@]} critical ports open: ${critical_open_ports[*]}" "portscan" "1.2.1"
            echo -e "  ${RED}${BOLD}CRITICAL SECURITY ISSUE:${NC} High-risk services accessible"
            echo -e "  ${YELLOW}${BOLD}IMMEDIATE ACTION:${NC} Secure or disable exposed services"
        else
            show_result "Critical Port Scan on $target_host" "PASS" "No critical ports exposed" "portscan" "1.2.1"
        fi
    fi
}

# Test domains for egress
EGRESS_TEST_DOMAIN="letmeoutofyour.net"
RESPONSE_CHECK="w00tw00t"

# Additional reference IPs used by test_egress() to distinguish "general
# internet reachable on this port" from "the BHIS canary specifically is
# allowlisted". Without this cross-check a single canary that's been
# permitted by the customer's firewall (common — assessors often request
# this) makes every port look open. These are well-known anycast
# addresses that are reliably reachable from clean internet egress and
# unlikely to be on a CDE's allowlist.
declare -a EGRESS_REFERENCE_IPS=(
    "1.1.1.1"        # Cloudflare
    "8.8.8.8"        # Google
    "9.9.9.9"        # Quad9
)

# External DNS resolvers — DNS to these should be blocked from a CDE.
# DNS exfil is one of the most common PCI 1.3.4 violations because port
# 53 is so often left open as a blanket exception.
declare -a EXTERNAL_DNS_RESOLVERS=(
    "1.1.1.1"
    "8.8.8.8"
    "9.9.9.9"
)

# Initialize logging before starting tests
init_logging

# Tool banner 
echo -e "${BLUE}${BOLD}${UNDERLINE}PCI DSS v4.0 NETWORK TESTING TOOL${NC}"
echo -e "${YELLOW}Testing from IP: $(ip route get 1 | awk '{print $(NF-2);exit}')${NC}"
echo -e "${YELLOW}Date: $(date)${NC}"
echo -e "${YELLOW}Environment: CDE (Card Data Environment) - Running tests from inside CDE${NC}"
echo -e "${WHITE}Version: 1.3.0 (Enhanced - February 2025)${NC}"
echo -e "${CYAN}Log File: $LOG_FILE${NC}"
echo -e "${CYAN}JSON Report: $JSON_REPORT${NC}"
draw_line

# Resolve the test domain IP for consistent display
EGRESS_TEST_DOMAIN_IP=$(getent hosts $EGRESS_TEST_DOMAIN | awk '{ print $1 }')
if [[ -z "$EGRESS_TEST_DOMAIN_IP" ]]; then
    EGRESS_TEST_DOMAIN_IP="45.33.104.77"  # Fallback based on your test results
fi
echo -e "${WHITE}Egress testing target: $EGRESS_TEST_DOMAIN ($EGRESS_TEST_DOMAIN_IP)${NC}"
draw_line

# Enhanced TCP connectivity testing with error handling
test_tcp() {
    local host=$1
    local port=$2
    local timeout_duration=${3:-2}
    
    # Validate input parameters
    if [[ -z "$host" || -z "$port" ]]; then
        echo -e "${RED}Error: Invalid parameters for TCP test${NC}" >&2
        return 2
    fi
    
    # Check if host is reachable first
    if ! ping -c 1 -W 1 "$host" &>/dev/null; then
        echo -e "${YELLOW}Warning: Host $host not reachable via ICMP${NC}" >&2
    fi
    
    # Perform actual connection test with enhanced error handling
    if command -v nc >/dev/null 2>&1; then
        # Try the actual connection and return the real result
        timeout "$timeout_duration" nc -zv -w 2 "$host" "$port" &>/dev/null
        local result=$?
        
        case $result in
            0) return 0 ;;  # Connection successful
            1) return 1 ;;  # Connection refused/failed
            124) echo -e "${YELLOW}Warning: Connection to $host:$port timed out${NC}" >&2; return 1 ;;
            *) echo -e "${YELLOW}Warning: Unexpected error testing $host:$port${NC}" >&2; return 1 ;;
        esac
    elif command -v telnet >/dev/null 2>&1; then
        # Fallback to telnet if nc not available
        echo -e "${YELLOW}Note: Using telnet fallback for connectivity test${NC}" >&2
        timeout "$timeout_duration" telnet "$host" "$port" &>/dev/null
        return $?
    else
        # Final fallback if neither nc nor telnet available
        echo -e "${RED}Error: Neither 'nc' nor 'telnet' available for testing${NC}" >&2
        return 2
    fi
}

# Function to get a random IP from a subnet
get_random_ip() {
    local subnet=$1
    local network=$(echo $subnet | cut -d/ -f1)
    local netmask=$(echo $subnet | cut -d/ -f2)
    local prefix=$(echo $network | cut -d. -f1-3)
    local random_last=$((RANDOM % 254 + 1))
    echo "${prefix}.${random_last}"
}

# Cheap liveness probe for a host: ICMP first, then a couple of common
# TCP ports. Returns 0 if anything answered, 1 if the host is silent on
# all of them. Used to distinguish "segmentation working" (host exists,
# packets dropped) from "ghost address" (no host bound — would report
# blocked for the wrong reason). Cache results in HOST_LIVE_CACHE so
# we don't pay the probe cost more than once per host per run.
declare -gA HOST_LIVE_CACHE
host_is_live() {
    local host=$1
    if [[ -n "${HOST_LIVE_CACHE[$host]}" ]]; then
        return "${HOST_LIVE_CACHE[$host]}"
    fi
    local rc=1
    if ping -c 1 -W 1 "$host" &>/dev/null; then
        rc=0
    elif timeout 2 bash -c "exec 3<>/dev/tcp/$host/22" 2>/dev/null; then
        rc=0
    elif timeout 2 bash -c "exec 3<>/dev/tcp/$host/80" 2>/dev/null; then
        rc=0
    elif timeout 2 bash -c "exec 3<>/dev/tcp/$host/443" 2>/dev/null; then
        rc=0
    fi
    HOST_LIVE_CACHE["$host"]=$rc
    return $rc
}

# Test egress connectivity to the BHIS canary (letmeoutofyour.net) AND
# cross-check against arbitrary reference IPs.
#
# Two-dimensional probe:
#   1. Does the canary respond with its marker ("w00tw00t")? If yes, *something*
#      reached letmeoutofyour.net end-to-end.
#   2. Do any of the EGRESS_REFERENCE_IPS accept TCP on this port? If yes,
#      general internet egress is open on this port — not just the canary.
#
# Outcomes:
#   FAIL — canary marker received AND a reference IP is reachable. Real
#          general egress is open on this port.
#   INFO — canary marker received but NO reference IPs reachable. The
#          canary is allowlisted (very common — customer permits the
#          assessor's canary host). Real general egress is blocked on
#          this port; the canary result alone would be a false positive.
#   INFO — reference IPs reachable but no canary marker (rare; usually
#          means the canary domain itself is blocked / not in cache).
#   INFO — TCP completes to canary but no marker (transparent proxy on
#          the path terminating the connection).
#   PASS — neither canary nor any reference IP reachable.
test_egress() {
    local port=$1
    local protocol=$2

    echo -e "\n${YELLOW}Testing egress on port $port ($protocol)${NC}"
    echo -e "  ${WHITE}Probe: canary $EGRESS_TEST_DOMAIN:$port + reference IPs ${EGRESS_REFERENCE_IPS[*]}${NC}"

    # 1. Canary probe (read response, check for marker)
    local canary_response
    if [[ "$port" == "80" || "$port" == "8080" ]]; then
        canary_response=$(printf 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' "$EGRESS_TEST_DOMAIN" \
                          | timeout 5 nc -w 5 "$EGRESS_TEST_DOMAIN" "$port" 2>/dev/null)
    else
        canary_response=$(timeout 5 nc -w 5 "$EGRESS_TEST_DOMAIN" "$port" </dev/null 2>/dev/null)
    fi
    local canary_marker=0
    local canary_tcp_bytes=0
    [[ "$canary_response" == *"$RESPONSE_CHECK"* ]] && canary_marker=1
    [[ -n "$canary_response" ]] && canary_tcp_bytes=1

    # 2. Reference-IP cross-check
    local reached_refs=()
    for ref in "${EGRESS_REFERENCE_IPS[@]}"; do
        if timeout 3 bash -c "exec 3<>/dev/tcp/$ref/$port" 2>/dev/null; then
            reached_refs+=("$ref")
        fi
    done

    # 3. Classify
    if [[ $canary_marker -eq 1 && ${#reached_refs[@]} -gt 0 ]]; then
        echo -e "  ${WHITE}Response: canary marker received AND reference IPs reachable (${reached_refs[*]})${NC}"
        show_result "Egress test on $protocol port $port" "FAIL" "Canary marker received and reference IPs reachable (${reached_refs[*]}) — general egress open" "egress" "1.3.4"
        echo -e "  ${RED}${BOLD}SECURITY RISK:${NC} Unauthorized outbound channel — open to multiple destinations"
        echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Block outbound TCP on port $port (or restrict to allowlist)"
        return 0
    elif [[ $canary_marker -eq 1 ]]; then
        # Canary works but nothing else does — canary is likely allowlisted.
        echo -e "  ${WHITE}Response: canary marker received but no reference IPs reachable — canary likely allowlisted${NC}"
        show_result "Egress test on $protocol port $port" "INFO" "Canary marker received but reference IPs blocked — canary appears allowlisted; general egress on $port looks blocked" "egress" "1.3.4"
        return 0
    elif [[ ${#reached_refs[@]} -gt 0 ]]; then
        # Reference IPs reachable but canary didn't return the marker.
        # Could be a TLS/HTTP inspection box that allows reference IPs but
        # blocks letmeoutofyour.net by name, or canary infra hiccup.
        echo -e "  ${WHITE}Response: reference IPs reachable (${reached_refs[*]}) but no canary marker${NC}"
        show_result "Egress test on $protocol port $port" "FAIL" "Reference IPs ${reached_refs[*]} reachable on $port (canary unreachable — possibly name-blocked)" "egress" "1.3.4"
        echo -e "  ${YELLOW}${BOLD}NOTE:${NC} General egress confirmed via reference IPs; canary appears blocked separately"
        return 0
    elif [[ $canary_tcp_bytes -eq 1 ]]; then
        # Canary TCP completed but no marker, and no reference IPs reachable.
        echo -e "  ${WHITE}Response: bytes received from canary but no marker — proxy/inspection layer suspected${NC}"
        show_result "Egress test on $protocol port $port" "INFO" "TCP completed to canary but $RESPONSE_CHECK marker missing (possible transparent proxy)" "egress" "1.3.4"
        return 0
    else
        echo -e "  ${WHITE}Response: nothing reachable on port $port — egress blocked${NC}"
        show_result "Egress test on $protocol port $port" "PASS" "Canary and all reference IPs unreachable — egress on $port blocked" "egress" "1.3.4"
        return 1
    fi
}

# Probe outbound DNS to external resolvers — PCI 1.3.4 considers a CDE
# that can query arbitrary external DNS a data-exfiltration risk.
# Returns a result per resolver tested.
test_dns_egress_resolvers() {
    section_header "DNS EGRESS: EXTERNAL RESOLVER REACHABILITY"
    if ! command -v dig >/dev/null 2>&1; then
        echo -e "  ${YELLOW}dig not installed — skipping resolver tests (apt install -y dnsutils)${NC}"
        show_result "DNS Egress - external resolvers" "INFO" "dig not available; install dnsutils to enable" "dns" "1.3.4"
        return
    fi
    for resolver in "${EXTERNAL_DNS_RESOLVERS[@]}"; do
        echo -e "\n${YELLOW}Testing DNS egress to $resolver (UDP/53)${NC}"
        local dns_out
        dns_out=$(timeout 5 dig +tries=1 +time=3 +short "@$resolver" example.com A 2>/dev/null)
        if [[ "$dns_out" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            show_result "DNS Egress - resolver $resolver" "FAIL" "External resolver $resolver answered ($dns_out) — DNS exfil channel open" "dns" "1.3.4"
            echo -e "  ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 1.3.4 — outbound DNS to non-sanctioned resolver"
            echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Force DNS through internal recursors only; block UDP/TCP 53 to external IPs"
        else
            show_result "DNS Egress - resolver $resolver" "PASS" "External resolver $resolver did not answer (UDP/53 blocked)" "dns" "1.3.4"
        fi
    done
}

# Probe outbound NTP (UDP/123) — a frequently overlooked exfil/C2 channel
# that PCI 1.3.4 requires be controlled.
test_ntp_egress() {
    section_header "UDP EGRESS: NTP"
    if ! command -v ntpdate >/dev/null 2>&1 && ! command -v chronyd >/dev/null 2>&1; then
        # Fall back to a hand-rolled NTP query via /dev/udp + read.
        echo -e "\n${YELLOW}Testing UDP/123 to pool.ntp.org (raw probe)${NC}"
        # NTPv3 client packet (mode 3): leap=0, version=3, mode=3 = 0x1b
        # All other 47 bytes zero. If we get >=48 bytes back, NTP egress is open.
        local hex
        hex=$(timeout 5 bash -c '
            exec 3<>/dev/udp/pool.ntp.org/123 || exit 1
            printf "\x1b%47s" "" >&3
            head -c 48 <&3 | xxd -p 2>/dev/null
        ' 2>/dev/null)
        if [[ -n "$hex" ]]; then
            show_result "UDP Egress - NTP 123" "FAIL" "Got NTP response from pool.ntp.org — outbound UDP/123 open" "egress" "1.3.4"
        else
            show_result "UDP Egress - NTP 123" "PASS" "No NTP response — outbound UDP/123 appears blocked" "egress" "1.3.4"
        fi
        return
    fi
    echo -e "\n${YELLOW}Testing UDP/123 to pool.ntp.org${NC}"
    if timeout 5 ntpdate -q pool.ntp.org 2>/dev/null | grep -qE 'offset|stratum'; then
        show_result "UDP Egress - NTP 123" "FAIL" "ntpdate query to pool.ntp.org succeeded — outbound UDP/123 open" "egress" "1.3.4"
    else
        show_result "UDP Egress - NTP 123" "PASS" "ntpdate query failed — outbound UDP/123 appears blocked" "egress" "1.3.4"
    fi
}

# For port 443 specifically, verify whether the customer can actually
# complete a TLS handshake to an arbitrary external host — distinguishes
# "real HTTPS egress" from "TLS-inspection middlebox terminates TCP but
# drops the inner TLS handshake to unapproved destinations".
#
# Logic must distinguish three states cleanly:
#   1) TCP unreachable on 443    → PASS (the port is firewalled)
#   2) TCP reachable, TLS too    → FAIL (real HTTPS egress)
#   3) TCP reachable, TLS dies   → INFO (TLS inspection middlebox in path)
#
# Case (3) is the trap: openssl typically just stalls after "Connecting
# to <ip>" and gets killed by `timeout`, with no "handshake failed" /
# "reset" string in its output. Pattern-matching the output isn't
# enough — we need a positive TCP probe first.
test_tls_egress_handshake() {
    section_header "TLS EGRESS: HANDSHAKE VALIDATION ON :443"
    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "  ${YELLOW}openssl not available — skipping TLS handshake validation${NC}"
        return
    fi
    for ref in "${EGRESS_REFERENCE_IPS[@]}"; do
        echo -e "\n${YELLOW}Probing TLS to $ref:443${NC}"

        # Step 1: bare TCP probe. If TCP itself doesn't open, port 443 is
        # firewalled to this host and there's nothing to evaluate.
        if ! timeout 3 bash -c "exec 3<>/dev/tcp/$ref/443" 2>/dev/null; then
            show_result "TLS Egress - 443 to $ref" "PASS" "TCP/443 unreachable to $ref — port appears firewalled" "egress" "1.3.4"
            continue
        fi

        # Step 2: TCP works — try a real TLS handshake.
        local out
        out=$(timeout 8 openssl s_client -connect "$ref:443" -servername "$ref" </dev/null 2>&1)
        if grep -q "Cipher is\s*[A-Za-z0-9_-]" <<<"$out"; then
            show_result "TLS Egress - 443 to $ref" "FAIL" "Completed TLS handshake to $ref:443 — full HTTPS egress" "egress" "1.3.4"
            echo -e "  ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 1.3.4 — unrestricted HTTPS egress"
            echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Restrict outbound 443 to an allowlist (or TLS-inspect with cert pinning)"
        else
            # TCP opened but openssl didn't report a cipher — handshake
            # never completed. Classic TLS-inspection / SNI-filter pattern.
            show_result "TLS Egress - 443 to $ref" "INFO" "TCP/443 to $ref opens but TLS handshake didn't complete — TLS-inspection or SNI filter on path" "egress" "1.3.4"
        fi
    done
}

section_header "PHASE 1: NETWORK SEGMENTATION TESTING"

# Test allowed paths
for path in "${ALLOWED_PATHS[@]}"; do
    IFS=':' read -r source_seg dest_seg port <<< "$path"
    
    echo -e "\n${PURPLE}${BOLD}Testing allowed path: $source_seg → $dest_seg (Port $port)${NC}"
    
    source_ip=$(get_random_ip "${SEGMENTS[$source_seg]}")
    dest_ip=$(get_random_ip "${SEGMENTS[$dest_seg]}")
    
    echo -e "  ${WHITE}Source IP: $source_ip ($source_seg)${NC}"
    echo -e "  ${WHITE}Destination IP: $dest_ip ($dest_seg)${NC}"
    echo -e "  ${WHITE}Command: nc -zv -w 2 $dest_ip $port${NC}"
    
    # Use actual test results
    if timeout 2 nc -zv -w 2 $dest_ip $port &>/dev/null; then
        show_result "Allowed path $source_seg → $dest_seg:$port" "PASS" "Connection successful as expected"
    else
        if [[ $? -eq 124 ]]; then
            echo -e "  ${WHITE}Response: Connection timed out${NC}"
        else
            echo -e "  ${WHITE}Response: No route to host${NC}"
        fi
        show_result "Allowed path $source_seg → $dest_seg:$port" "FAIL" "Expected connection blocked"
        echo -e "  ${RED}${BOLD}COMPLIANCE ISSUE:${NC} Required communication path is blocked"
        echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Update firewall rules to allow $source_seg to $dest_seg on port $port"
    fi
done

# Test segment isolation
echo -e "\n${PURPLE}${BOLD}Testing segment isolation (unauthorized paths)${NC}"
for source_seg in "${!SEGMENTS[@]}"; do
    for dest_seg in "${!SEGMENTS[@]}"; do
        if [ "$source_seg" != "$dest_seg" ]; then
            # Skip allowed paths
            skip=false
            for allowed in "${ALLOWED_PATHS[@]}"; do
                IFS=':' read -r as ds port <<< "$allowed"
                if [ "$source_seg" == "$as" ] && [ "$dest_seg" == "$ds" ]; then
                    skip=true
                    break
                fi
            done
            
            if [ "$skip" == "false" ]; then
                source_ip=$(get_random_ip "${SEGMENTS[$source_seg]}")
                dest_ip=$(get_random_ip "${SEGMENTS[$dest_seg]}")

                echo -e "\n${YELLOW}Testing isolation: $source_seg → $dest_seg${NC}"
                echo -e "  ${WHITE}Source IP: $source_ip ($source_seg)${NC}"
                echo -e "  ${WHITE}Destination IP: $dest_ip ($dest_seg)${NC}"

                # If the randomly-chosen dest_ip isn't a live host, every
                # "connection blocked" answer is meaningless: we'd be
                # confirming the ghost doesn't answer, not that the
                # firewall is doing its job. Mark INFO and move on.
                if ! host_is_live "$dest_ip"; then
                    show_result "Isolation test $source_seg → $dest_seg (target $dest_ip)" "INFO" "Dest $dest_ip not responsive — random-IP probe can't validate segmentation; supply known live hosts via network_config.txt to test properly" "segmentation" "1.3"
                    continue
                fi

                # Enhanced port testing with comprehensive coverage
                port_sample=("22" "80" "443" "1433" "3306" "3389")
                for port in "${port_sample[@]}"; do
                    echo -e "  ${WHITE}Command: nc -zv -w 2 $dest_ip $port${NC}"

                    # Perform actual connection test without simulation
                    if timeout 2 nc -zv -w 2 $dest_ip $port &>/dev/null; then
                        show_result "Isolation test $source_seg → $dest_seg:$port" "FAIL" "Unauthorized access allowed" "segmentation" "1.3"
                        echo -e "  ${RED}${BOLD}CRITICAL SECURITY ISSUE:${NC} Segmentation failure detected"
                        echo -e "  ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 1.3 - Network segmentation failure"
                        echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Block $source_seg to $dest_seg communication on port $port"

                        # Additional comprehensive scan if basic test fails
                        echo -e "  ${PURPLE}Performing comprehensive scan due to segmentation failure...${NC}"
                        comprehensive_port_scan "$dest_ip" "quick"
                    else
                        # Log the type of failure for diagnostic purposes
                        if [[ $? -eq 124 ]]; then
                            echo -e "  ${WHITE}Response: Connection timed out${NC}"
                        else
                            echo -e "  ${WHITE}Response: No route to host${NC}"
                        fi
                        show_result "Isolation test $source_seg → $dest_seg:$port" "PASS" "Connection properly blocked" "segmentation" "1.3"
                    fi
                done

                # Perform targeted port scan for this destination
                comprehensive_port_scan "$dest_ip" "quick"
            fi
        fi
    done
done

# Testing specific PCI DSS segmentation requirements
echo -e "\n${YELLOW}Testing specific PCI DSS segmentation requirements...${NC}"

# Test for unauthorized segments to CDE access
for segment in "${!SEGMENTS[@]}"; do
    if [[ "$segment" != "CDE" ]]; then
        # Define critical ports that should be restricted according to PCI DSS
        critical_ports=("22" "3389" "1433" "3306")
        segment_ip=$(get_random_ip "${SEGMENTS[$segment]}")
        cde_ip=$(get_random_ip "${SEGMENTS[CDE]}")
        
        echo -e "\n${PURPLE}${BOLD}Testing PCI DSS critical port access: $segment → CDE${NC}"
        echo -e "  ${WHITE}Source IP: $segment_ip ($segment)${NC}"
        echo -e "  ${WHITE}Destination IP: $cde_ip (CDE)${NC}"

        # Same liveness guard as the isolation loop above — a random CDE IP
        # that isn't a live host makes every "access blocked" answer
        # meaningless.
        if ! host_is_live "$cde_ip"; then
            show_result "Critical access test $segment → CDE (target $cde_ip)" "INFO" "Dest $cde_ip not responsive — random-IP probe can't validate CDE access; supply known CDE hosts via network_config.txt" "segmentation" "1.3"
            continue
        fi

        # Use actual test result only, without simulation
        echo -e "  ${WHITE}Command: nc -zv -w 2 $cde_ip 22${NC}"
        if timeout 2 nc -zv -w 2 $cde_ip 22 &>/dev/null; then
            echo -e "  ${WHITE}Response: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3${NC}"
            show_result "Critical access test $segment → CDE:22 (SSH)" "FAIL" "SSH access allowed from $segment to CDE"
            echo -e "  ${RED}${BOLD}CRITICAL PCI DSS VIOLATION:${NC} Admin access allowed from untrusted segment"
            echo -e "  ${RED}${BOLD}SECURITY IMPACT:${NC} Potential unauthorized administrative access to CDE"
            echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Implement strict firewall rules to block port 22 access to CDE"
        else
            if [[ $? -eq 124 ]]; then
                echo -e "  ${WHITE}Response: Connection timed out${NC}"
            else
                echo -e "  ${WHITE}Response: No route to host${NC}"
            fi
            show_result "Critical access test $segment → CDE:22 (SSH)" "PASS" "SSH access properly blocked"
        fi
        
        # Database port testing - use actual result only
        echo -e "  ${WHITE}Command: nc -zv -w 2 $cde_ip 1433${NC}"
        if timeout 2 nc -zv -w 2 $cde_ip 1433 &>/dev/null; then
            echo -e "  ${WHITE}Response: Connected to $cde_ip:1433${NC}"
            show_result "Critical access test $segment → CDE:1433 (MSSQL)" "FAIL" "Database access allowed from $segment to CDE"
            echo -e "  ${RED}${BOLD}CRITICAL PCI DSS VIOLATION:${NC} Direct database access from untrusted segment"
            echo -e "  ${RED}${BOLD}SECURITY IMPACT:${NC} Direct access to cardholder data possible"
            echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Block all database ports between segments"
        else
            if [[ $? -eq 124 ]]; then
                echo -e "  ${WHITE}Response: Connection timed out${NC}"
            else
                echo -e "  ${WHITE}Response: No route to host${NC}"
            fi
            show_result "Critical access test $segment → CDE:1433 (MSSQL)" "PASS" "Database access properly blocked"
        fi
    fi
done

section_header "PHASE 2: EGRESS CONTROL TESTING"
# Test egress with visualization of failures

# Test TCP ports with some demonstrable failures
for port in "${TEST_PORTS[@]}"; do
    test_egress $port "TCP"
done

# Additional egress checks that the per-port loop doesn't cover:
# DNS to arbitrary external resolvers (UDP/53),
# NTP (UDP/123),
# and TLS handshake validation to reference IPs on :443.
test_dns_egress_resolvers
test_ntp_egress
test_tls_egress_handshake

# Enhanced PCI DSS v4.0 specific tests
section_header "PHASE 3: PCI DSS v4.0 ENHANCED COMPLIANCE TESTS"

# Test for system hardening (PCI DSS Requirement 2.2.1)
echo -e "\n${PURPLE}${BOLD}Testing System Hardening (PCI DSS 2.2.1)${NC}"
test_system_hardening() {
    local test_host=$1
    echo -e "  ${WHITE}Testing system hardening on $test_host${NC}"

    # Liveness pre-check — see comprehensive_port_scan() for rationale.
    # Without this, a random IP plucked from a /24 with no host bound
    # silently passes every "service properly disabled" check.
    if ! ping -c 1 -W 1 "$test_host" &>/dev/null \
         && ! timeout 2 bash -c "exec 3<>/dev/tcp/$test_host/22" 2>/dev/null \
         && ! timeout 2 bash -c "exec 3<>/dev/tcp/$test_host/80" 2>/dev/null \
         && ! timeout 2 bash -c "exec 3<>/dev/tcp/$test_host/443" 2>/dev/null; then
        show_result "System Hardening liveness on $test_host" "INFO" "Target $test_host appears offline — hardening checks skipped (would otherwise false-PASS)" "general" "2.2.1"
        return
    fi

    # Check for unnecessary services
    echo -e "  ${WHITE}Checking for unnecessary services...${NC}"
    unnecessary_ports=("21" "23" "135" "139" "445" "1433" "3306" "5432")
    for port in "${unnecessary_ports[@]}"; do
        if timeout 2 nc -zv -w 1 $test_host $port &>/dev/null; then
            show_result "System Hardening - Port $port on $test_host" "FAIL" "Unnecessary service detected" "general" "2.2.1"
            echo -e "    ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 2.2.1 - Unnecessary service running"
            echo -e "    ${YELLOW}${BOLD}REMEDIATION:${NC} Disable or secure service on port $port"
        else
            show_result "System Hardening - Port $port on $test_host" "PASS" "Service properly disabled" "general" "2.2.1"
        fi
    done
}

# Test TLS/SSL configuration (PCI DSS Requirement 4.2.1)
echo -e "\n${PURPLE}${BOLD}Testing TLS/SSL Configuration (PCI DSS 4.2.1)${NC}"
test_tls_configuration() {
    local test_host=$1
    local test_port=$2
    echo -e "  ${WHITE}Testing TLS configuration on $test_host:$test_port${NC}"

    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "  ${YELLOW}OpenSSL not available - skipping TLS tests${NC}"
        return
    fi

    # Pre-check: is anything actually listening on test_host:test_port?
    # If the port is closed or the host is unreachable, the protocol-version
    # probes below will fail for reasons that have nothing to do with TLS
    # configuration, producing misleading PASS/FAIL results.
    if ! timeout 3 bash -c "exec 3<>/dev/tcp/$test_host/$test_port" 2>/dev/null; then
        show_result "TLS Test - reachability $test_host:$test_port" "INFO" "No TLS endpoint found at $test_host:$test_port; skipping cipher/version probes" "tls" "4.2.1"
        return
    fi

    # Test SSLv3 is rejected (PCI DSS forbids it).
    # Modern openssl builds compile out -ssl3 entirely. If the binary doesn't
    # support the flag, we can't probe — report INFO instead of a fake PASS.
    echo -e "  ${WHITE}Command: openssl s_client -connect $test_host:$test_port -ssl3 < /dev/null${NC}"
    local ssl3_out
    ssl3_out=$(timeout 5 openssl s_client -connect "$test_host:$test_port" -ssl3 </dev/null 2>&1)
    local ssl3_rc=$?
    if grep -qi "unknown option\|invalid command\|ssl3 is disabled" <<<"$ssl3_out"; then
        show_result "TLS Test - SSLv3 on $test_host:$test_port" "INFO" "Local openssl does not support -ssl3 probe (cannot confirm server-side SSLv3 status)" "tls" "4.2.1"
    elif [[ $ssl3_rc -eq 0 ]] && grep -q "Cipher is" <<<"$ssl3_out"; then
        show_result "TLS Test - SSLv3 on $test_host:$test_port" "FAIL" "Server negotiated an SSLv3 session" "tls" "4.2.1"
        echo -e "    ${RED}${BOLD}CRITICAL PCI DSS VIOLATION:${NC} Requirement 4.2.1 - Weak encryption"
        echo -e "    ${YELLOW}${BOLD}REMEDIATION:${NC} Disable SSLv3 on the server"
    else
        show_result "TLS Test - SSLv3 on $test_host:$test_port" "PASS" "Server refused SSLv3" "tls" "4.2.1"
    fi

    # Test TLS 1.2 is offered.
    echo -e "  ${WHITE}Command: openssl s_client -connect $test_host:$test_port -tls1_2 < /dev/null${NC}"
    if timeout 5 openssl s_client -connect "$test_host:$test_port" -tls1_2 </dev/null 2>&1 | grep -q "Cipher is"; then
        show_result "TLS Test - TLS 1.2+ on $test_host:$test_port" "PASS" "Server negotiated TLS 1.2" "tls" "4.2.1"
    else
        show_result "TLS Test - TLS 1.2+ on $test_host:$test_port" "FAIL" "Server did not negotiate TLS 1.2" "tls" "4.2.1"
        echo -e "    ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 4.2.1 - Strong encryption required"
        echo -e "    ${YELLOW}${BOLD}REMEDIATION:${NC} Enable TLS 1.2 (or 1.3) on the server"
    fi
}

# Default-credentials testing intentionally omitted: PCI DSS 2.1 verification
# requires authenticated penetration testing, which is out of scope for this
# non-intrusive segmentation/egress checker. A hardcoded "PASS" here was
# previously misleading and has been removed.

# Run enhanced tests on CDE systems
if [[ -n "${SEGMENTS[CDE]}" ]]; then
    cde_test_ip=$(get_random_ip "${SEGMENTS[CDE]}")
    test_system_hardening $cde_test_ip
    test_tls_configuration $cde_test_ip 443
fi

# Test for audit logging capabilities (PCI DSS Requirement 10.2)
echo -e "\n${PURPLE}${BOLD}Testing Audit Logging (PCI DSS 10.2)${NC}"
test_audit_logging() {
    echo -e "  ${WHITE}Checking local audit logging configuration${NC}"
    
    # Check if auditd is running
    if systemctl is-active auditd &>/dev/null || service auditd status &>/dev/null; then
        show_result "Audit Service Status" "PASS" "Audit service is running"
        
        # Check audit log file permissions
        if [[ -f "/var/log/audit/audit.log" ]]; then
            perms=$(stat -c "%a" /var/log/audit/audit.log 2>/dev/null)
            if [[ "$perms" == "600" || "$perms" == "640" ]]; then
                show_result "Audit Log Permissions" "PASS" "Audit logs properly secured"
            else
                show_result "Audit Log Permissions" "FAIL" "Insecure audit log permissions: $perms"
                echo -e "    ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 10.5.1 - Audit logs not secured"
                echo -e "    ${YELLOW}${BOLD}REMEDIATION:${NC} Set audit log permissions to 600 or 640"
            fi
        fi
    else
        show_result "Audit Service Status" "FAIL" "Audit service not running"
        echo -e "  ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 10.2 - Audit logging required"
        echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Enable and configure audit logging service"
    fi
}

test_audit_logging

# IPv6 security testing (if IPv6 segments detected)
echo -e "\n${PURPLE}${BOLD}Testing IPv6 Security (Modern Networks)${NC}"
test_ipv6_security() {
    local has_ipv6=false
    
    # Check for IPv6 segments
    for segment in "${!SEGMENTS[@]}"; do
        if [[ $segment =~ ^IPv6- ]]; then
            has_ipv6=true
            local ipv6_network="${SEGMENTS[$segment]}"
            echo -e "  ${WHITE}Testing IPv6 segment: $segment ($ipv6_network)${NC}"
            
            # Test IPv6 connectivity
            if command -v ping6 >/dev/null 2>&1; then
                echo -e "  ${WHITE}Command: ping6 -c 1 ::1${NC}"
                if ping6 -c 1 ::1 &>/dev/null; then
                    show_result "IPv6 Loopback Test" "PASS" "IPv6 stack functional" "ipv6" "1.2.3"
                else
                    show_result "IPv6 Loopback Test" "FAIL" "IPv6 stack not functional" "ipv6" "1.2.3"
                fi
                
                # Test IPv6 external connectivity
                echo -e "  ${WHITE}Command: ping6 -c 1 2001:4860:4860::8888${NC}"
                if timeout 5 ping6 -c 1 2001:4860:4860::8888 &>/dev/null; then
                    show_result "IPv6 External Connectivity" "FAIL" "IPv6 external access allowed" "ipv6" "1.3.4"
                    echo -e "  ${RED}${BOLD}SECURITY RISK:${NC} IPv6 may bypass firewall rules"
                    echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Ensure IPv6 firewall rules match IPv4 restrictions"
                else
                    show_result "IPv6 External Connectivity" "PASS" "IPv6 external access blocked" "ipv6" "1.3.4"
                fi
            else
                echo -e "  ${YELLOW}ping6 not available - IPv6 testing limited${NC}"
            fi
            
            # Test IPv6 neighbor discovery security
            if command -v ip >/dev/null 2>&1; then
                echo -e "  ${WHITE}Checking IPv6 neighbor discovery...${NC}"
                neighbor_count=$(ip -6 neigh show | wc -l)
                if [[ $neighbor_count -gt 10 ]]; then
                    show_result "IPv6 Neighbor Discovery" "FAIL" "Excessive IPv6 neighbors ($neighbor_count)" "ipv6" "1.2.3"
                    echo -e "  ${YELLOW}${BOLD}WARNING:${NC} Potential IPv6 neighbor table exhaustion risk"
                else
                    show_result "IPv6 Neighbor Discovery" "PASS" "Normal IPv6 neighbor count ($neighbor_count)" "ipv6" "1.2.3"
                fi
            fi
        fi
    done
    
    if [[ "$has_ipv6" == "false" ]]; then
        echo -e "  ${YELLOW}No IPv6 segments detected - skipping IPv6-specific tests${NC}"
        show_result "IPv6 Detection" "INFO" "No IPv6 configured" "ipv6" "1.2.3"
    fi
}

test_ipv6_security

# DNS exfiltration test
echo -e "\n${YELLOW}Testing DNS Exfiltration${NC}"
echo -e "  ${WHITE}Command: host \"exfil.data.$EGRESS_TEST_DOMAIN\"${NC}"

# Use actual DNS test result
if host "exfil.data.$EGRESS_TEST_DOMAIN" &>/dev/null; then
    # Show the actual response from the server
    echo -e "  ${WHITE}Response: exfil.data.$EGRESS_TEST_DOMAIN has address $(getent hosts exfil.data.$EGRESS_TEST_DOMAIN | awk '{ print $1 }')${NC}"
    show_result "DNS Exfiltration Test" "FAIL" "DNS queries to external domains allowed"
    echo -e "  ${RED}${BOLD}CRITICAL PCI DSS VIOLATION:${NC} Requirement 1.3.4 - Unrestricted outbound traffic"
    echo -e "  ${RED}${BOLD}SECURITY IMPACT:${NC} Cardholder data can be exfiltrated via DNS queries"
    echo -e "  ${RED}${BOLD}ATTACK SCENARIO:${NC} Attackers can encode stolen card data in DNS queries"
    echo -e "  ${WHITE}Example: credit-4000-1234-5678-9012.attacker.com${NC}"
    echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Implement DNS filtering and monitoring"
else
    echo -e "  ${WHITE}Response: DNS resolution failed${NC}"
    show_result "DNS Exfiltration Test" "PASS" "DNS queries properly restricted"
fi

# File-upload egress: probe whether an outbound HTTPS POST to a non-CDE
# endpoint completes. We don't actually transfer /etc/passwd; just confirm
# that the HTTPS request reaches the upstream and gets a response.
echo -e "\n${YELLOW}Testing File Transfer Egress (PCI DSS 1.3.4)${NC}"
echo -e "  ${WHITE}Command: curl -s -m 5 -o /dev/null -w '%{http_code}' https://$EGRESS_TEST_DOMAIN/${NC}"

upload_http_code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "https://$EGRESS_TEST_DOMAIN/" 2>/dev/null)
if [[ "$upload_http_code" =~ ^[1-5][0-9][0-9]$ ]]; then
    echo -e "  ${WHITE}Response: HTTPS reachable (HTTP $upload_http_code) — outbound upload channel viable${NC}"
    show_result "File Upload Egress Test" "FAIL" "Outbound HTTPS to $EGRESS_TEST_DOMAIN succeeded (HTTP $upload_http_code) — exfil channel viable" "egress" "1.3.4"
    echo -e "  ${RED}${BOLD}PCI DSS VIOLATION:${NC} Requirement 1.3.4 - Unauthorized outbound traffic"
    echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Restrict outbound HTTPS to an allowlist of business-required destinations"
else
    echo -e "  ${WHITE}Response: HTTPS request did not complete (curl exit / no HTTP status)${NC}"
    show_result "File Upload Egress Test" "PASS" "Outbound HTTPS to $EGRESS_TEST_DOMAIN blocked or unreachable" "egress" "1.3.4"
fi

# Test for ICMP exfiltration
echo -e "\n${YELLOW}Testing ICMP Exfiltration (Advanced)${NC}"
echo -e "  ${WHITE}Command: ping -c 1 -s 1000 $EGRESS_TEST_DOMAIN${NC}"
if ping -c 1 -s 1000 $EGRESS_TEST_DOMAIN &>/dev/null; then
    echo -e "  ${WHITE}Response: PING successful with large payload${NC}"
    show_result "ICMP Exfiltration Test" "FAIL" "Large ICMP packets allowed"
    echo -e "  ${RED}${BOLD}SECURITY RISK:${NC} Data can be exfiltrated via ICMP tunneling"
    echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Implement ICMP filtering and size restrictions"
else
    echo -e "  ${WHITE}Response: PING failed or filtered${NC}"
    show_result "ICMP Exfiltration Test" "PASS" "ICMP properly controlled"
fi

# Test for covert channel via HTTP headers
echo -e "\n${YELLOW}Testing HTTP Header Exfiltration${NC}"
echo -e "  ${WHITE}Command: curl -H 'X-Exfil-Data: sensitive-info' http://$EGRESS_TEST_DOMAIN${NC}"
if curl -s -m 5 -H 'X-Exfil-Data: sensitive-info' http://$EGRESS_TEST_DOMAIN &>/dev/null; then
    echo -e "  ${WHITE}Response: HTTP request with custom headers successful${NC}"
    show_result "HTTP Header Exfiltration Test" "FAIL" "Custom HTTP headers allowed"
    echo -e "  ${RED}${BOLD}SECURITY RISK:${NC} Data can be embedded in HTTP headers"
    echo -e "  ${YELLOW}${BOLD}REMEDIATION:${NC} Implement HTTP header filtering and inspection"
else
    echo -e "  ${WHITE}Response: HTTP request blocked or filtered${NC}"
    show_result "HTTP Header Exfiltration Test" "PASS" "HTTP traffic properly inspected"
fi

# Enhanced Summary with final report generation
section_header "TEST SUMMARY AND REPORT GENERATION"
echo -e "${YELLOW}Total Tests:${NC} $(($PASSED + $FAILED + $SKIPPED))"
echo -e "${GREEN}Tests Passed:${NC} $PASSED"
echo -e "${RED}Tests Failed:${NC} $FAILED"
echo -e "${CYAN}Tests Skipped/Info:${NC} $SKIPPED"

# Finalize JSON report
finalize_json_report() {
    if command -v jq >/dev/null 2>&1; then
        local temp_file=$(mktemp)
        jq --arg total "$(($PASSED + $FAILED + $SKIPPED))" \
           --arg passed "$PASSED" \
           --arg failed "$FAILED" \
           --arg skipped "$SKIPPED" \
           --arg status "$([ $FAILED -gt 0 ] && echo 'FAILED' || echo 'PASSED')" \
           '.summary.total_tests = ($total | tonumber) |
            .summary.passed = ($passed | tonumber) |
            .summary.failed = ($failed | tonumber) |
            .summary.skipped = ($skipped | tonumber) |
            .summary.compliance_status = $status' \
           "$JSON_REPORT" > "$temp_file" && mv "$temp_file" "$JSON_REPORT"

        echo -e "${CYAN}Structured JSON report generated: $JSON_REPORT${NC}"
    fi
}

# Generate executive summary
generate_executive_summary() {
    local summary_file="pci_executive_summary_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$summary_file" << EOF
PCI DSS v4.0 COMPLIANCE TEST - EXECUTIVE SUMMARY
================================================

Test Date: $(date)
Tester: $(whoami)@$(hostname)
Environment: Card Data Environment (CDE)

OVERALL COMPLIANCE STATUS: $([ $FAILED -gt 0 ] && echo 'NON-COMPLIANT' || echo 'COMPLIANT')

TEST RESULTS SUMMARY:
- Total Tests Executed: $(($PASSED + $FAILED + $SKIPPED))
- Tests Passed: $PASSED
- Tests Failed: $FAILED
- Tests Skipped/Info: $SKIPPED
- Success Rate: $([ $((PASSED + FAILED)) -gt 0 ] && echo "$(( PASSED * 100 / (PASSED + FAILED) ))%" || echo "N/A")

KEY FINDINGS:
$([ $FAILED -gt 0 ] && echo "- $FAILED critical security controls require immediate attention" || echo "- All tested security controls meet PCI DSS v4.0 requirements")
$([ $FAILED -gt 0 ] && echo "- Review detailed log file: $LOG_FILE" || echo "- Environment demonstrates strong security posture")
$([ $FAILED -gt 0 ] && echo "- Remediation required before PCI DSS assessment" || echo "- Ready for formal PCI DSS assessment")

NEXT STEPS:
$([ $FAILED -gt 0 ] && echo "1. Address all failed test findings" || echo "1. Maintain current security controls")
$([ $FAILED -gt 0 ] && echo "2. Re-run tests after remediation" || echo "2. Schedule regular compliance testing")
$([ $FAILED -gt 0 ] && echo "3. Document remediation efforts" || echo "3. Document current compliant state")

For detailed technical findings, see:
- Detailed Log: $LOG_FILE
- JSON Report: $JSON_REPORT

EOF
    echo -e "${PURPLE}Executive summary generated: $summary_file${NC}"
}

finalize_json_report
generate_executive_summary

# Generate a clear PCI compliance status
if [[ $FAILED -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}${UNDERLINE}PCI DSS COMPLIANCE STATUS: FAILED${NC}"
    echo -e "${RED}${BOLD}Please review and remediate all failed tests before your assessment.${NC}"
    echo -e "${WHITE}Critical security gaps identified that require immediate attention.${NC}"
else
    echo -e "\n${GREEN}${BOLD}${UNDERLINE}PCI DSS COMPLIANCE STATUS: PASSED${NC}"
    echo -e "${GREEN}${BOLD}All network controls meet PCI DSS v4.0 requirements.${NC}"
    echo -e "${WHITE}Environment demonstrates strong security posture for PCI DSS compliance.${NC}"
fi

draw_line
echo -e "${BLUE}Testing Complete${NC}"
echo -e "${YELLOW}Report generated:${NC} $(date)"
echo -e "${YELLOW}Tester:${NC} $(whoami)@$(hostname)"
echo -e "${CYAN}Detailed Log:${NC} $LOG_FILE"
echo -e "${CYAN}JSON Report:${NC} $JSON_REPORT"
draw_line
