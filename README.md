# PCI DSS v4.0 Network Testing Tool

## Overview

This tool helps assess network segmentation and egress control compliance with PCI DSS v4.0 requirements. It automatically discovers network segments, tests segmentation between them, and checks for unauthorized egress paths that could lead to data exfiltration.

## Features

- **Automatic Network Discovery**: Identifies available network segments without requiring manual configuration
- **Segmentation Testing**: Tests network isolation between segments to verify PCI DSS segmentation requirements
- **Egress Control Testing**: Verifies that outbound connections are properly restricted
- **DNS Exfiltration Testing**: Checks for DNS-based data exfiltration risks
- **File Transfer Testing**: Tests for unrestricted file upload capabilities

## Requirements

- Bash shell environment
- Network utilities: `ip`, `nc` (netcat), `host`, `getent`, and `curl`
- Run from within the CDE (Card Data Environment)
- Root/sudo access for network discovery (recommended)

## Usage

```bash
# Basic usage
./segment.sh

# With sudo (recommended for better network discovery)
sudo ./segment.sh
```

## Configuration

The tool automatically discovers network segments, but for more accurate testing, you can provide a manual configuration file:

1. Create a file named `network_config.txt` in the same directory as the script
2. Define your network segments and allowed paths (see sample_config.txt)
3. Run the script again to use your manual configuration

## Test Phases

### Phase 1: Network Segmentation Testing

Tests network isolation between segments to verify PCI DSS Requirements 1.3.1, 1.3.2, and 1.3.3:

- Tests isolation between all discovered network segments
- Verifies that administrative ports (22, 3389) are properly restricted
- Checks that database ports (1433, 3306) are properly secured

### Phase 2: Egress Control Testing

Tests egress controls to verify PCI DSS Requirement 1.3.4:

- Tests outbound connectivity on common ports (21, 22, 23, 25, 53, 80, 443, etc.)
- Checks for DNS exfiltration vulnerabilities
- Tests for unrestricted file upload capabilities

## Output

The tool produces detailed, color-coded output with:

- Pass/fail indicators for each test
- Detailed diagnostics for failed tests
- PCI DSS requirement references
- Remediation suggestions
- Summary statistics and overall compliance status

## Customization

To test specific network segments or allowed paths:

1. Create a custom `network_config.txt` file
2. Define your SEGMENTS and ALLOWED_PATHS
3. Run the script with your configuration

## Interpreting Results

- **PASS**: The tested control is working as expected
- **FAIL**: The tested control is not properly implemented and requires remediation
- Review all failed tests and implement the suggested remediation measures
- Address egress control failures to prevent data exfiltration
- Ensure proper segmentation to restrict access to cardholder data

## Security Considerations

- Run this tool in a controlled environment
- Coordinate testing with your security team
- Schedule testing during maintenance windows when possible
- Obtain proper authorization before testing

## Troubleshooting

- If no segments are discovered, verify your network configuration
- If all tests fail, check network connectivity and firewall settings
- If DNS tests fail unexpectedly, verify DNS resolution is working

## License

This tool is provided for internal use only and should not be distributed without permission.
