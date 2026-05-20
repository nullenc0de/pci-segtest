# PCI DSS v4.0 Network Testing Tool

A network segmentation and egress-control validation tool for PCI DSS v4.0
compliance assessments. Runs from a single vantage host inside (or adjacent
to) the Card Data Environment and reports what's actually reachable —
distinguishing real egress from canary allowlists and TLS-inspection
interception.

## Quick start

```bash
# Recommended dependencies (script degrades gracefully without them, with warnings)
sudo apt-get install -y jq dnsutils ntpsec-ntpdate netcat-openbsd dnsutils openssl

# Standard run (general CDE host)
sudo ./segment.sh

# Run on the authorized vulnerability scanner host
sudo ./segment.sh --scanner-host
```

Outputs three artifacts in the working directory:

- `pci_test_<timestamp>.log` — full text log of every check
- `pci_report_<timestamp>.json` — structured per-check JSON (populated when `jq` is installed)
- `pci_executive_summary_<timestamp>.txt` — short summary suitable for the engagement deliverable

## What's tested

### Phase 1 — Network segmentation (PCI DSS 1.3.x)

- **Allowed-path verification** (`ALLOWED_PATHS` from `network_config.txt`):
  confirms required cross-segment paths actually work.
- **Isolation tests**: for every segment pair *not* in `ALLOWED_PATHS`,
  probes a sampling of admin/database/web ports and reports any that get
  through as a segmentation failure.
- **Liveness gating**: random-IP targets that don't respond to ICMP or
  TCP/22/80/443 are reported as `INFO` rather than `PASS`, because a
  ghost address answering "no" tells us nothing about the firewall.

### Phase 2 — Egress control (PCI DSS 1.3.4)

Egress testing is the part most often broken in similar tools, so this
one is deliberately layered:

1. **Canary marker check** against `letmeoutofyour.net` (Black Hills
   Information Security's egress canary). Every port returns a
   `w00tw00t` marker on TCP connect (HTTP ports need a `GET`), so we
   can prove the bytes actually round-tripped rather than just trusting
   that the TCP handshake completed.
2. **Reference-IP cross-check** against `1.1.1.1`, `8.8.8.8`, `9.9.9.9`.
   If the canary is reachable but no reference IP is, the canary is
   likely allowlisted by the customer's firewall and the canary result
   alone would be a false-positive finding.
3. **External DNS resolver probe** (`dig` against 1.1.1.1, 8.8.8.8,
   9.9.9.9 on UDP/53). DNS being open to any external resolver is a
   PCI 1.3.4 risk; the box should resolve only via internal recursors.
4. **NTP (UDP/123)** to `pool.ntp.org`. Often-overlooked exfil/C2 vector.
5. **TLS handshake validation** on `:443` to each reference IP. A clean
   TCP open with a stalled TLS handshake indicates a TLS-inspection or
   SNI-filter middlebox on the path — neither a clean PASS nor a clean
   FAIL, classified `INFO` for further investigation.
6. **DNS exfiltration** via internal recursor (queries an arbitrary
   subdomain of the canary; if it resolves, exfil via encoded
   subdomains is viable).
7. **ICMP and HTTP-header exfil** probes for the long-tail channels.

### Phase 3 — Other PCI DSS v4.0 checks

- System hardening (PCI DSS 2.2.1): scans a CDE target for unnecessary
  services. Skipped (`INFO`) if the target host is offline.
- TLS configuration (PCI DSS 4.2.1): checks SSLv3 is refused and TLS 1.2
  is offered. Reachability-gated so a closed port doesn't false-PASS.
- Audit logging (PCI DSS 10.2): verifies `auditd` is running.
- IPv6 detection / configuration (PCI DSS 1.2.3, 1.3.4).

## Result semantics

| Status | Meaning |
|--------|---------|
| `PASS` | Control is working — connection blocked / cipher refused / service disabled, as expected. |
| `FAIL` | Control is missing or broken — finding for the report. |
| `INFO` | Couldn't validate the control. Common reasons: target host offline (no point probing), canary appears allowlisted, TLS-inspection middlebox terminating connections, optional dependency missing. Treat these as "needs follow-up", not "passed". |

`INFO` and `SKIP` are tracked separately from `PASS`/`FAIL` in the
summary so a run that legitimately couldn't probe anything doesn't
masquerade as compliant.

## Scanner-host exception (`--scanner-host`)

The authorized vulnerability scanner (Nessus, Qualys, etc.) running
inside the CDE needs outbound 80/443 (and effectively DNS via the
internal recursor) to pull plugin updates and OS patches — that's a
documented PCI exception, not a finding.

Pass `--scanner-host` and the script reclassifies the ports a scanner
needs from `FAIL` to `INFO` with a "scanner-host exception" note:

```bash
sudo ./segment.sh --scanner-host
```

Default scanner allowlist is `53 80 443`. Override via env or
`network_config.txt`:

```bash
SCANNER_ALLOWED_PORTS=(80 443)   # stricter — disallow direct external DNS
```

Things that **don't** get downgraded even in `--scanner-host` mode:
findings on unrelated ports (e.g. `:8080`, `:8443`), the DNS exfil
test (recursor accepting arbitrary subdomains is a scanner-independent
issue), `auditd` not running, and TLS handshake INFO classifications.

**Do not pass this flag on general-purpose CDE hosts** — it hides real
findings. The flag is recorded in the executive summary so report
readers know it was used.

## Configuration

Drop a `network_config.txt` in the same directory as the script to
override autodiscovery. Example:

```bash
SEGMENTS["CDE"]="10.50.10.0/24"
SEGMENTS["DMZ"]="192.168.10.0/24"
SEGMENTS["Corporate"]="10.200.0.0/16"

ALLOWED_PATHS+=("Corporate:CDE:443")
ALLOWED_PATHS+=("DMZ:CDE:443")
```

You can also override the egress canary, reference IPs, and resolver
list (defined near the top of the script):

```bash
EGRESS_TEST_DOMAIN="letmeoutofyour.net"
RESPONSE_CHECK="w00tw00t"
EGRESS_REFERENCE_IPS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
EXTERNAL_DNS_RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
```

## Limitations

Be honest about what a single-vantage tool can and can't tell you:

- **Single vantage**: tests run from one host inside (or adjacent to)
  the CDE. We can verify "this host can/can't reach X" — we can't
  verify "non-CDE hosts can't reach the CDE" without a probe placed in
  the non-CDE segment. A complete segmentation assessment needs
  probes on each side of the boundary.
- **Random-IP segmentation tests**: when `network_config.txt` doesn't
  specify known live hosts per segment, the script uses random IPs in
  the segment's CIDR. Those tests are `INFO` (skipped) when the random
  IP doesn't respond — a "no answer" from a ghost address doesn't
  prove segmentation. Provide real hosts in `network_config.txt` for
  meaningful results.
- **Canary allowlisting**: customers commonly add the assessor's
  canary host to a firewall allowlist so testing works at all. The
  reference-IP cross-check catches this — without it, every port
  would look open.

## Requirements

- Bash 4+
- Required: `ip`, `ping`, `nc` (netcat-openbsd)
- Recommended: `jq` (for JSON report), `dig` (`dnsutils`, for DNS resolver
  egress), `ntpdate`/`ntpsec-ntpdate` (UDP/123), `openssl` (TLS probes),
  `curl`, `host`
- Run as root or with sudo for full network discovery and ICMP

## Output / interpretation

A typical good run on a properly-segmented CDE host looks like:

```
Total Tests Executed: 36
Tests Passed:         9
Tests Failed:         7
Tests Skipped/Info:   20
```

A high `INFO` count is normal — it reflects the script being honest
about what it could and couldn't actually test from a single vantage.
The deliverable should reflect the `FAIL` count and explain the `INFO`
classifications case-by-case.

## Security considerations

- Run with explicit authorization. The egress probes are mostly
  passive but the segmentation tests touch arbitrary IPs in the
  target subnets.
- Test against the canary involves outbound connections to
  `letmeoutofyour.net` (45.33.104.77). Brief the customer that the
  scanner host needs outbound network access for the test to work.
- Schedule during a maintenance window when possible; the
  comprehensive port scan can generate IDS events.

## License

Provided as-is for security assessment use.
