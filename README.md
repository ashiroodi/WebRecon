# 🛡️ WebScan — Advanced Web Security Assessment Tool

A comprehensive web application and infrastructure security assessment tool written in Bash.

## Features

- DNS enumeration
- SSL/TLS certificate analysis
- Technology stack fingerprinting
- XSS testing
- SQL injection testing
- Path traversal & LFI testing
- RFI testing
- Command injection testing
- SSTI testing
- XXE testing
- Log4Shell detection
- Security header auditing
- Sensitive file discovery
- Authentication & session testing
- SSRF testing
- HTTP method analysis
- TLS hardening checks
- Nmap integration
- Automated remediation recommendations

## Installation

```bash
chmod +x webscan.sh
```

## Usage

```bash
./webscan.sh example.com
```

Origin IP testing:

```bash
./webscan.sh example.com 1.2.3.4
```

## Output

WebScan generates a timestamped log file containing:

- Findings
- Warnings
- Failures
- Recommended remediations
- Security scorecard

## Disclaimer

Only scan systems you own or have explicit authorization to assess.
