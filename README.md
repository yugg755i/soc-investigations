# SOC Investigations

A collection of SOC incident investigations performed in the LetsDefend SOC simulation environment. Each report documents the investigation process from initial alert triage through evidence analysis, MITRE ATT&CK mapping, and final incident verdict, covering authentication attacks, phishing, malware execution, identity attacks, and cloud security events.

## About

The alert scenarios, telemetry, and investigation playbooks are provided by LetsDefend. The investigation methodology, evidence analysis, IOC validation, MITRE ATT&CK mapping, incident assessment, and documentation were completed independently.

## Methodology

Each investigation follows a standardized incident response workflow:

```
Alert Triage → Evidence Collection → IOC Analysis → Threat Intelligence Validation → MITRE ATT&CK Mapping → Impact Assessment → Incident Verdict → Response Recommendations
```

## Investigation Index

| # | Title | Attack Type | Severity | Verdict | MITRE Tactics | Report |
|---|-------|----------|----------|---------|----------------|--------|
| 001 | RDP Brute Force, Successful Login from External IP | Brute Force | Medium | True Positive | Initial Access, Credential Access | [INV-001](investigations/INV-001-rdp-brute-force.md) |
| 002 | Phishing Email, Malicious Attachment Executed with C2 Callback | Phishing | Medium | True Positive | Initial Access, Execution, Command and Control | [INV-002](investigations/INV-002-phishing-deceptive-email.md) |
| 003 | Suspicious PowerShell Execution, Drive-By Download Leading to C2 Callback | Malware Execution | Medium | True Positive | Initial Access, Execution, Defense Evasion, Command and Control | [INV-003](investigations/INV-003-powershell-execution.md) |
| 004 | VPN Login Attempt from Unauthorized Country, Blocked by MFA | Unauthorized Access | Low | True Positive | Credential Access | [INV-004](investigations/INV-004-vpn-unauthorized-country.md) |
| 005 | Unauthorized Cloud Region Access Attempt, Blocked Before Authentication | Web Attack | Low | True Positive | Defense Evasion, Credential Access | [INV-005](investigations/INV-005-cloud-region-access.md) |

## Repository Structure

```
SOC-Investigations/
├── README.md
├── investigations/   # Individual incident reports
│   ├── INV-001-rdp-brute-force.md
│   ├── INV-002-phishing-deceptive-email.md
│   ├── INV-003-powershell-execution.md
│   ├── INV-004-vpn-unauthorized-country.md
│   └── INV-005-cloud-region-access.md
└── evidence/         # Supporting investigation screenshots
    ├── 001_alert_overview.png
    ├── 002_alert_overview.png
    ├── 003_alert_overview.png
    ├── 004_alert_overview.png
    └── 005_alert_overview.png
```

## Technologies & Platforms

`LetsDefend` · `VirusTotal` · `AbuseIPDB` · `MITRE ATT&CK Navigator`

## Contact

### Yug Sutariya

[LinkedIn](https://www.linkedin.com/in/yug-sutariya-410a79320/) | [GitHub](https://github.com/yugg755i) | [Email](mailto:sutariyayug5@gmail.com)
