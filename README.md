# SOC Investigations

Hands-on SOC investigations performed in the LetsDefend SOC simulation environment, documented as internal-style incident reports.

MITRE ATT&CK-mapped incident investigations covering authentication attacks, phishing, malware execution, identity attacks, and cloud security events.

## About

The alert scenarios, telemetry, and playbooks originate from LetsDefend. The investigation, analysis, verdict reasoning, and documentation are my own.

This repo exists to show how I think through an alert, not just that I got the right answer.

## Methodology

Every investigation follows a consistent structure covering alert information, investigation, IOCs, threat intelligence, MITRE ATT&CK mapping, impact & verdict, recommended response, and lessons learned.

## Investigation Index

| # | Title | Category | Severity | Verdict | MITRE Tactics | Report |
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
├── investigations/
│   ├── INV-001-rdp-brute-force.md
│   ├── INV-002-phishing-deceptive-email.md
│   ├── INV-003-powershell-execution.md
│   ├── INV-004-vpn-unauthorized-country.md
│   └── INV-005-cloud-region-access.md
└── evidence/
    ├── 001_alert_overview.png
    ├── 002_alert_overview.png
    ├── 003_alert_overview.png
    ├── 004_alert_overview.png
    └── 005_alert_overview.png
```

## Skills Demonstrated Across This Repo

| Area | Examples |
|------|----------|
| Log & endpoint analysis | Process trees, PowerShell logs, auth logs, network flows |
| Threat intelligence | VirusTotal, AbuseIPDB, hash/IP/domain reputation checks |
| Detection mapping | MITRE ATT&CK tactic/technique identification |
| Incident triage | True/false positive determination with documented reasoning |
| Technical writing | Concise, evidence-first reporting suitable for handoff |

## Tools Referenced

`LetsDefend` · `VirusTotal` · `AbuseIPDB` · `MITRE ATT&CK Navigator`

## Contact

**Yug Sutariya**, 3rd year B.Sc. IT (Cyber Security)

[LinkedIn](https://www.linkedin.com/in/yug-sutariya-410a79320/) | [GitHub](https://github.com/yugg755i) | [Email](mailto:sutariyayug5@gmail.com)
