# INV-005: Unauthorized Cloud Region Access Attempt, Blocked Before Authentication

| | |
|---|---|
| **Platform** | LetsDefend |
| **Category** | Web Attack |
| **Severity** | Low |
| **Verdict** | True Positive |

## Executive Summary

SIEM rule SOC325 flagged repeated login attempts against `test@letsdefend.io` from 134.209.145.73, originating from a cloud region outside the organization's authorized list. Every attempt returned a 403 and was blocked at the firewall. Reputation lookup on the source IP came back malicious. No login succeeded, no device needed isolating, and no critical system was affected. Verdict is True Positive. A malicious IP made repeated attempts against a real account from an unsupported region, and the firewall held.

## Alert Information

| Field | Value |
|-------|-------|
| Alert ID | SOC325 (Event ID 303) |
| Detection Rule | SOC325, Unauthorized Cloud Region Access Attempt Detected |
| Source IP | 134.209.145.73 |
| Destination IP | 52.15.206.21 |
| Targeted Account | test@letsdefend.io |
| Request | POST /accounts/login HTTP/1.1 403 512 |
| Device Action | Blocked |
| Alert Trigger Reason | Too many access attempts against the same user in a short period from an unused/unsupported cloud region |

## Investigation

The alert fired on a pattern: repeated login attempts against `test@letsdefend.io` from a single source in a short window, from a region flagged as unused or unsupported under the org's cloud access policy. That combination, volume plus region, is what tripped SOC325.

The source IP belongs to a DigitalOcean-owned range (AS14061), commonly used for VPS hosting, while the destination is an AWS-hosted login endpoint. This is consistent with an externally hosted system attempting to access a cloud-hosted service.

Every logged request came back HTTP 403, blocked. That points to the firewall or WAF stopping this before authentication completed, with nothing in the case data suggesting a correct password was ever entered, just volume against the login endpoint. The playbook categorized this specifically as a defense evasion technique tied to unused or unsupported cloud regions, meaning whatever was driving these attempts was trying to route around region-based restrictions or monitoring rather than brute forcing the login form on its own merits.

Scope determination came back negative, no additional systems or users affected, and device isolation wasn't needed since nothing here reached an endpoint. I'm taking that scope answer at face value since the handoff didn't include the underlying log excerpts to verify it independently.

## IOC Table

| Type | Value | Description |
|------|-------|--------------|
| IP | 134.209.145.73 | Source of repeated login attempts, flagged malicious |
| IP | 52.15.206.21 | Destination address, AWS-hosted login endpoint |
| Username | test@letsdefend.io | Targeted account |

## Threat Intelligence

| Indicator | Checked Via | Result |
|-----------|-------------|--------|
| 134.209.145.73 | VirusTotal / manual reputation review | Flagged malicious; falls within a DigitalOcean-owned range (AS14061), consistent with abused VPS infrastructure. No dedicated public AbuseIPDB report found for this exact address at time of review |
| 52.15.206.21 | Manual review | AWS-owned address; this is the organization's own cloud-hosted login endpoint, not a third-party indicator |

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Defense Evasion | T1535, Unused/Unsupported Cloud Regions | Login attempts originated from a cloud region outside the org's authorized/supported list |
| Credential Access | T1110, Brute Force | Multiple login attempts against the same account in a short window |

## Impact & Verdict

No login succeeded, no device needed containment, and no critical system was touched. Every attempt was blocked at the firewall before authentication completed. Scope was reported as limited to this one account and this one source IP, though that determination wasn't independently reverified against raw logs here. Verdict is True Positive, high confidence. A reputation-flagged IP making repeated attempts against a real account from a region the org doesn't authorize is real malicious activity, regardless of the fact it never got anywhere.

## Recommended Response

- **Containment:** No device isolation needed; the attempt was blocked before reaching an endpoint
- **Eradication:** Block 134.209.145.73 at the firewall/WAF; confirm the unauthorized region remains blocked at the cloud access policy level
- **Recovery:** No password reset is strictly required since no login succeeded, but worth confirming `test@letsdefend.io` isn't running a weak or default credential given it's a likely repeat target
- **Prevention:** Review whether test/service accounts should carry MFA or tighter restrictions given they're common automated targets; confirm cloud region allow-listing is enforced consistently across all access points

## Lessons Learned

The account being targeted, `test@letsdefend.io`, is the kind of generic account name that gets probed automatically rather than singled out deliberately, and that's worth keeping in mind when triaging alerts like this one going forward: the account name itself is a signal about whether an attempt is targeted or opportunistic. Also worth flagging for process: the scope determination came from the playbook answers rather than the underlying logs. Verifying that directly against the logs would strengthen the investigation.

## Evidence

### Alert Overview

![Alert Overview](../evidence/005_alert_overview.png)

*Figure 1: LetsDefend alert overview showing the alert details, completed playbook, and final True Positive verdict.*
