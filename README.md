# XorDDoS Trojan Detection – April 2025

## Summary

The investigation began after a custom detection rule for XorDDoS Trojans triggered in Microsoft Sentinel on **April 8, 2025**. This rule was configured following a breach in **March 2025**, during which XorDDoS activity was documented in the environment.

## Current Scope

The investigation is focused on activity associated with **Remote IP: 218.92.0.231**.

---

## 📁 Uploaded Log Files

These `.csv` files were reviewed and analyzed as part of the forensic process:

- `total_device_logon_events.csv` – Logon activity, including SSH brute-force attempts.
- `total_device_process_events.csv` – Suspicious command execution (PowerShell, wget, curl, etc.).
- `total_device_file_events.csv` – Local file creation/modification linked to payload staging.
- `total_file_events_and_network_events.csv` – Correlation of file events and outbound network activity.
- `total_suspicious_ips.csv` – IPs contacted by compromised host; includes known and suspicious addresses.

---

## 📌 Supporting Reports

### 🔸 [MITRE ATT&CK Report]
Outlines the techniques and tactics used during the incident, mapped to the MITRE ATT&CK framework. Includes activity across:

- Initial Access (Brute Force)
- Execution (Shell / PowerShell)
- Persistence (Init scripts or systemd services)
- Defense Evasion (Masquerading, Obfuscation)
- Discovery, Collection, and Exfiltration
- Command and Control (via HTTP/S)

---

### 🔸 [Further_investigation_ips]
Details external IPs that should be prioritized for threat intel enrichment and retrospective log analysis.  
Suggested actions include:

- IP reputation checks
- Proxy/DNS log pivoting
- GeoIP and ASN enrichment
- C2 infrastructure tracing

---

### 🔸 [Remediation]
Provides detailed short-term and long-term remediation actions:

- System isolation
- IP blocks and credential resets
- SSH hardening
- Monitoring recommendations
- Threat hunting guidance
- Security control improvements

---

### 🔸 [KQL]
Provides KQL commands used.

