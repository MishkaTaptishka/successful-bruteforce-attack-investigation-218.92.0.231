# 🔒 Summary of Malicious Activity

## Overview

On **April 8, 2025**, a detection rule flagged unauthorized access originating from **IP address 218.92.0.231**, previously linked to the XorDDoS Trojan. This activity is believed to be part of ongoing malicious operations following a confirmed breach in March.

## Key Observations

- **Remote Access:** A successful logon was recorded from the suspicious IP, indicating initial access to an internal host.
- **Process Execution:** Post-access, the attacker executed a range of suspicious processes—primarily automation and transfer tools—suggesting command-and-control or payload deployment.
- **File Activity:** Elevated file creation and modification activity was observed, consistent with data staging or malware deployment.
- **Network Behavior:** Compromised hosts established outbound connections to several external IPs, some of which are linked to malicious infrastructure.

## Conclusion

The sequence of events—remote login, process execution, file staging, and network exfiltration behavior—strongly indicates a post-compromise phase associated with XorDDoS or a similar threat actor. Continued monitoring and containment actions are required.

