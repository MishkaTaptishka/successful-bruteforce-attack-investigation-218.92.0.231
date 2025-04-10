# MITRE ATT&CK Mapping

## Tactic: Initial Access  
**Technique:** [T1110.001] Brute Force: Password Guessing  
- Multiple failed SSH login attempts were recorded, targeting default accounts such as `root`.
- Activity originated from various external IPs, consistent with brute-force behavior.
- A successful login was eventually observed on April 8, 2025, validating the breach via brute-force.

---

## Tactic: Execution  
**Technique:** [T1059.004] Command and Scripting Interpreter: Unix Shell  
- Suspicious shell command execution (`/bin/sh`, `.sh`, `bash`) was identified.
- Attackers used tools like `wget` and `curl` for payload retrieval, confirming scripted automation of execution phase.

**Technique:** [T1059.001] Command and Scripting Interpreter: PowerShell  
- PowerShell commands containing `-EncodedCommand` were detected, suggesting use of obfuscated scripts across platforms.

---

## Tactic: Persistence  
**Technique:** [T1037] Boot or Logon Initialization Scripts  
- Files were created or modified in directories such as `/etc/init.d/`, `/lib/systemd/`, and similar startup folders.
- This implies persistence via system services or startup agents.

---

## Tactic: Defense Evasion  
**Technique:** [T1036] Masquerading  
- Filenames such as `svchost.ps1`, `updateservice.sh`, and other variants mimicking system binaries were observed.
- These files were placed in privileged or commonly trusted folders.

**Technique:** [T1027] Obfuscated Files or Information  
- Obfuscation patterns included Base64-encoded PowerShell, and indirect payload staging via script downloaders.

---

## Tactic: Discovery  
**Technique:** [T1082] System Information Discovery  
- Enumeration via commands like `whoami`, `uname -a`, `env`, and `hostname` were logged post-compromise.
- These commands reveal host-level reconnaissance by the attacker.

---

## Tactic: Collection  
**Technique:** [T1005] Data from Local System  
- Large file creations (over 1MB) occurred shortly after suspicious process execution, suggesting data staging or payload unpacking.
- Locations and file names aligned with attacker-controlled directories.

---

## Tactic: Command and Control  
**Technique:** [T1071.001] Application Layer Protocol: Web Protocols  
- Outbound connections over ports 80, 443, and 1520 were logged, sourced from renamed binaries.
- Connections matched indicators of compromise and C2 behavior.

---

## Tactic: Exfiltration  
**Technique:** [T1041] Exfiltration Over C2 Channel  
- Timing of outbound network activity and file events (within short intervals) indicates potential exfiltration via existing C2 paths.

---

## Findings

- Device `linuxremediation.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` exhibited full attack chain activity.
- Attacker used a brute-force SSH login to gain initial access.
- Post-exploitation included system enumeration, persistence via init/systemd, and outbound HTTP/S connections.
- No interactive shell activity was noted, indicating automation via scripts or agents.
