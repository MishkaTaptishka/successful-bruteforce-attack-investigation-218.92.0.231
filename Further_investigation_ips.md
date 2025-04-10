# 🔍 Further Investigation – Suspicious External IPs

This document lists IP addresses that were contacted by the compromised host during or following the XorDDoS activity window. These IPs should be prioritized for threat intelligence enrichment, historical traffic review, and possible IOC correlation.

---

## 📌 Suspicious IPs for Enrichment and Review

- `169.254.169.254`
- `185.199.109.133`
- `185.199.108.133`
- `185.199.110.133`
- `185.199.111.133`
- `169.239.130.5`

> **Note:**  
> - `169.254.169.254` is commonly used by cloud instance metadata services (e.g., AWS EC2, Azure IMDS). Review for misuse or unauthorized metadata access attempts.  
> - IPs in the `185.199.x.x` range are GitHub infrastructure; investigate their use in the context of suspicious download, staging, or C2 activity.

---

## Suggested Investigation Steps

1. **Check threat intelligence feeds** for each IP:
   - Use platforms such as VirusTotal, AbuseIPDB, Cisco Talos, and GreyNoise.
   - Flag any known associations with malware delivery, C2 servers, or botnet infrastructure.

2. **Perform historical log analysis**:
   - Pivot across proxy, firewall, and DNS logs for traffic to/from these IPs.
   - Identify patterns of communication or recurrence across other assets in the environment.

3. **Enrich with context**:
   - Conduct GeoIP and ASN lookups for external addresses.
   - Use reverse DNS to identify service providers or hosting platforms.
