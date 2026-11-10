# SOC Incident Analysis Report: Dridex Malware Infection

## 📝 Executive Summary
* **Incident Case:** Dridex / Urelas Malware Infection Analysis
* **Target Organization:** Umbrella Corporation
* **Affected User/Host:** Sarah (Accounting Department) | IP: `10.11.27.101`
* **Analyst Name:** Abdulrezzak AL-Ahmad
* **Date of Investigation:** November 10, 2026
* **Status:** Closed - Remediated & Documented

---

## 🎯 Incident Overview
A security incident was flagged involving an accounting department employee, Sarah, who received a spear-phishing email containing a malicious Microsoft Office document with macros. Upon opening the attachment, a crash occurred, and an unauthorized download chain was triggered, introducing the **Dridex / Urelas** banking trojan into the internal network.

This report details the forensic network analysis performed on the captured traffic (`pcap`), identifying the attacker's tactics, infrastructure, and malicious artifacts.

---

## 🔗 Cyber Kill Chain Mapping

| Stage | Activity Observed in Scenario |
| :--- | :--- |
| **1. Reconnaissance** | Gathering target information on Umbrella Corp's accounting staff (Sarah). |
| **2. Weaponization** | Embedding malicious VBA macros into an Office document to deliver Dridex. |
| **3. Delivery** | Sending a spear-phishing email disguised as a customer invoice to Sarah. |
| **4. Exploitation** | Execution of the malicious macro upon document open, resulting in an application crash. |
| **5. Installation** | Fetching initial executable (`MZ` header) and secondary `.rar` payload (`spet.rar`). |
| **6. Command & Control (C2)**| Establishing encrypted SSL/TLS C2 communication with `185.244.152.30`. |
| **7. Actions on Objectives**| Preparing for credential harvesting, financial espionage, and botnet propagation. |

---

## 🔎 Technical Investigation & Findings

### 1. Environment & Setup
* **PCAP File:** `traffic with dedex infection.pcap`
* **Analysis Tools Used:** Wireshark, Zui (Brim Data), VirusTotal, PowerShell.
* **Timestamp Calibration:** Time display set to **UTC** to standardize timeline tracking across SIEM logs.

### 2. Network Protocol & Traffic Breakdown
* Protocol hierarchy inspection indicated active **DNS**, **HTTP**, and **TLS/SSL** traffic.
* **Top Communicating IP Addresses:**
  1. `95.181.98.231` (Location: Russia) - Host of primary malware payload.
  2. `176.32.33.108` (Location: Russia) - Associated with malicious base64 data fetching.
  3. `185.244.152.30` - Identified as Dridex C2 server.

### 3. Payload Acquisition & File Artifacts
* **First Executable Download:**
  * **Packet Frame:** 6
  * **Port:** 80 (HTTP)
  * **Signature:** HTTP Stream revealed Windows executable header (`MZ` signature and string `This program cannot be run in DOS mode`).
* **Archive Download:**
  * **Packet Frame:** 911 (Time: 16:38:39 UTC)
  * **URL:** `http://95.181.98.231/.../spet.rar`
* **Image/Script Retrieval Domain:** `cato.com` (Flagged as malicious on VirusTotal).

### 4. IDS Alert Corroboration (Zui / Suricata)
Using Zui to process the PCAP file against Suricata and Zeke IDS signatures revealed immediate hits:
* **Alert Rule Match:** `ETPRO Malware.ch SSL Blacklist` & `Dridex / Urelas C2 detected`.
* **C2 Communication:** Confirmed active encrypted traffic between host `10.11.27.101` and C2 IP `185.244.152.30`.

### 5. File Hash Verification
Extracted objects via Wireshark (`Export Objects > HTTP`) and computed SHA-256 hashes using PowerShell:
* **Hash Check:** Tested against VirusTotal.
* **Result:** Malicious score **>60/70 detections**, categorized as **Trojan / Spyware (Dridex Family)**.

---

## 📊 Summary of Extracted Indicators (IoCs)

| Indicator Type | Value / Description |
| :--- | :--- |
| **Infected Host IP** | `10.11.27.101` |
| **Primary Payload URL** | `http://95.181.98.231/.../spet.rar` |
| **Suspicious Domain** | `cochrimato.com` |
| **Dridex C2 Server IP** | `185.244.152.30` |
| **Malware Category** | Dridex / Urelas Trojan |

---

## 🛡️ Recommended Remediation & Mitigation

1. **Host Isolation:** Immediately disconnect `10.11.27.101` from the network to prevent lateral movement.
2. **Block IoCs:** Add IP addresses `95.181.98.231`, `176.32.33.108`, and `185.244.152.30` as well as domain `cochrimato.com` to internal firewall and web gateway blocklists.
3. **Credential Reset:** Force a password reset for Sarah’s account and all credentials used on the host.
4. **Endpoint Inspection:** Run full EDR/AV scans, inspect Windows `Prefetch` (`C:\Windows\Prefetch`), and check `Amcache` logs.
5. **Security Awareness:** Conduct phishing awareness training focusing on macro-enabled documents.

---
