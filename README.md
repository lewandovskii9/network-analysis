# Network Analysis 

*Aspiring SOC Analyst focused on network traffic analysis and incident investigation.  
This repository contains a series of PCAP analysis write-ups. As the series progresses, the write-ups demonstrate increasing depth, improved methodology, and a more professional approach to incident investigation, reflecting my growth in SOC-style reporting and malware analysis.*

---

## 🛠 Technical Stack

* **Network Traffic Analysis:** Deep packet inspection and stream reconstruction.
* **Malware Detection:** Identifying infection vectors and C2 communication.
* **IOC Extraction:** Harvesting and enriching indicators from network data.
* **Timeline Reconstruction:** Building chronological maps of security incidents.
* **Incident Response:** Applying basic triage and forensics to PCAP files.

---

## 🔧 Tools & Techniques

* **Wireshark** (packet analysis, stream inspection)
* **VirusTotal** (hash & IOC validation)
* **TCP stream / HTTP object analysis**
* **NBNS, Kerberos, DNS** investigation
* [**Wireshark filtration commands**](./cheatsheets/wireshark.md)

---

## 📁 Investigation Cases

This section contains all network traffic analysis write-ups. As the series progresses, later write-ups demonstrate more thorough methodology, clearer evidence presentation, and a more professional reporting style.

| #  | Case                                                        | Key Findings                                              | Malware |
| -- | ----------------------------------------------------------- | --------------------------------------------------------- | ------- |
| 01 | [Dridex Infection](./wireshark/dridex-infection/writeup.md) | Malicious HTTP download → PE file execution → C2 over TLS | Dridex  |
| 02 | [Trickbot & IcedID Infection](./wireshark/trickbot-icedid-infection/writeup.md) | 6 executables disguised as images → dual infection | Trickbot, IcedID |
| 03 | [Cridex/Dridex, Remcos RAT Infection](./wireshark/dridex-remcos-withLaterMovement-infection/writeup.md) | Multi-stage PE download → Remcos RAT C2 → Dridex post-exploitation | Dridex, Remcos  |
---

## 🔍 What Each Case Includes

* Identification of infected host
* Malware delivery analysis
* Extracted IOCs (IP, URL, hash)
* Network-based evidence (Wireshark)
* Attack timeline reconstruction
* Final incident verdict

---

## 🚩 Current Objectives

* Expanding malware traffic analysis cases
* Improving detection logic & reasoning
* Studying real-world SOC workflows

---

## 📜 Certifications

* CompTIA Security+ (expected August 2026)

---

## 📬 Contact

* LinkedIn: [Me](https://www.linkedin.com/in/aldiyar-bulat-194478403/)

---

## ⚠️ Disclaimer

All PCAP files are sourced from publicly available malware analysis platforms and used strictly for educational purposes.

---
*Return to [Main Portfolio](https://github.com/lewandovskii9)*
