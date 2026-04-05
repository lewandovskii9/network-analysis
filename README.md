# SOC Network Analysis Portfolio

Aspiring SOC Analyst focused on network traffic analysis and incident investigation.  
This repository contains a series of PCAP analysis write-ups. As the series progresses, the write-ups demonstrate increasing depth, improved methodology, and a more professional approach to incident investigation, reflecting my growth in SOC-style reporting and malware analysis.

---

## 🛠 Technical Stack

* Network traffic analysis (Wireshark)
* Malware infection detection
* IOC extraction & enrichment
* Timeline reconstruction
* Basic incident response

---

## Tools & Techniques

* Wireshark (packet analysis, stream inspection)
* VirusTotal (hash & IOC validation)
* TCP stream / HTTP object analysis
* NBNS, Kerberos, DNS investigation

---

## 📁 Investigation Cases

This section contains all network traffic analysis write-ups. As the series progresses, later write-ups demonstrate more thorough methodology, clearer evidence presentation, and a more professional reporting style.

| #  | Case                                                        | Key Findings                                              | Malware |
| -- | ----------------------------------------------------------- | --------------------------------------------------------- | ------- |
| 01 | [Dridex Infection](./wireshark/dridex-infection/writeup.md) | Malicious HTTP download → PE file execution → C2 over TLS | Dridex  |
| 02 | [Trickbot & IcedID Infection](./wireshark/trickbot-icedid-infection/writeup.md) | 6 executables disguised as images → dual infection | Trickbot, IcedID |
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

* LinkedIn: <your link>

---

## ⚠️ Disclaimer

All PCAP files are sourced from publicly available malware analysis platforms and used strictly for educational purposes.

