# Defensive Security Projects 🛡️

A collection of foundational defensive security tools and scripts built from scratch using Python, as part of a deep engineering journey into Blue Teaming, threat detection, and system hardening before advancing into AI Security.

## 🛠️ Included Projects:

1. **Log Monitoring System (Mini-SIEM):**
   - **Path:** `01-Log-Monitor-SIEM/`
   - **Description:** A lightweight, memory-efficient log monitoring script that reads server access logs in real-time using generators and pre-compiled regex.
   - **Capabilities:** Detects Brute-force login attempts and SQL Injection (SQLi) patterns, triggering automated defensive warnings and tracking malicious IPs.

2. **Web Application Firewall (Mini-WAF):**
   - **Path:** `02-Mini-WAF/`
   - **Description:** A middleware security guard built with Flask for web application protection.
   - **Capabilities:** Inspects incoming HTTP request URIs and POST/PUT/PATCH bodies against compiled attack signatures (such as XSS and Advanced SQLi), blocking malicious payloads with a `403 Forbidden` response.

3. **Network Intrusion Detection System (Mini-IDS):**
   - **Path:** `03-Mini-IDS/`
   - **Description:** A network packet sniffer built using Python and Scapy.
   - **Capabilities:** Monitors live TCP traffic to detect suspicious scanning behaviors (such as rapid Port Scanning/Reconnaissance) while optimizing memory usage and preventing log spamming.

---

## 🚀 Getting Started & Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/venomx943-pixel/Defensive-Security-Projects.git](https://github.com/venomx943-pixel/Defensive-Security-Projects.git)