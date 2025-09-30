Network-Packet-Sniffing-and-Analysis
 Objective
The goal of this project is to capture and analyze live network traffic using Wireshark to identify sensitive data such as credentials or detect suspicious activity. This project demonstrates how network sniffing tools can expose vulnerabilities in unencrypted traffic and helps understand network-level security risks.

---
 Tools & Environment
Wireshark – for capturing and analyzing network packets.
Operating System: Kali Linux (or any Linux/Windows OS with network access)
Network Interface:eth0 / wlan0 (or any active interface)
Protocols Analyzed: HTTP, TCP, DNS, ARP
 1. Setup and Capture
- Installed and launched Wireshark.
- Selected the active network interface and started live capture.
- Generated some test network traffic (e.g., web browsing, login attempts, HTTP requests).
2. Applying Filters
- Used Wireshark display filters to focus on suspicious or sensitive traffic:
  - `http.request`
  - `ip.addr == <target IP>`
  - `http.request.method == "POST"`
  - `frame contains "password"`
 3. Analyzing Traffic
- Followed TCP streams to reconstruct communication between client and server.
- Identified any plaintext credentials transmitted over HTTP.
- Exported relevant packets and HTTP objects for further analysis.
 4. Evidence Collection
- Saved captured traffic as `capture_evidence.pcap`.
- Took screenshots of filtered traffic and credential findings.
- Exported sensitive POST data into text files for reporting.
Finding 1: Plaintext Credentials Detected
- Description:Detected a POST request containing `username` and `password` parameters in plaintext over HTTP.
- Severity: High
- Evidence: 
  - Packet No: 245
  - File: `capture/capture_evidence.pcap`
  - Screenshot: `screenshots/03_credentials_detected.png`
- Recommendation: Always use HTTPS to encrypt communication and protect user credentials.
Finding 2: Unencrypted Session Cookies
- Description: Cookies transmitted without `Secure` or `HttpOnly` flags.
- Severity:Medium
- Recommendation:Enable secure cookie flags and enforce HTTPS.

 Deliverables
- `capture/capture_evidence.pcap`
- `analysis_report.pdf`
- `screenshots/`
- `exports/`
 Outcome
- Learned to use Wireshark for packet sniffing and traffic analysis.
- Discovered how unencrypted HTTP traffic can leak sensitive credentials.
- Understood network-level risks and importance of encryption.
