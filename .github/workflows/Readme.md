# Network Scanner

Network Scanner is a Python-based cybersecurity and network monitoring tool that discovers devices on a local network, scans open ports, analyzes security risks, identifies vendors using MAC addresses, and generates downloadable reports through a Flask web dashboard.

---

# Features

## Device Discovery
- Detect active devices on local network
- Scan subnet automatically
- Display:
  - IP Address
  - Hostname
  - MAC Address
  - Vendor
  - Latency
  - Device Status

---

## Port Scanning
- Multi-threaded TCP port scanning
- Detect open ports
- Identify running services
- Banner grabbing support

Supported Services:
- HTTP
- HTTPS
- SSH
- SMTP
- DNS
- SMB
- FTP
- MySQL
- RDP
- Redis
- PostgreSQL
- And more

---

## AI Risk Assessment
Analyzes detected open ports and calculates:
- Risk Score
- Threat Level
- Security Recommendations

Threat Levels:
- LOW
- MEDIUM
- HIGH
- CRITICAL

---

## Vendor Detection
Detect device manufacturers using MAC address prefixes.

Examples:
- Lenovo
- Raspberry Pi
- Cisco
- TP-Link
- Dell
- Intel

---

## PDF Report Generation
Generate downloadable scan reports containing:
- Device information
- Open ports
- Risk analysis
- Threat levels

---

# Technologies Used

## Backend
- Python
- Flask

## Frontend
- HTML
- CSS
- JavaScript

## Networking
- socket
- subprocess
- concurrent.futures
- ipaddress

---

# Project Architecture

```text
AI Network Scanner
│
├── app.py
│
├── scanner/
│   ├── discovery.py
│   ├── portscanner.py
│   ├── risk_engine.py
│   ├── report_generator.py
│   └── history_manager.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── app.js
│
├── reports/
│
├── macvendors.txt
│
└── README.md