Azure Honeypot Monitored with Microsoft Sentinel
Azure Honeypot with Microsoft Sentinel

Overview

Built a Windows honeypot in Azure to detect and log brute-force RDP attacks using Microsoft Sentinel.

This project simulates a real-world attacker environment where malicious activity is logged, monitored, and analyzed through Sentinel using KQL. It demonstrates log ingestion, event analysis, and detection engineering.

Architecture

Kali Attacker
     ⬇
Azure Windows Honeypot VM
     ⬇
Log Analytics Workspace
     ⬇
Microsoft Sentinel

☁️ Azure Setup

VM OS: Windows Server 2019 Datacenter

VM Size: B1s

Public IP: 74.249.xx.xx

NSG Configuration

Inbound Rules Added:

3389 (TCP) - RDP

445 (TCP) - SMB

139 (TCP) - NetBIOS

135 (TCP) - RPC

80 (TCP) - HTTP

✉️ Screenshot: docs/screenshots/nsg-settings.png

🔒 Windows Firewall Configuration

Enabled or created inbound rules for:

Remote Desktop (TCP-In)

File and Printer Sharing (SMB-In)

Windows Remote Management (HTTP-In)

World Wide Web Services (HTTP Traffic-In)

✉️ Screenshot: docs/screenshots/firewall-rules.png

✨ Microsoft Sentinel Setup

Created Log Analytics Workspace

Installed MMA agent with workspace ID + key

Enabled Security Events via Legacy Agent connector

VM selected

All events enabled

✉️ Screenshot: docs/screenshots/sentinel-connector.png

🔢 KQL Queries Used

Failed Login Detection:

SecurityEvent
| where EventID == 4625
| order by TimeGenerated desc

Brute-Force Detection:

SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedAttempts = count() by TargetUserName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3

✉️ Screenshot: docs/screenshots/4625-query-results.png

🛡️ Manual Traffic Simulation

Used .rdp file to attempt multiple failed logins with wrong passwords

Optional tools used:

nmap -Pn <VM_IP>

hydra -l Administrator -P passlist.txt rdp://<VM_IP>

✉️ Screenshot: docs/screenshots/rdp-attempt.png
✉️ Screenshot: docs/screenshots/nmap-scan.png

🔐 Detection Rule (Optional)

Name: RDP Brute-Force DetectionKQL:

SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedAttempts = count() by TargetUserName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3

Runs every 5 min

Alerts if results > 0

✉️ Screenshot: docs/screenshots/detection-rule.png
✉️ Screenshot: docs/screenshots/incident-alert.png

✅ Outcome

Successfully simulated brute-force login behavior

Captured logs in Microsoft Sentinel

Confirmed real-time log ingestion and alerting via KQL

Demonstrated hands-on detection logic using free Azure tools

🔧 Skills Demonstrated

Microsoft Sentinel setup

Log Analytics workspace configuration

KQL for event hunting and detection

Windows firewall and NSG hardening

Simulating threat actor behavior

Building cloud-based honeypots
