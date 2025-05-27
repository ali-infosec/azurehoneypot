Azure Honeypot Monitored with Microsoft Sentinel

Overview

Built a Windows honeypot in Azure to detect and log brute-force RDP attacks using Microsoft Sentinel.

This project simulates a real-world attacker environment where malicious activity is logged, monitored, and analyzed through Sentinel using KQL. It demonstrates log ingestion, event analysis, and detection engineering.

Architecture

Kali Attacker
    
Azure Windows Honeypot VM
     
Log Analytics Workspace
    
Microsoft Sentinel

Azure Setup

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

[NSG Rules](docs/screenshots/NSG_Rules.png)

Windows Firewall Configuration

Enabled or created inbound rules for:

Remote Desktop (TCP-In)

File and Printer Sharing (SMB-In)

Windows Remote Management (HTTP-In)

World Wide Web Services (HTTP Traffic-In)

[Firewall Rules](docs/screenshots/Firewall-Rules.png)

Microsoft Sentinel Setup

Created Log Analytics Workspace

Installed MMA agent with workspace ID + key

Enabled Security Events via Legacy Agent connector

VM selected

All events enabled

[Sentinel Connector](docs/screenshots/Sentinel-Connector.png)

KQL Queries Used

Failed Login Detection:

SecurityEvent
| where EventID == 4625
| order by TimeGenerated desc

[Traffic of Failed Logins](docs/screenshots/Failed-Login-Detection.png)

Brute-Force Detection:

SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedAttempts = count() by TargetUserName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3

[Detected Brute-Force Traffic](docs/screenshots/Bruteforce-Results.png)

Detection Rules

Name: RDP Brute-Force DetectionKQL:

SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedAttempts = count() by TargetUserName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3

Runs every 5 min

Alerts if results > 0

Outcome

Successfully simulated brute-force login behavior

Captured logs in Microsoft Sentinel

Confirmed real-time log ingestion and alerting via KQL

Demonstrated hands-on detection logic using Azure tools

Skills Demonstrated

Microsoft Sentinel setup

Log Analytics workspace configuration

KQL for event hunting and detection

Windows firewall and NSG hardening

Capturing threat actor behavior

Building cloud-based honeypots
