\# VetClinic SOC Incident Investigation \& Threat Hunting Lab



!\[Wazuh](https://img.shields.io/badge/Wazuh-SIEM-005571?style=flat-square)

!\[Sysmon](https://img.shields.io/badge/Sysmon-Endpoint%20Telemetry-blue?style=flat-square)

!\[Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Ubuntu-orange?style=flat-square)

!\[Focus](https://img.shields.io/badge/Focus-SOC%20%7C%20Threat%20Hunting-red?style=flat-square)



\## Overview



This project demonstrates a practical SOC investigation workflow using \*\*Wazuh, Microsoft Sysmon, Windows Security Event Logs and PowerShell Script Block Logging\*\*.



A Windows 11 endpoint named `vetclinic-windows-01` was monitored while controlled suspicious activity was generated and investigated.



The project covers:



\- Sysmon deployment and telemetry collection

\- PowerShell Event ID 4104 investigation

\- Base64 PowerShell detection

\- Failed-logon analysis

\- Repeated failed-logon correlation

\- Windows account creation and deletion monitoring

\- Sysmon process analysis

\- Network telemetry validation

\- MITRE ATT\&CK mapping

\- Detection engineering

\- Evidence preservation

\- SIEM pipeline troubleshooting



All testing was performed in an authorised personal lab.



\---



\## Architecture



```mermaid

flowchart LR

&#x20;   A\["Windows 11 Endpoint"] --> B\["Sysmon"]

&#x20;   A --> C\["Windows Security Logs"]

&#x20;   A --> D\["PowerShell 4104"]

&#x20;   B --> E\["Wazuh Agent"]

&#x20;   C --> E

&#x20;   D --> E

&#x20;   E --> F\["Wazuh Manager"]

&#x20;   F --> G\["Wazuh Threat Hunting"]

&#x20;   F --> H\["Custom Detection Rules"]

&#x20;   G --> I\["SOC Investigation"]

&#x20;   H --> I

