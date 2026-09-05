\# VetClinic SOC Incident Investigation \& Threat Hunting Lab



!\[Wazuh](https://img.shields.io/badge/Wazuh-SIEM-005571?style=flat-square)

!\[Sysmon](https://img.shields.io/badge/Sysmon-Endpoint%20Telemetry-blue?style=flat-square)

!\[Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Ubuntu-orange?style=flat-square)

!\[Focus](https://img.shields.io/badge/Focus-SOC%20%7C%20Threat%20Hunting-red?style=flat-square)



\## Overview



This project documents a practical SOC investigation and threat-hunting lab built around a Windows 11 endpoint monitored by Wazuh.



The endpoint, `vetclinic-windows-01`, was instrumented with Microsoft Sysmon, Windows Security Event Logs and PowerShell Script Block Logging. Controlled security events were generated so that they could be detected, investigated, correlated and documented using a repeatable SOC workflow.



The project demonstrates:



\- Sysmon deployment and telemetry collection

\- PowerShell Event ID 4104 investigation

\- PowerShell Base64 decoding detection

\- Windows failed-logon investigation

\- Repeated failed-logon correlation

\- Account creation and deletion monitoring

\- Process creation analysis

\- Network telemetry analysis

\- Custom Wazuh detection engineering

\- MITRE ATT\&CK mapping

\- Evidence preservation

\- SIEM pipeline troubleshooting



All testing was conducted in an authorised personal laboratory environment.



\## Architecture



```mermaid

flowchart LR

&#x20;   A\[Windows 11 Endpoint] --> B\[Sysmon]

&#x20;   A --> C\[Windows Security Logs]

&#x20;   A --> D\[PowerShell Event 4104]



&#x20;   B --> E\[Wazuh Agent]

&#x20;   C --> E

&#x20;   D --> E



&#x20;   E --> F\[Wazuh Manager]



&#x20;   F --> G\[Threat Hunting]

&#x20;   F --> H\[Custom Detection Rules]



&#x20;   G --> I\[SOC Investigation]

&#x20;   H --> I

```



\## Investigation Highlights



\### 1. Sysmon Deployment



Microsoft Sysmon was installed and verified as running on the monitored Windows endpoint.



!\[Sysmon installed](screenshots/01-sysmon-installed-running.png)



The Wazuh agent was configured to collect events from the Sysmon Operational channel.



!\[Sysmon collection](screenshots/02-wazuh-sysmon-collection-configured.png)



Sysmon telemetry was then confirmed inside Wazuh Threat Hunting.



!\[Sysmon dashboard](screenshots/03-sysmon-threat-hunting-dashboard.png)



\### 2. Telemetry Pipeline Validation



A controlled test event was generated to confirm that endpoint telemetry travelled successfully from Sysmon through the Wazuh agent and into the SIEM.



!\[Pipeline test](screenshots/04-sysmon-pipeline-test-event.png)



This validated the endpoint-to-SIEM monitoring pipeline before additional investigation scenarios were performed.



\### 3. PowerShell Script Block Investigation



PowerShell Script Block Logging was enabled and Windows Event ID `4104` was successfully generated and collected.



!\[PowerShell 4104](screenshots/05-powershell-4104-events.png)



Event ID 4104 gives analysts visibility into PowerShell script content and is valuable when investigating suspicious or encoded command execution.



\### 4. PowerShell Base64 Detection



A controlled Base64 decoding test generated PowerShell telemetry.



Wazuh's existing PowerShell detection identified the activity, after which a custom rule was created to escalate it.



\*\*Custom rule:\*\* `100210`  

\*\*Severity:\*\* Level `12`



\*\*MITRE ATT\&CK\*\*



\- `T1059.001` — PowerShell

\- `T1140` — Deobfuscate/Decode Files or Information



!\[Base64 detection](screenshots/06-powershell-base64-custom-detection.png)



Base64 activity is not automatically malicious. During a real investigation, an analyst should correlate the event with the user, parent process, script content, network connections and surrounding endpoint activity.



\### 5. Failed Windows Logon Investigation



A controlled authentication failure generated Windows Security Event ID `4625`.



The event was investigated to identify the target account, authentication status and related Wazuh alert information.



!\[Failed logon user](screenshots/07a-failed-logon-user-details.png)



!\[Failed logon rule](screenshots/07b-failed-logon-rule-details.png)



A single authentication failure can be benign. Repeated failures against the same account may indicate password guessing, incorrect credentials or account misuse.



\### 6. Repeated Failed-Logon Correlation



Multiple failed authentication events were generated against the same account.



A custom Wazuh correlation rule was created to identify repeated failures occurring within a short period.



\*\*Custom rule:\*\* `100220`  

\*\*Severity:\*\* Level `12`  

\*\*Threshold:\*\* 5 failed logons within 60 seconds



\*\*MITRE ATT\&CK\*\*



\- `T1110.001` — Password Guessing



!\[Repeated failed logon](screenshots/08-repeated-failed-logon-custom-alert.png)



This converted several individually lower-context authentication events into a higher-priority alert suitable for SOC triage.



\### 7. Local Account Creation



A controlled local account named `VCSOC-AUDIT` was created.



Windows generated Security Event ID `4720`, which was collected and investigated in Wazuh.



!\[Account creation event](screenshots/09a-account-created-event-details.png)



!\[Account creation rule](screenshots/09b-account-created-rule-details.png)



The activity was mapped to:



\*\*MITRE ATT\&CK `T1098` — Account Manipulation\*\*



Unexpected account creation can indicate persistence, compromised administrative credentials or unauthorised system changes.



\### 8. Local Account Deletion



The controlled test account was removed after investigation.



Windows generated Security Event ID `4726`, and the deletion was also captured by Wazuh.



!\[Account deletion event](screenshots/10a-account-deleted-event-details.png)



!\[Account deletion rule](screenshots/10b-account-deleted-rule-details.png)



Monitoring both account creation and deletion provides visibility across the account lifecycle and can help identify attacker cleanup or unauthorised administrative activity.



\## Detection Engineering



The project includes two validated custom Wazuh detections:



| Rule | Detection | Level | MITRE ATT\&CK |

| --- | --- | ---: | --- |

| `100210` | PowerShell Base64 decoding | 12 | T1059.001, T1140 |

| `100220` | Repeated failed logons | 12 | T1110.001 |



The complete detection file is available here:



\[`detections/vetclinic\_soc\_rules.xml`](detections/vetclinic\_soc\_rules.xml)



\## Sysmon Process Investigation



A controlled PowerShell process launched `cmd.exe`, generating Sysmon Event ID `1`.



A unique marker was used to distinguish the controlled test from normal system activity.



Supporting evidence:



\[`evidence/sysmon-event1-process-test.txt`](evidence/sysmon-event1-process-test.txt)



The investigation demonstrated how parent-child process relationships and command-line telemetry can provide additional context during threat hunting.



\## Network Telemetry Investigation



Sysmon Event ID `3` recorded a PowerShell network connection from the Windows endpoint to the Wazuh server over TCP port `443`.



The event was verified in Wazuh archived telemetry.



Supporting evidence:



\[`evidence/sysmon-event3-archive-sample.json`](evidence/sysmon-event3-archive-sample.json)



One useful troubleshooting lesson from this test was that security telemetry passes through several stages:



```text

Endpoint → Agent → Decoder → Archive → Rule → Alert → Dashboard

```



An event can therefore reach the SIEM even when it does not generate a visible dashboard alert. Checking the raw telemetry helped distinguish an alerting limitation from a collection failure.



\## Investigation Timeline



| Stage | Activity |

| --- | --- |

| 1 | Sysmon installed and validated |

| 2 | Wazuh Sysmon collection configured |

| 3 | Endpoint telemetry confirmed |

| 4 | PowerShell Event ID 4104 validated |

| 5 | Base64 activity generated and detected |

| 6 | Custom rule 100210 triggered |

| 7 | Failed authentication investigated |

| 8 | Repeated failures correlated |

| 9 | Custom rule 100220 triggered |

| 10 | Local account creation investigated |

| 11 | Local account deletion investigated |

| 12 | Process and network telemetry analysed |



\## Skills Demonstrated



\- SOC alert triage

\- Wazuh SIEM

\- Microsoft Sysmon

\- Windows Security Event Logs

\- PowerShell Script Block Logging

\- Detection engineering

\- SIEM correlation rules

\- Threat hunting

\- Authentication investigation

\- Account-management monitoring

\- Process analysis

\- Network telemetry analysis

\- MITRE ATT\&CK mapping

\- Evidence preservation

\- Incident reconstruction

\- SIEM pipeline troubleshooting

\- Security documentation



\## Repository Structure



```text

vetclinic-soc-investigation-lab/

├── README.md

├── detections/

│   ├── sysmon-vetclinic.xml

│   └── vetclinic\_soc\_rules.xml

├── docs/

│   └── incident-investigation-report.md

├── evidence/

│   ├── account-created-4720-local.txt

│   ├── account-deleted-4726-local.txt

│   ├── failed-logon-4625-local.txt

│   ├── powershell-4104-local-verification.txt

│   ├── powershell-base64-test.txt

│   ├── repeated-failed-logons-local.txt

│   ├── sysmon-event1-process-test.txt

│   ├── sysmon-event3-archive-sample.json

│   └── additional verification files

└── screenshots/

&#x20;   ├── 01-sysmon-installed-running.png

&#x20;   ├── 02-wazuh-sysmon-collection-configured.png

&#x20;   ├── 03-sysmon-threat-hunting-dashboard.png

&#x20;   ├── 04-sysmon-pipeline-test-event.png

&#x20;   ├── 05-powershell-4104-events.png

&#x20;   ├── 06-powershell-base64-custom-detection.png

&#x20;   ├── 07a-failed-logon-user-details.png

&#x20;   ├── 07b-failed-logon-rule-details.png

&#x20;   ├── 08-repeated-failed-logon-custom-alert.png

&#x20;   ├── 09a-account-created-event-details.png

&#x20;   ├── 09b-account-created-rule-details.png

&#x20;   ├── 10a-account-deleted-event-details.png

&#x20;   └── 10b-account-deleted-rule-details.png

```



\## Full Incident Report



A more detailed investigation report containing analyst observations, evidence, response recommendations and limitations is available here:



\[`docs/incident-investigation-report.md`](docs/incident-investigation-report.md)



\## Limitations and Future Improvements



This is a controlled single-endpoint laboratory rather than a production enterprise SOC.



The suspicious activity was deliberately generated for defensive-security testing and did not involve malware, real patient records or unauthorised third-party infrastructure.



Future improvements could include multiple monitored endpoints, DNS and firewall telemetry, EDR integration, automated alert enrichment, case-management integration and additional ATT\&CK detection scenarios.



\## Ethical Statement



All activity documented in this repository was performed on systems owned and authorised by the project creator. Test accounts, records and events were intentionally simulated for defensive-security training.

