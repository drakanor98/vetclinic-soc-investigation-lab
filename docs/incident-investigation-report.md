# VetClinic SOC Incident Investigation Report

## Executive Summary

This project simulates the investigation of suspicious activity on a Windows 11 endpoint in a fictional veterinary-clinic environment.

The endpoint, `vetclinic-windows-01`, was monitored using Wazuh, Windows Security Event Logs, PowerShell Script Block Logging, Microsoft Defender telemetry, and Sysmon.

Controlled security events were generated to test detection and investigation workflows. The investigation identified PowerShell Base64 decoding activity, repeated failed authentication attempts, local account creation and deletion, suspicious parent-child process activity, and Sysmon network telemetry.

Two custom Wazuh detection rules were engineered and validated:

- Rule `100210` — PowerShell Base64 decoding, severity level 12.
- Rule `100220` — repeated failed Windows logons for the same account, severity level 12.

All tests were performed on an authorised personal lab. No malware, production systems, real patient records, or third-party infrastructure were used.

---

## 1. Investigation Scope

### Monitored endpoint

- Host: Windows 11 Pro
- Wazuh agent: `vetclinic-windows-01`
- SIEM: Wazuh
- Endpoint telemetry: Sysmon
- PowerShell logging: Script Block Logging / Event ID 4104
- Windows authentication logging: Security Event Log
- Virtualisation: Microsoft Hyper-V

### Investigation objectives

The investigation was designed to:

1. Validate Sysmon telemetry ingestion.
2. Investigate PowerShell activity.
3. Detect encoded or decoded PowerShell content.
4. Investigate failed Windows authentication.
5. Detect repeated failed-logon behaviour.
6. Investigate local account creation and deletion.
7. Analyse process-creation telemetry.
8. Review network-connection telemetry.
9. Map relevant activity to MITRE ATT&CK.
10. Preserve evidence suitable for SOC reporting.

---

## 2. Evidence Collection

Evidence was retained in three forms:

- Wazuh screenshots showing alerts and event details.
- Local Windows event-verification files.
- Raw Wazuh/Sysmon telemetry exported for analysis.

The evidence directory contains verification records for PowerShell, authentication, Sysmon process creation, network connections, and account-management events.

---

## 3. Investigation Finding: Sysmon Telemetry

Sysmon was installed and verified as running on the Windows endpoint.

Wazuh was configured to collect events from:

`Microsoft-Windows-Sysmon/Operational`

Process-creation and other Sysmon events subsequently appeared in Wazuh Threat Hunting, confirming that endpoint telemetry was reaching the SIEM.

### Evidence

- `01-sysmon-installed-running.png`
- `02-wazuh-sysmon-collection-configured.png`
- `03-sysmon-threat-hunting-dashboard.png`
- `04-sysmon-pipeline-test-event.png`

### Security significance

Sysmon provides detailed endpoint visibility beyond standard Windows logs, including process creation, parent-child relationships, command lines, hashes, and network activity.

---

## 4. Investigation Finding: PowerShell Script Block Activity

PowerShell Script Block Logging was enabled and validated locally.

Windows Event ID `4104` was successfully generated and ingested by Wazuh.

### Evidence

- `05-powershell-4104-events.png`
- `evidence\powershell-4104-local-verification.txt`

### Security significance

PowerShell is widely used for legitimate administration but can also be abused for execution, discovery, credential access, persistence, and defence evasion.

Capturing Event ID 4104 provides analysts with visibility into executed PowerShell script content.

---

## 5. Investigation Finding: PowerShell Base64 Decoding

A controlled PowerShell Base64 decoding test generated Event ID 4104.

Wazuh's built-in PowerShell detection identified the decoding behaviour. A custom detection rule was then created to escalate the activity.

### Custom detection

- Rule ID: `100210`
- Severity: `12`
- Parent rule: `91809`
- Description: `VetClinic SOC: PowerShell Base64 decoding activity detected.`

### MITRE ATT&CK mapping

- `T1059.001` — PowerShell
- `T1140` — Deobfuscate/Decode Files or Information

### Evidence

- `06-powershell-base64-custom-detection.png`
- `evidence\powershell-base64-test.txt`
- `detections\vetclinic_soc_rules.xml`

### Analyst assessment

Base64 decoding is not inherently malicious, but it is frequently associated with obfuscated PowerShell activity. Analysts should correlate the event with the user, parent process, command line, network activity, and surrounding endpoint events before determining intent.

---

## 6. Investigation Finding: Failed Windows Logon

A controlled failed authentication attempt generated Windows Security Event ID `4625`.

Wazuh detected the event and identified it as an authentication failure.

Investigation of the event exposed fields including the target username, logon type, status code, and sub-status code.

### Evidence

- `07a-failed-logon-user-details.png`
- `07b-failed-logon-rule-details.png`
- `evidence\failed-logon-4625-local.txt`

### Observed test account

`VETCLINIC-SOC-TEST`

### Security significance

A single failed logon may be benign. Multiple failures against the same account within a short period can indicate password guessing, brute-force activity, incorrect service credentials, or account misuse.

---

## 7. Investigation Finding: Repeated Failed Logons

A correlation rule was created to detect repeated failed Windows authentication events targeting the same account.

### Custom detection

- Rule ID: `100220`
- Severity: `12`
- Frequency: `5`
- Timeframe: `60 seconds`
- Parent rule: `60122`

The rule correlates failed-logon events using the target username.

### MITRE ATT&CK mapping

- `T1110.001` — Password Guessing

### Evidence

- `08-repeated-failed-logon-custom-alert.png`
- `evidence\repeated-failed-logons-local.txt`
- `detections\vetclinic_soc_rules.xml`

### Analyst assessment

Repeated authentication failures should be reviewed against source host, target account, logon type, timing, asset criticality, and any subsequent successful authentication.

---

## 8. Investigation Finding: Local Account Creation

A controlled local Windows account named:

`VCSOC-AUDIT`

was created to test account-management monitoring.

Windows generated Security Event ID `4720`, which was ingested by Wazuh.

The Wazuh alert mapped the activity to MITRE ATT&CK Account Manipulation.

### MITRE ATT&CK mapping

- `T1098` — Account Manipulation
- Tactic: Persistence

### Evidence

- `09a-account-created-event-details.png`
- `09b-account-created-rule-details.png`
- `evidence\account-created-4720-local.txt`

### Security significance

Unexpected local account creation may indicate persistence, privilege misuse, compromised administrative credentials, or unauthorised system changes.

---

## 9. Investigation Finding: Local Account Deletion

The test account was removed after investigation.

Windows generated Security Event ID `4726`, and the account-deletion activity was captured by Wazuh.

### Evidence

- `10a-account-deleted-event-details.png`
- `10b-account-deleted-rule-details.png`
- `evidence\account-deleted-4726-local.txt`

### Analyst assessment

Account deletion can be part of legitimate administration, but unexpected deletion may also indicate attacker cleanup, account manipulation, insider activity, or attempts to remove evidence of persistence.

---

## 10. Investigation Finding: Process Creation

A controlled PowerShell process launched `cmd.exe`, generating Sysmon Event ID `1`.

The test used a unique marker to distinguish the controlled event from normal endpoint activity.

Wazuh identified the parent-child process relationship.

### Evidence

- `evidence\sysmon-event1-process-test.txt`

### Security significance

Parent-child process relationships are valuable during threat hunting. For example, unusual command shells spawned by scripting engines, Office applications, browsers, or service processes can warrant further investigation.

---

## 11. Investigation Finding: Network Telemetry

Sysmon Event ID `3` captured a PowerShell network connection from the Windows endpoint to the Wazuh server over TCP port 443.

The event was verified in Wazuh's archived telemetry.

### Evidence

- `evidence\sysmon-event3-archive-sample.json`
- `evidence\sysmon-network-connection-local.txt`

### Investigation lesson

During testing, Sysmon Event ID 3 was confirmed at the telemetry and archive layer even though it did not surface in the normal alert view used for the other detections.

This demonstrated an important SOC troubleshooting principle: absence of a dashboard alert does not automatically mean telemetry was not collected.

Analysts should validate each stage of the logging pipeline:

Endpoint → Agent → Decoder → Archive → Rule → Alert → Dashboard.

---

## 12. Incident Timeline

| Stage | Activity | Evidence |
| --- | --- | --- |
| 1 | Sysmon installed and validated | Screenshots 01–04 |
| 2 | PowerShell Script Block Logging validated | Screenshot 05 |
| 3 | Base64 decoding generated and detected | Screenshot 06 |
| 4 | Failed Windows authentication investigated | Screenshots 07a–07b |
| 5 | Repeated failed logons correlated | Screenshot 08 |
| 6 | Local account created | Screenshots 09a–09b |
| 7 | Local account removed | Screenshots 10a–10b |
| 8 | Sysmon process creation analysed | Raw evidence |
| 9 | Sysmon network telemetry validated | Raw archive evidence |

---

## 13. Detection Engineering Summary

| Rule | Detection | Severity | ATT&CK |
| --- | --- | ---: | --- |
| 100210 | PowerShell Base64 decoding | 12 | T1059.001, T1140 |
| 100220 | Multiple failed logons against the same account | 12 | T1110.001 |

Both custom detections are stored in:

`detections/vetclinic_soc_rules.xml`

---

## 14. Recommended SOC Response

For suspicious PowerShell activity:

1. Identify the user and parent process.
2. Review the complete script block.
3. Check command-line arguments and encoded content.
4. Correlate nearby Sysmon process and network events.
5. Review Defender detections.
6. Determine whether the activity was authorised.
7. Escalate or contain the endpoint if malicious behaviour is suspected.

For repeated authentication failures:

1. Identify the target account.
2. Determine the source host.
3. Review logon type and failure codes.
4. Check for subsequent successful authentication.
5. Determine whether the account is privileged.
6. Investigate related account changes.
7. Reset credentials or isolate affected assets where necessary.

For unexpected account creation:

1. Confirm who created the account.
2. Review administrative logons.
3. Check group membership and privileges.
4. Determine whether the change was authorised.
5. Review surrounding PowerShell and process activity.
6. Disable or remove unauthorised accounts.
7. Preserve relevant logs.

---

## 15. Skills Demonstrated

This investigation demonstrates practical experience with:

- Wazuh SIEM
- Microsoft Sysmon
- Windows Event Logs
- PowerShell Script Block Logging
- Threat hunting
- Detection engineering
- SIEM correlation rules
- Windows authentication investigation
- Account-management monitoring
- Process analysis
- Network telemetry analysis
- MITRE ATT&CK mapping
- Evidence preservation
- Incident timeline reconstruction
- Alert triage
- SOC troubleshooting
- Security documentation

---

## 16. Limitations

This was a controlled single-endpoint laboratory rather than a production enterprise environment.

The simulated events were intentionally generated and therefore do not represent a real compromise.

A larger implementation would include multiple endpoints, identity-provider logs, DNS telemetry, firewall data, EDR telemetry, central case management, and automated alert enrichment.

---

## Conclusion

The project demonstrates an end-to-end SOC workflow rather than only SIEM installation.

Security telemetry was generated on a Windows endpoint, transported into Wazuh, analysed, correlated, mapped to MITRE ATT&CK, preserved as evidence, and used to create custom detections.

The investigation also demonstrated troubleshooting at different stages of the SIEM pipeline when a Sysmon network event was present in archived telemetry but did not surface through the normal alert workflow.

The resulting lab provides practical evidence of Windows security monitoring, threat hunting, detection engineering, incident investigation, and SOC reporting skills.
