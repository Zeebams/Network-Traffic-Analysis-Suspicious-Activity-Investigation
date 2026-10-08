# Network Traffic Analysis & Suspicious Activity Investigation

## Project Overview

This project involved analyzing a network packet capture (PCAP) using Wireshark to investigate suspicious network activity reported within a controlled lab environment.

The investigation focused on identifying communicating hosts, analyzing network protocols, investigating DNS and HTTP activity, examining a Telnet session, extracting indicators of interest (IOCs), and determining whether the captured traffic indicated potentially unauthorized remote access.

The analysis was performed using the publicly available `dns-remoteshell.pcap` sample capture from the Wireshark Sample Captures collection.

> **Note:** This project uses a public PCAP dataset in a controlled analysis environment. No live systems were accessed or tested during the investigation.

---

## Scenario

A SOC analyst received a network monitoring alert indicating potentially suspicious communication between systems on an internal network.

The analyst was provided with a packet capture containing traffic surrounding the suspected activity.

The objective was to determine:

* Which systems communicated with each other
* What protocols were used
* Whether suspicious or unauthorized activity occurred
* What commands or activity were observed
* Which IP addresses and domains could be considered indicators of interest
* The potential security impact
* Appropriate containment and remediation actions

---

## Tools Used

* Wireshark
* Public PCAP dataset
* TCP/IP protocol analysis
* DNS analysis
* HTTP analysis
* Telnet/TCP stream analysis
* MITRE ATT&CK framework

---

# 1. PCAP Overview

The packet capture contained:

* **131 total packets**
* **Internal hosts:**

  * `192.168.1.2`
  * `192.168.1.3`
  * `192.168.1.1`
* **External hosts observed:**

  * `83.170.75.178`
  * `205.227.136.203`
  * `140.112.253.189`

### Protocols observed

* ARP
* DNS
* TCP
* HTTP
* SSLv3
* TELNET

The presence of Telnet traffic warranted further investigation because Telnet provides interactive remote terminal access and is generally considered insecure compared with encrypted remote administration protocols.


---

# 2. Host Identification

The IPv4 endpoint analysis identified the following hosts:

| IP Address        | Packets | Initial Observation    |
| ----------------- | ------: | ---------------------- |
| `192.168.1.2`     |     118 | Active internal host   |
| `192.168.1.3`     |     110 | Active internal host   |
| `192.168.1.1`     |       6 | Local network/DNS host |
| `83.170.75.178`   |      10 | External host          |
| `205.227.136.203` |       3 | External host          |
| `140.112.253.189` |       1 | External host          |

The investigation focused primarily on the communication involving `192.168.1.2` and `192.168.1.3`.

---

# 3. DNS Analysis

DNS traffic was identified between:

`192.168.1.3 → 192.168.1.1`

Six DNS packets were observed.

The DNS queries included:

* `www.www.com`
* `www.www.com.lan`

The queries were identified as:

* **Type:** A
* **Class:** IN

The DNS traffic itself did not provide sufficient evidence to classify either domain as malicious. Therefore, the domains were documented as indicators of interest rather than confirmed malicious indicators.


---

# 4. HTTP Traffic Analysis

The investigation identified HTTP communication between:

`192.168.1.2 ↔ 83.170.75.178`

A total of approximately 10 packets were associated with this communication.

The HTTP traffic included:

* HTTP GET request
* `HTTP/1.1 304 Not Modified` response

A TCP connection was initiated by:

`192.168.1.2 → 83.170.75.178`

The HTTP activity demonstrates communication between the internal host and an external system.

However, the available packet evidence does **not** establish that the external host was malicious or that it directly caused the Telnet activity. Therefore, `83.170.75.178` is treated as an external host of interest rather than a confirmed malicious IOC.

---

# 5. Telnet Investigation

The most significant finding in the investigation was a Telnet session between two internal hosts.

The communication occurred between:

`192.168.1.3:1403 → 192.168.1.2:23`

TCP port **23** is the standard Telnet service port.

The initial TCP handshake was observed:

```text
192.168.1.3:1403 → 192.168.1.2:23    SYN
192.168.1.2:23 → 192.168.1.3:1403    SYN, ACK
192.168.1.3:1403 → 192.168.1.2:23    ACK
```

This confirms that a TCP connection was successfully established.


---

# 6. Telnet Command Shell Analysis

The Telnet TCP stream revealed an interactive Windows XP command shell.

The captured session displayed:

```text
Microsoft Windows XP [Version 5.1.2600]

C:\>
```

The following commands were observed:

```text
dir
ls -la
exit
```

The `dir` command successfully returned the directory contents of the Windows system.

The `ls -la` command failed because it is a Unix/Linux command and is not recognized by Windows XP.

The session was subsequently terminated using:

```text
exit
```


---

# 7. Suspicious Activity Assessment

The successful Telnet session represents the most significant security finding in the capture.

The evidence demonstrates:

1. An internal host (`192.168.1.3`) initiated a connection to another internal host (`192.168.1.2`) on TCP port 23.
2. The Telnet connection successfully completed the TCP handshake.
3. The session provided an interactive Windows XP command shell.
4. Commands were successfully executed on the remote system.
5. Directory information was returned to the initiating host.

This indicates **interactive remote access over Telnet**.

However, the capture does not provide sufficient evidence to determine whether the activity was authorized administrative activity or malicious access.

There was also no observed evidence in the Telnet stream of:

* Malware download
* File deletion
* Persistence
* Privilege escalation
* Credential theft
* Data exfiltration
* Additional payload execution

Therefore, the incident is classified as:

> **Suspicious Remote Access / Potential Unauthorized Telnet Activity**

rather than confirmed malware compromise.

---

# 8. Indicators of Interest

| Indicator         | Type         | Observation                           | Classification                    |
| ----------------- | ------------ | ------------------------------------- | --------------------------------- |
| `192.168.1.3`     | Internal IP  | Initiated Telnet session              | Host of interest                  |
| `192.168.1.2`     | Internal IP  | Received Telnet connection            | Host of interest                  |
| `83.170.75.178`   | External IP  | HTTP communication with `192.168.1.2` | External host of interest         |
| `www.www.com`     | Domain       | DNS query from `192.168.1.3`          | Domain of interest                |
| `www.www.com.lan` | Domain       | DNS query from `192.168.1.3`          | Domain of interest                |
| TCP/23            | Service/Port | Telnet communication                  | Suspicious/insecure remote access |

> **IOC classification note:** The IP addresses and domains above are documented based on their presence in the PCAP. Their presence alone does not establish that they are malicious.

---

# 9. MITRE ATT&CK Mapping

The observed activity can be mapped to the following MITRE ATT&CK technique:

### T1021.004 — Remote Services: SSH

**Not applicable.**

The observed protocol was Telnet, not SSH.

### T1021 — Remote Services

The activity is broadly consistent with the **Remote Services** technique because one internal host established a remote interactive session with another host.

The exact ATT&CK sub-technique for Telnet should not be claimed without confirming that the selected ATT&CK version explicitly maps Telnet to a specific sub-technique.

### Command and Shell Activity

The captured Telnet session provided access to a Windows command shell, demonstrating remote command execution capability.

Because the capture only shows basic commands such as `dir`, the analysis does not claim more advanced execution techniques.

---

# 10. Incident Timeline

### Stage 1 — DNS Activity

`192.168.1.3` generated DNS queries to the local DNS server:

`192.168.1.3 → 192.168.1.1`

Queries included:

* `www.www.com`
* `www.www.com.lan`

### Stage 2 — External HTTP Communication

`192.168.1.2` established HTTP communication with:

`83.170.75.178`

An HTTP GET request and `304 Not Modified` response were observed.

### Stage 3 — Telnet Connection

`192.168.1.3` initiated a Telnet connection:

`192.168.1.3:1403 → 192.168.1.2:23`

The TCP three-way handshake completed successfully.

### Stage 4 — Interactive Remote Shell

The Telnet session exposed a Windows XP command prompt.

The `dir` command was executed and directory information was returned.

### Stage 5 — Session Termination

The session was terminated using:

```text
exit
```

---

# 11. Risk Assessment

### Risk Level: Medium–High

The presence of an interactive Telnet session between internal hosts creates a security concern because Telnet is an insecure remote administration protocol and provides interactive access to the target system.

Potential risks include:

* Unauthorized remote access
* Exposure of credentials and session data
* Lateral movement
* Remote command execution
* Compromise of legacy systems
* Increased attack surface due to insecure services

However, the available evidence does not confirm malware execution, data theft, persistence, or privilege escalation.

---

# 12. Recommended SOC Response

### Immediate Actions

1. Identify the owner and role of `192.168.1.3`.
2. Identify the owner and role of `192.168.1.2`.
3. Determine whether the Telnet session was authorized.
4. Review authentication and system logs on both hosts.
5. Check whether TCP port 23 is required.
6. Disable Telnet if it is not required.
7. Replace Telnet with a secure remote administration protocol where appropriate.
8. Investigate the external communication involving `83.170.75.178`.
9. Review DNS activity associated with `www.www.com` and `www.www.com.lan`.
10. Monitor both internal hosts for additional suspicious activity.

### If Unauthorized Activity Is Confirmed

* Isolate the affected host.
* Preserve relevant logs and forensic evidence.
* Review accounts used for remote access.
* Reset potentially exposed credentials.
* Investigate lateral movement.
* Perform endpoint malware and integrity checks.
* Block unnecessary remote services.
* Document and escalate the incident according to the organization's incident response procedure.

---

# 13. Key Findings

The investigation identified:

* **131 packets** in the supplied PCAP.
* Communication between multiple internal and external hosts.
* DNS queries from `192.168.1.3` to `192.168.1.1`.
* HTTP communication between `192.168.1.2` and `83.170.75.178`.
* A successful Telnet connection from `192.168.1.3` to `192.168.1.2`.
* An interactive Windows XP command shell accessible through the Telnet session.
* Execution of the `dir` command and retrieval of directory information.
* No direct evidence of malware execution, persistence, privilege escalation, or data exfiltration within the observed Telnet stream.

---

# 14. Analyst Conclusion

The PCAP analysis identified **suspicious internal remote access activity involving Telnet**.

The strongest evidence was a successful TCP connection from `192.168.1.3` to `192.168.1.2` over TCP port 23, followed by an interactive Windows XP command shell.

While this demonstrates remote command-line access, the available evidence does not conclusively establish that the activity was malicious. Further investigation of host logs, authentication records, endpoint telemetry, and system ownership would be required to determine whether the Telnet session was authorized.

The external HTTP communication and DNS queries were documented as additional areas of interest but were not independently classified as malicious based solely on the available PCAP evidence.

This investigation demonstrates the importance of **evidence-driven network analysis**, protocol inspection, TCP stream reconstruction, IOC identification, and cautious incident classification in a SOC environment.

---

# 15. Evidence

The following screenshots were captured during the investigation and added as a file attached:

```text
evidence/
├── 01-pcap-overview.png
├── 02-telnet-handshake.png
├── 03-telnet-command-shell.png
└── 04-dns-queries.png
```

---

# 16. Skills Demonstrated

* PCAP analysis
* Wireshark
* Network traffic investigation
* IPv4 endpoint analysis
* DNS analysis
* HTTP traffic analysis
* TCP analysis
* TCP three-way handshake analysis
* Telnet investigation
* TCP stream reconstruction
* IOC identification
* Incident classification
* MITRE ATT&CK analysis
* Risk assessment
* SOC incident response
* Evidence-based reporting

---

## Disclaimer

This project was performed using a publicly available Wireshark sample PCAP in a controlled learning environment.

No unauthorized systems were accessed, scanned, attacked, or tested as part of this investigation.
