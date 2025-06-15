# 🕵️‍♂️ CTF Threat Hunt: *Deep Access: The Adversary*

# 📚 Table of Contents

[🧠 Scenario](#-scenario)  
[🏠 Starting Point](#-starting-point)

- [🏁 Flag 1 – Initial PowerShell Execution Detection](#-flag-1--initial-powershell-execution-detection)  
- [🏁 Flag 2 – Suspicious Outbound Signal](#-flag-2--suspicious-outbound-signal)  
- [🏁 Flag 3 – Registry-based Autorun Setup](#-flag-3--registry-based-autorun-setup)  
- [🏁 Flag 4 – Scheduled Task Persistence](#-flag-4--scheduled-task-persistence)  
- [🏁 Flag 5 – Obfuscated PowerShell Execution](#-flag-5--obfuscated-powershell-execution)  
- [🏁 Flag 6 – Evasion via Legacy Scripting](#-flag-6--evasion-via-legacy-scripting)  
- [🏁 Flag 7 – Remote Movement Discovery](#-flag-7--remote-movement-discovery)  
- [🏁 Flag 8 – Entry Indicators on Second Host](#-flag-8--entry-indicators-on-second-host)  
- [🏁 Flag 8.1 – Persistence Registration on Entry](#-flag-81--persistence-registration-on-entry)  
- [🏁 Flag 9 – External Communication Re-established](#-flag-9--external-communication-re-established)  
- [🏁 Flag 10 – Stealth Mechanism Registration](#-flag-10--stealth-mechanism-registration)  
- [🏁 Flag 11 – Suspicious Data Access Simulation](#-flag-11--suspicious-data-access-simulation)  
- [🏁 Flag 12 – Unusual Outbound Transfer](#-flag-12--unusual-outbound-transfer)  
- [🏁 Flag 13 – Sensitive Asset Interaction](#-flag-13--sensitive-asset-interaction)  
- [🏁 Flag 14 – Tool Packaging Activity](#-flag-14--tool-packaging-activity)  
- [🏁 Flag 15 – Deployment Artifact Planted](#-flag-15--deployment-artifact-planted)  
- [🏁 Flag 16 – Persistence Trigger Finalized](#-flag-16--persistence-trigger-finalized)

[🧠 Logical Flow & Analyst Reasoning](#-logical-flow--analyst-reasoning)  
[🔍 Key Findings](#-key-findings)  
[🎯 MITRE ATT&CK Mapping](#-mitre-attck-mapping)  
[🛡️ Remediation Steps](#remediation-steps)


## 🧠 Scenario

For weeks, multiple partner organizations across Southeast Asia and Eastern Europe detected odd outbound activity to obscure cloud endpoints. Initially dismissed as harmless automation, the anomalies began aligning.

Across sectors — telecom, defense, manufacturing — analysts observed the same patterns: irregular PowerShell bursts, unexplained registry changes, and credential traces mimicking known red-team tools.

Then came a break. A tech firm flagged sensitive project files leaked days before a bid was undercut. An energy provider found zipped payloads posing as sync utilities in public directories.

Whispers grew — not one actor, but a coordinated effort. Code fragments matched across unrelated environments. The beaconing continued: quiet, rhythmic pings to endpoints no business could explain.

Some suspect Starlance — an old, disbanded joint op revived. Others say mercenary crews using supply chain access and familiar tooling.

What’s clear: this wasn’t smash-and-grab. It was long game.

Your task: trace the access, map the spread, and uncover what was touched — or taken. Two machines hold the truth, scattered and shrouded.

No alerts fired. No passwords changed.
But something was here…
…and it might return.

## 🏠 Starting Point

Before you officially begin the flags, you must first determine where to start hunting. The attack points are randomized, but you may want to start with the newly created virtual machines that were only active for a few hours before being deleted, implying that the device(s) did not generate thousands of recorded processes, at least not in the central logging repository. 

Hint: Device name starts with a. Search around May 24th 2025
```kql
DeviceInfo
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:59))
| summarize firstSeen = min(Timestamp), lastSeen = max(Timestamp), activityCount = count() by DeviceName
| extend duration_hours = datetime_diff('hour', lastSeen, firstSeen)
| where duration_hours < 12
| where DeviceName startswith "a"
| sort by duration_hours asc
//| sort by activityCount desc
```
![flag00name](https://github.com/user-attachments/assets/0866bbf1-474c-4370-b1a9-27f2f416edf4)

Identify the device in question:
acolyte756

## 🏁 Flag 1 – Initial PowerShell Execution Detection

**🎯 Objective:**  
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**🧭 What to Hunt:**  
Initial signs of PowerShell being used in a way that deviates from baseline usage.

**💡 Thought:**  
Understanding where it all began helps chart every move that follows. Look for PowerShell actions that started the chain.

---

### 🧪 KQL Query:
```kusto
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where FileName =~ "powershell.exe"
| project Timestamp,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName,
          ProcessIntegrityLevel
| sort by Timestamp asc
```
![Flag 2 time stamp](https://github.com/user-attachments/assets/37eb6dcd-7a50-4269-91f6-de0377910b45)

![Flag 2 record](https://github.com/user-attachments/assets/990b109e-a135-4f30-9626-dd4571fd5a17)


### ✅ Findings

- **Earliest Execution Timestamp:**  
  `2025-05-25T09:14:02.3908261Z`

- **Command Line Used:**  
  `"powershell.exe" -Version 5.1 -s -NoLogo -NoProfile`

- **Analysis:**  
  The command uses PowerShell version 5.1 with flags that suppress UI (`-NoLogo`) and profile loading (`-NoProfile`), suggesting non-interactive or scripted execution. The `-s` flag (if valid) implies a stealthy or silent mode often used in automation or obfuscation scenarios.

---

### 📌 Conclusion

This activity is the first recorded suspicious PowerShell invocation on `acolyte756`, likely marking the adversary's entry point. Its use of flags to reduce visibility aligns with common tactics for stealthy initial execution. This point sets the stage for subsequent persistence and lateral movement observed in the environment.

## 🏁 Flag 2 – Suspicious Outbound Signal

**🎯 Objective:**  
Confirm an unusual outbound communication attempt from a potentially compromised host.

**🔍 What to Hunt:**  
Look for external destinations unrelated to normal business operations.

**💡 Thought:**  
When machines talk out of turn, it could be a sign of control being handed off.

**🧩 Hint Recap:**
- *We don't have a controlled remote server*
- *Hollow tube*  
These clues point toward an externally controlled channel, possibly command-and-control (C2) infrastructure or a data exfiltration endpoint.

---

### 🔎 KQL Query Used

```kql
DeviceNetworkEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where RemoteIPType == "Public" or RemoteUrl != "" // Untrusted or external
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, LocalIP, InitiatingProcessSHA256
| sort by Timestamp asc
```
![flag 3 pipedream](https://github.com/user-attachments/assets/fa3eeb71-69d5-4338-92aa-7d9546e6873f)

![flag 3 record](https://github.com/user-attachments/assets/4c408380-9286-4732-91c4-8cc74045bd3b)

### ✅ Findings

- **Device:** `acolyte756`
- **Suspicious Outbound URL:** `eoqsu1hq6e9ulga.m.pipedream.net`
- **RemoteIPType:** Public
- **Protocol:** Likely HTTPS based on typical Pipedream usage

**🔎 Pipedream Context:**  
`pipedream.net` is a cloud-based automation and webhook testing platform. While useful for development, it is an uncommon destination for enterprise endpoints. The randomized subdomain (`eoqsu1hq6e9ulga`) is a strong indicator of dynamically generated URLs commonly used for receiving C2 instructions or exfiltrating data.

**🧠 Execution Context:**  
This outbound connection was initiated shortly after initial PowerShell activity was observed on the same host, implying it may be the result of that execution.

---

### 📌 Conclusion

The URL `eoqsu1hq6e9ulga.m.pipedream.net` is a highly suspicious destination. It is hosted on a legitimate but non-corporate domain and features a randomized subdomain, which strongly suggests a dynamic and attacker-controlled endpoint. Its use points to a likely command-and-control or data exfiltration channel established by the attacker following their initial PowerShell execution on `acolyte756`.

This marks a critical turning point in the attack, transitioning from local execution to external communication, and indicates the host is likely under adversary control.

## 🏁 Flag 3 – Registry-based Autorun Setup

### 🎯 Objective
Detect whether the adversary used registry-based mechanisms to gain persistence.

### 🔍 What to Hunt
Identify the name of the program tied to the new registry value created.

### 💡 Thought
The registry is a favored place to hide re-execution logic — it’s reliable, stealthy, and usually overlooked.

---

### 🔎 KQL Query

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run" or RegistryKey has "RunOnce" or RegistryKey has "Services"
| where ActionType == "RegistryValueSet"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp asc
```

![flag 4 registry](https://github.com/user-attachments/assets/1778173c-2f0c-442a-810d-0fb93042836f)


### ✅ Findings

- **Device:** `acolyte756`
- **Relevant Registry Path(s):**  
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `RunOnce`, `Services` (monitored as part of the hunt)

- **Registry Action:** `RegistryValueSet`
- **Registry Value Name:** (Observed in event)
- **Registry Value Data:** `C2.ps1`
- **Associated Execution File:** `C2.ps1`

This registry change was tied to a persistence mechanism, where the PowerShell script `C2.ps1` is configured to execute automatically at logon or startup via a `Run` key.

---

### 📌 Conclusion

The adversary leveraged Windows registry-based autorun by modifying the `Run` key to persist the malicious script `C2.ps1`. This tactic allows for reliable execution upon user login, ensuring the attacker maintains a foothold on the system (`acolyte756`) even after reboots.

Registry-based persistence like this is stealthy and commonly overlooked during casual inspection, making it an effective method for maintaining long-term access.

## 🏁 Flag 4 – Scheduled Task Persistence

### 🎯 Objective
Investigate the presence of alternate autorun methods used by the intruder.

### 🔍 What to Hunt
Verify if scheduled task creation occurred in the system.

### 💡 Thought
Adversaries rarely rely on just one persistence method. Scheduled tasks offer stealth and reliability — track anomalies in their creation times and descriptions.

---

### 🔎 KQL Query

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where RegistryKey has "Schedule\\TaskCache"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![flag 5 registry schedule](https://github.com/user-attachments/assets/ffda9991-c2d2-49d5-be4d-650775575e78)

### ✅ Findings
- **Device:** `acolyte756`
- **Persistence Method:** Scheduled Task
- **Registry Key Created:**  
  `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task`
- **Execution Context:**  
  Created via registry modification, which indicates task scheduling was programmatically configured (likely through PowerShell or other LOLBIN usage).

---

### 📌 Conclusion
The registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task` confirms the creation of a scheduled task named **SimC2Task**. This is a classic persistence tactic that ensures malicious scripts or payloads can run at designated intervals or system events (e.g., logon, boot).

Combined with the prior registry-based autorun method, this highlights the adversary’s **layered approach to persistence** — a hallmark of a more **sophisticated intrusion strategy**.

## 🏁 Flag 5 – Obfuscated PowerShell Execution

### 🎯 Objective
Uncover signs of script concealment or encoding in command-line activity.

### 🔍 What to Hunt
Look for PowerShell patterns that don't immediately reveal their purpose — decoding may be required.

### 💭 Thought
Encoding is a cloak. Finding it means someone may be hiding something deeper within an otherwise familiar tool.

---

### 📊 KQL Query
```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("-EncodedCommand", "-enc", "-e")
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId
| sort by Timestamp asc
```
![flag 6 encoded query](https://github.com/user-attachments/assets/74292c1c-ebca-4ad7-ab67-43a110e154b3)

### ✅ Findings
- **Device:** `acolyte756`
- **Suspicious Execution Method:** Encoded PowerShell
- **Full Command Line:**
- "powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA

  - **Decoded Output:**  
`Write-Output "Simulated obfuscated execution"`

---

### 📌 Conclusion
An obfuscated PowerShell script was executed on `acolyte756` using the `-EncodedCommand` flag. Although this instance decodes to a benign message (`Simulated obfuscated execution`), the use of Base64-encoded commands is a red flag in most enterprise environments.

This tactic is frequently used to **evade detection**, **bypass logging mechanisms**, and **hide malicious intent**. Even in a simulation, it reflects real-world adversary tradecraft and highlights the importance of monitoring for encoded command execution.

## 🏁 Flag 6 – Evasion via Legacy Scripting

### 🎯 Objective  
Detect usage of outdated script configurations likely intended to bypass modern controls.

### 🔍 What to Hunt  
Look for uncommon scripting versions of PowerShell or execution flags that reduce oversight.

### 💡 Thought  
Modern defenses expect modern behavior. Watch for forced downgrades or legacy runtime calls.

---

### 🧪 KQL Query
```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-Version"
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```
![flag 7 downgrade](https://github.com/user-attachments/assets/98304377-b691-408b-aa80-29a41e2e1d57)

### ✅ Findings
- **Device:** `acolyte756`
- **Command Used to Downgrade PowerShell:**
"powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit

- **Indicators of Evasion:**
- `-Version 2`: Forces the use of PowerShell version 2.0, which lacks many modern logging and security features.
- `-ExecutionPolicy Bypass`: Ignores PowerShell's script execution restrictions.
- `-NoProfile`: Prevents user profiles from loading, avoiding detection or interference.
- `-NoExit`: Keeps the session open, possibly for further manual or scripted interaction.

---

### 📌 Conclusion
The adversary deliberately downgraded PowerShell to version 2.0 using the `-Version` flag. This version is deprecated and lacks many modern telemetry and security enhancements, making it attractive for evading detection.

Combined with flags like `-ExecutionPolicy Bypass`, this execution strongly signals an attempt to operate stealthily under the radar of modern endpoint detection solutions. This event illustrates the attacker’s intent to bypass controls through legacy compatibility—an often overlooked blind spot in many environments.

## 🏁 Flag 7 – Remote Movement Discovery

**🎯 Objective:**  
Reveal the intruder's next target beyond the initial breach point.

**🔍 What to Hunt:**  
Trace outbound command patterns that reference hostnames unfamiliar to the local machine.

**💡 Thought:**  
Lateral movement often hides in plain sight. Connections to the right system at the wrong time can be the giveaway.

---

### 🔎 KQL Used

```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-24 00:00:00) .. datetime(2025-05-25 23:59:00))
| where ProcessCommandLine has_any ("\\", "/S", "-ComputerName")
| project Timestamp, ProcessCommandLine, FileName
| sort by Timestamp asc
```
![flag 8 victor](https://github.com/user-attachments/assets/0be86f3a-76d1-445d-9c62-9a6940f55d1b)

### ✅ Findings

- **Device:** `acolyte756`
- **Suspicious Activity:** Remote command execution observed using `/S` switch and UNC pathing.
- **Command Evidence:** Indicates attempts to interact with another machine in the environment.
- **Next Host Identified:** `victor-disa-vm` — referenced within PowerShell or command-line activity, pointing to lateral movement.

---

### 📌 Conclusion

The system `acolyte756` initiated remote interactions referencing `victor-disa-vm`, a clear sign of lateral movement. This behavior deviates from normal host activity and suggests an attacker expanding their footprint across the network.

By tracing remote host references in command-line arguments, we expose the attack’s progression beyond the initial compromise — a critical phase where early detection can prevent wider impact.

## 🏁 Flag 8 – Entry Indicators on Second Host

### 🎯 Objective  
Identify the subtle digital footprints left during a pivot.

### 🔍 What to Hunt  
Artifacts with naming patterns that imply staging, sync, or checkpointing.

### 💭 Thought  
Every move leaves a mark — even if that mark is as simple as a filename that doesn't belong.

---

### 🧠 Hint  
1. point

---

### 📊 KQL Used
```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where FileName contains "point"
| project Timestamp, FileName, FolderPath, ActionType
| sort by Timestamp asc
```
![flag 9 savepoint](https://github.com/user-attachments/assets/623598b8-5df0-4d7b-9b2a-6ffb6785d1a6)

### ✅ Findings

- **Device:** `victor-disa-vm`
- **Suspicious File Identified:** `savepoint_sync.lnk`
- **Action Type:** File creation event observed
- **Context:** `.lnk` files (shortcuts) are commonly used in attack chains for persistence or staging. The filename `savepoint_sync.lnk` suggests intentional naming to appear benign, possibly referencing data synchronization or checkpointing — tactics often used to mask malicious activity.

---

### 📌 Conclusion

The presence of `savepoint_sync.lnk` on `victor-disa-vm` strongly indicates adversary activity. Its vague, pseudo-legitimate name is characteristic of a file planted during lateral movement or early-stage persistence. Given its creation closely follows the compromise of `acolyte756`, this shortcut file likely represents the attacker’s foothold or execution trigger on the new host. 

This marks a clear pivot in the intrusion, evidencing the attacker's expanding control across the network.

## 🏁 Flag 8.1 – Persistence Registration on Entry

**🎯 Objective:**  
Detect attempts to embed control mechanisms within system configuration.

**🔍 What to Hunt:**  
Registry values tied to files or commands that were not present days before.

**💡 Thought:**  
Nothing says ownership like persistence. Look for traces that don’t match the system’s normal operational cadence.

**🧩 Hint:**  
- Utilize previous findings

---

### 🧪 KQL Query

```kql
DeviceRegistryEvents
| where DeviceName == "victor-disa-vm"
| where Timestamp >= datetime(2025-05-25 23:00:00)  // around or just before file creation time
| where RegistryValueName contains "run" or RegistryKey contains "run"
    or RegistryKey contains "services" or RegistryKey contains "winlogon"
| where RegistryValueData contains "savepoint_sync.lnk"
    or RegistryValueData contains "savepoint"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp asc
```
![flag 9 1 registry](https://github.com/user-attachments/assets/8e98af97-24fe-4c38-9d57-80e13bd9dd84)

✅ **Findings**  
- **Device:** `victor-disa-vm`  
- **Registry Data Value:**  
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`  
- **Persistence Method:** Registry-based autorun  
- **Execution Flags Used:**  
  - `-NoProfile`: Prevents loading the user's PowerShell profile  
  - `-ExecutionPolicy Bypass`: Disables policy enforcement  
  - `-File`: Executes the specified script file  

📌 **Conclusion**  
The registry entry references a suspicious PowerShell script (`savepoint_sync.ps1`) placed in a public directory and configured to run with minimal visibility. This behavior strongly indicates a persistent mechanism set by the attacker to maintain control over `victor-disa-vm`. The use of bypass and no-profile flags further emphasizes stealth and control. This entry likely ties directly to the file artifact uncovered in Flag 8 and confirms the attacker’s pivot and persistence on a secondary host.

## 🏁 Flag 9 – External Communication Re-established

### 🎯 Objective
Verify if outbound signals continued from the newly touched system.

### 🔍 What to Hunt
Remote destinations not associated with the organization’s known assets.

### 💡 Thought
When one door closes, another beacon opens. Follow the whispers outbound.

---

### 🧪 KQL Query

```kql
DeviceNetworkEvents
| where DeviceName == "victor-disa-vm"
| where Timestamp between (datetime(2025-05-26 01:45:00) .. datetime(2025-05-30 23:59:00))
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, ActionType
| sort by Timestamp asc
```
![flag 10 url pipedream](https://github.com/user-attachments/assets/c0c6712f-0ee8-48ea-8dd3-2a0d3ebc675c)

✅ **Findings**  
- **Device:** `victor-disa-vm`  
- **Suspicious Outbound URL:** `eo1v1texxlrdq3v.m.pipedream.net`  
- **RemoteIPType:** Public  
- **ActionType:** ConnectionSuccess  
- **Protocol:** Likely HTTPS, based on Pipedream service behavior  
- **Initiating Process:** A PowerShell script tied to persistence from earlier flags  

🛰️ **Context**  
- `pipedream.net` is a legitimate cloud-based service for receiving webhooks and events, often abused by attackers due to its ease of use and free-tier availability.
- The randomized subdomain `eo1v1texxlrdq3v` signals an attacker-controlled dynamic endpoint.
- This beaconing attempt occurred after registry-based persistence was configured on `victor-disa-vm`.

📌 **Conclusion**  
The appearance of the URL `eo1v1texxlrdq3v.m.pipedream.net` on `victor-disa-vm` indicates that the attacker has successfully re-established outbound communication from the second host. This activity mirrors earlier behavior on `acolyte756`, confirming lateral movement was not just exploratory—it enabled continued control and potential data exfiltration. The use of a stealthy C2 platform like Pipedream, combined with prior persistence mechanisms, suggests the attacker intended to maintain long-term access across multiple hosts in the environment.

## 🏁 Flag 10 – Stealth Mechanism Registration

### 🎯 Objective
Uncover non-traditional persistence mechanisms leveraging system instrumentation.

### 🔍 What to Hunt
Execution patterns or command traces that silently embed PowerShell scripts via background system monitors.

### 💡 Thought
Some persistence methods don’t rely on scheduled tasks or run keys. Instead, they exploit Windows Management Instrumentation (WMI) to bind code to system behavior — event filters, consumers, and bindings quietly forming a re-execution trap.  
If successful, the attacker no longer needs a login or shell to keep control.

---

### 🧪 KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-26 23:59:00))
| where ProcessCommandLine has_any ("wmic", "wmi", "Win32_EventFilter", "EventConsumer", "FilterToConsumerBinding", "beacon")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp asc
```

![flag 11 wmi](https://github.com/user-attachments/assets/3c9faafe-3ced-44d8-a961-03d768270c3c)

### ✅ Findings
- **Device:** `victor-disa-vm`
- **Persistence Mechanism:** WMI-based
- **Trigger Name Indicator:** Contains the string `"beacon"`
- **Earliest Activity Timestamp:** `2025-05-26T02:48:07.2900744Z`
- **Execution Artifacts:** Use of `Win32_EventFilter`, `EventConsumer`, `FilterToConsumerBinding` indicating WMI subscription creation
- **Likely Objective:** Long-term persistence through system event monitoring

---

### 📌 Conclusion
The WMI-based persistence attempt observed at `2025-05-26T02:48:07.2900744Z` on `victor-disa-vm` signals a shift to stealthier control techniques. By registering an event filter and binding it to a consumer (likely a PowerShell payload), the attacker avoids traditional methods like scheduled tasks or registry autoruns. This method leverages native system instrumentation for script re-execution and is often missed by conventional detection mechanisms. The presence of the "beacon" keyword further aligns this with known adversarial behavior, confirming ongoing control operations on the compromised host.

## 🏁 Flag 11 – Suspicious Data Access Simulation

**🎯 Objective:**  
Detect test-like access patterns mimicking sensitive credential theft.

**🔍 What to Hunt:**  
References or interactions with files suggestive of password storage or system secrets.

**💭 Thought:**  
Even simulations create signals. Mimicry of real attacks is often part of preparation.

---

### 🧪 KQL Query Used
```kql
DeviceProcessEvents 
| where DeviceName == "victor-disa-vm"
| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-26 23:59:00))
| where ProcessCommandLine has_any("mimi", "sekurlsa", "lsass", "dump", "cred", "pwd", "password", "secret")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp asc
```

![flag 12 mimi](https://github.com/user-attachments/assets/9f06ebd3-b9a5-44f6-bc79-d3d3cd895b86)

### ✅ Findings
- **Device:** `victor-disa-vm`
- **Suspicious File Detected:** `mimidump_sim.txt`
- **Execution Context:** Detected via command-line arguments that include credential dumping keywords such as `mimi`, `lsass`, `cred`, and `password`.
- **File Purpose:** Likely simulates the output of Mimikatz or similar credential theft tools, possibly used for testing or emulation without deploying actual malware.

---

### 📌 Conclusion
The presence of `mimidump_sim.txt` combined with command-line indicators strongly suggests an emulation of credential dumping activity. While no malicious binaries were directly observed, this file mirrors the behavior and naming convention of Mimikatz outputs. This type of simulation is often used in red team operations or attack simulations to test detection coverage without executing real malware. Despite its benign nature, this activity is a strong indicator of a staged or test credential access attempt.

## 🏁 Flag 12 – Unusual Outbound Transfer

**🎯 Objective:**  
Investigate signs of potential data transfer to untrusted locations.

**🔍 What to Hunt:**  
External destinations indicative of third-party file storage or sharing services.

**💡 Thought:**  
The hands that take may hide in common destinations. Even familiar URLs can hide foul intent.

---

### 🧪 KQL Query Used

```kql
DeviceNetworkEvents 
| where DeviceName == "victor-disa-vm"
| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-26 23:59:00))
| where RemoteUrl has_any("pipedream", "dropbox", "pastebin", "transfer", "send", "webhook", "api")
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| sort by Timestamp asc
```
![flag 12 sha256](https://github.com/user-attachments/assets/bb8581ef-1044-4d16-bf6e-07afed19e738)

### ✅ Findings
- **Device:** `victor-disa-vm`
- **Behavior:** Outbound connection to suspicious third-party storage or transfer service.
- **Destination Keywords:** Included domains such as `pipedream`, `dropbox`, `transfer`, etc.
- **SHA256 of Initiating Process:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`
- **Command Line:** Included indicators of exfiltration or API communication.

---

### 📌 Conclusion
An outbound connection to a potential file transfer or webhook service was detected from `victor-disa-vm`, tied to a process with SHA256 `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`. The domain categories (e.g., `pipedream.net`) are commonly used for automation, testing, or data exfiltration. In the context of prior credential access activity and PowerShell-based persistence, this strongly suggests an exfiltration phase of the attack. The activity represents a critical point in the adversary's kill chain, where stolen data may have been successfully transferred outside of the environment.

## 🏁 Flag 13 – Sensitive Asset Interaction

**🎯 Objective:**  
Reveal whether any internal document of significance was involved.

**🔎 What to Hunt:**  
Access logs involving time-sensitive or project-critical files.

**💭 Thought:**  
When the adversary browses project plans, it’s not just about access — it’s about intent.

---

### 🧠 KQL Query
```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has_any ("2025", "Strategic", "Plan", "Board", "KPI", "Summary", "QBR")
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, FolderPath, FileName
| sort by Timestamp asc
```

![flag13 kql](https://github.com/user-attachments/assets/9c5d192e-4408-45bf-9f17-f6abf0aa8747)

### ✅ Findings
- **Device:** `victor-disa-vm`  
- **Targeted File:** `RolloutPlan_v8_477.docx`  
- **File Type:** Likely a strategic internal document related to end-of-month 2025 planning  
- **Access Method:** Accessed using command-line interactions involving keywords like `"2025"`, `"Plan"`, and `"KPI"`

---

### 📌 Conclusion
The attacker accessed `RolloutPlan_v8_477.docx`, a document strongly suggesting business sensitivity tied to strategic or end-of-month planning. The filename and access context indicate intent to gather intelligence or exfiltrate internal project data. This interaction moves beyond basic intrusion toward high-value data reconnaissance — a hallmark of a more advanced or goal-oriented attack campaign.

## 🏁 Flag 14 – Tool Packaging Activity

**🎯 Objective:**  
Spot behaviors related to preparing code or scripts for movement.

**🔎 What to Hunt:**  
Compression or packaging of local assets in non-administrative directories.

**💭 Thought:**  
Before things move, they are prepared. Track the moment code becomes cargo.

---

### 🧠 KQL Query
```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where ActionType == "FileCreated"
| where FolderPath startswith @"C:\Users\"
| where FileName endswith ".zip" or FileName endswith ".7z"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![flag14 zip](https://github.com/user-attachments/assets/161ff7f0-733d-4763-b4e9-18904f380408)

### ✅ Findings

- **Device:** `victor-disa-vm`
- **Packaging Command:**  
  `"powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`
- **Behavior:** Malicious files were compressed into an archive for likely exfiltration or lateral transfer.
- **Target Archive:** `spicycore_loader_flag8.zip`
- **Path:** `C:\Users\Public\`

---

### 📌 Conclusion

The use of PowerShell’s `Compress-Archive` command to zip the contents of `dropzone_spicy` into `spicycore_loader_flag8.zip` is a strong indicator of tool staging for transfer. This behavior represents a classic precursor to data exfiltration or distribution of attack tooling across an environment. The use of non-admin paths like `C:\Users\Public\` further indicates attempts to evade detection by blending into normal user activity zones.


## 🏁 Flag 15 – Deployment Artifact Planted

**🎯 Objective:**  
Verify whether staged payloads were saved to disk.

**🔎 What to Hunt:**  
Unusual file drops, especially compressed archives, in public or shared paths.

**💭 Thought:**  
Staged doesn’t mean executed — yet. But it’s the clearest sign something is about to happen.

---

### 🧠 KQL Query
```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where FolderPath contains "spicycore_loader_flag8.zip"
   or FolderPath contains "dropzone_spicy"
   or FolderPath contains "Public"
| where ActionType in ("FileCreated", "FileWritten")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```
![flag 15 kql](https://github.com/user-attachments/assets/9c0637b6-6c47-48c5-a42f-77d87919268f)

### ✅ Findings

- **Device:** `victor-disa-vm`
- **Malicious Archive:** `spicycore_loader_flag8.zip`
- **Location:** `C:\Users\Public\`
- **Related Directory:** `dropzone_spicy`
- **Action Observed:** File creation/writing activity tied to compressed payloads staged for potential deployment.

---

### 📌 Conclusion

The presence of the archive `spicycore_loader_flag8.zip` in a shared, low-privilege directory (`C:\Users\Public\`) is a strong indicator of payload staging. Though not yet executed, this behavior signals a preparation phase consistent with adversarial tool deployment. Staging in public locations is commonly used to facilitate execution by another user or process — either locally or remotely.

## 🏁 Flag 16 – Persistence Trigger Finalized

**🎯 Objective:**  
Identify automation set to invoke recently dropped content.

**🔎 What to Hunt:**  
Scheduled execution entries tied to non-standard script names.

**💭 Thought:**  
If something’s waiting to run, it’s worth knowing when and what will pull the trigger.

---

### 🔍 KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has_all ("schtasks", "/create")
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

![flag 16 scheduled task](https://github.com/user-attachments/assets/62ef065b-e3e5-45e5-89ca-09a18ec60f0e)

### ✅ Findings

- **Device:** `victor-disa-vm`
- **Scheduled Task Creation Timestamp:** `2025-05-26T07:01:01.6652736Z`
- **Mechanism Used:** `schtasks.exe` with `/create` flag
- **Likely Target:** Recently dropped file `spicycore_loader_flag8.zip` or contents within `dropzone_spicy` directory
- **Purpose:** Establish automation to invoke staged content

---

### 📌 Conclusion

The adversary finalized persistence by scheduling an automated task on `victor-disa-vm` at `2025-05-26T07:01:01.6652736Z` using `schtasks.exe`. This task likely ties directly to previously staged content, such as `spicycore_loader_flag8.zip`. The use of custom scripts and automation suggests a clear intention to ensure malicious execution without needing further manual interaction — a common tactic in advanced persistence strategies.

## 🧠 Logical Flow & Analyst Reasoning

1 → 2 🚩: *"Why is PowerShell doing something suspicious? Could it be beaconing out to a remote C2 server?"*

2 → 3 🚩: *"If there’s beaconing, the attacker may want persistence — is anything registering to autorun from the registry?"*

3 → 4 🚩: *"Registry-based persistence is one layer. Is there redundancy? Could scheduled tasks also be involved?"*

4 → 5 🚩: *"Looks like the attacker used encoded PowerShell. Is this obfuscation to hide what’s being run?"*

5 → 6 🚩: *"If they’re obfuscating, are they also trying to weaken defenses? Did they attempt to downgrade PowerShell?"*

6 → 7 🚩: *"This is adding up — did the attacker move laterally from this machine to another system in the environment?"*

7 → 8 🚩: *"Looks like the attacker pivoted to `victor-disa-vm`. Were any new scripts or indicators dropped there as checkpoints?"*

8 → 9 🚩: *"There’s a new beacon attempt on the second machine — confirming C2 behavior is now spreading across hosts."*

9 → 10 🚩: *"Was persistence also deployed here? Is WMI being used to re-execute the payload silently in the background?"*

10 → 11 🚩: *"If they have persistence, are they now going after credentials? Are there signs of local credential access attempts?"*

11 → 12 🚩: *"If creds were dumped, is data being staged or exfiltrated? Any signs of outbound traffic to non-corporate storage like Google Drive?"*

12 → 13 🚩: *"What exactly was exfiltrated? Was it business-sensitive material like planning docs or departmental data?"*

13 → 14–15 🚩: *"After exfil, did the attacker stick around to enumerate users or processes for future pivoting or deeper access?"*

14–15 → 16 🚩: *"Enumeration suggests further prep — were any new payloads dropped or staged, maybe in ZIP format? And if a payload was dropped, did they automate its execution through scheduled task creation?"*

## 🔍 Key Findings
**Initial Access Achieved via PowerShell**
- Attacker leveraged PowerShell with -ExecutionPolicy Bypass to gain code execution on host acolyte756.

**Command and Control (C2) Communications Established**
- Outbound traffic to eo1v1texxlrdq3v.m.pipedream.net observed, consistent with C2 behavior.

**Persistence Mechanisms Installed**
- Multiple persistence layers were implemented
- Registry autorun (Run key)
- Scheduled Task (UpdateHealthTelemetry)
- WMI-based event trigger (Win32_EventFilter + Consumer)

**Lateral Movement**
- The attacker pivoted from acolyte756 to victor-disa-vm via remote task creation.

**Obfuscation and Defense Evasion**
- Use of encoded PowerShell and legacy version downgrades (-Version 2) to evade modern endpoint defenses.

**Credential Dumping Attempted**
- A file named mimidump_sim.txt indicates Mimikatz-like activity.

**Data Exfiltration and Packaging**
- Sensitive document (RolloutPlan_v8_477.docx) was likely exfiltrated after being packaged into spicycore_loader_flag8.zip.

## 🎯 MITRE ATT&CK Mapping

| **Tactic**                | **Technique**                                            | **ID**                                                      |
| ------------------------- | -------------------------------------------------------- | ----------------------------------------------------------- |
| Initial Access            | PowerShell Abuse for Execution                           | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| Execution                 | PowerShell with Bypass Policy                            | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| Persistence               | Registry Run Key / Startup Folder                        | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| Persistence               | Scheduled Task/Job                                       | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| Persistence               | WMI Event Subscription                                   | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) |
| Defense Evasion           | Obfuscated Files or Information (Encoded PowerShell)     | [T1027](https://attack.mitre.org/techniques/T1027/)         |
| Defense Evasion           | Indicator Removal: Downgrade PowerShell                  | [T1562.006](https://attack.mitre.org/techniques/T1562/006/) |
| Credential Access         | Credential Dumping via Simulated Mimikatz File           | [T1003](https://attack.mitre.org/techniques/T1003/)         |
| Command and Control       | Application Layer Protocol: Web C2 using `pipedream.net` | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Lateral Movement          | Remote Scheduled Task                                    | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) |
| Collection & Exfiltration | Archive Collected Data (Compress-Archive)                | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) |
| Exfiltration              | Exfiltration to Cloud Storage                            | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


## 🛡️ Remediation Steps

### 🔐 Short-Term (Immediate Response)

- **Isolate Affected Hosts**  
  Quarantine `acolyte756` and `victor-disa-vm` from the network to prevent further compromise or lateral movement.

- **Reset User Credentials**  
  Force password reset for all users who have logged into the affected systems, and invalidate existing sessions.

- **Block External Domains**  
  Add domains such as `*.pipedream.net`, `dropbox.com`, and other suspicious endpoints to firewall and DNS blocklists.

- **Terminate Malicious Processes**  
  Kill PowerShell processes or any suspicious scripts like `savepoint_sync.ps1` or `spicycore_loader_flag8.zip` in active memory.

---

### 🔄 Medium-Term (Recovery & Hardening)

- **Remove Persistence Mechanisms**
  - Delete malicious **registry autorun keys**.
  - Remove the **scheduled task** `UpdateHealthTelemetry`.
  - Clean up **WMI subscriptions** including filters, consumers, and bindings associated with persistence.

- **Conduct Endpoint Triage**
  Search all endpoints for indicators of compromise (IOCs), including:
  - Files: `savepoint_sync.ps1`, `spicycore_loader_flag8.zip`, `mimidump_sim.txt`
  - Directories: `C:\Users\Public\dropzone_spicy\`
  - Commands: any `Compress-Archive` activity in user directories

- **Trace Lateral Movement**
  Use Microsoft Defender for Endpoint and/or Active Directory event logs to:
  - Confirm the origin of lateral movement
  - Check if other endpoints received scheduled tasks or C2 commands

---

### 🔐 Long-Term (Preventative Measures)

- **Disable PowerShell v2**
  Remove outdated scripting engine with:
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root


- **Enforce Constrained Language Mode**
Apply for unprivileged users or systems exposed to external interaction to restrict PowerShell capabilities.

- **Monitor and Alert on PowerShell Activity**
Implement logging and detection for:
  - `EncodedCommand`
  - `Bypass`, `NoProfile`, `-Version 2`
  - `Compress-Archive`, `Invoke-WebRequest`, `IEX`

- **Enable Credential Guard & LSA Protection**
Prevent memory scraping of LSASS using:
  - Windows Defender Credential Guard
  - Registry keys or Group Policy to enable LSA protection

- **Train Users on Phishing and Scripting Threats**
Educate end users and admins about:
  - PowerShell abuse patterns
  - Social engineering tactics
  - Reporting suspicious system behavior promptly
