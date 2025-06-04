# 🕵️‍♂️ CTF Threat Hunt: *The Great Admin Heist*

## 🧠 Scenario

At **Acme Corp**, the eccentric yet brilliant IT admin, **Bubba Rockerfeatherman III**, isn’t just patching servers and resetting passwords — he’s the secret guardian of **trillions in digital assets**.

Hidden deep within encrypted vaults lie:
- Private keys 🔐  
- Sensitive intellectual property 🧬  
- Confidential enterprise data 📁  

A covert APT group known only as **The Phantom Hackers** 👤 has targeted Bubba.  
Masters of deception, they blend:
- Social engineering
- Fileless malware
- Stealthy persistence mechanisms

into a **multi-stage attack campaign** designed to silently steal everything — without ever being detected.

The **breach has already begun**.

Through **phishing**, **credential theft**, and evasive tactics, the adversaries have **infiltrated Acme’s network**.  
Bubba? He doesn’t even know he’s been compromised.

---

## 🎯 Mission

Your task is to:

- Dive into **Microsoft Defender for Endpoint (MDE)** telemetry
- Write and execute **KQL queries** to uncover the attack chain
- Track suspicious activity, correlate indicators, and identify persistence
- **Stop the exfiltration** before it’s too late

Can you uncover the Phantom Hackers' moves in time?  
Or will they vanish into the digital void with **Bubba’s crown jewels**?

---

## 🧩 Known Information

- 💻 **Device Name**: `anthony-001`
- **Program Name**: likely begins with the following letters: A, B, or C.

---

## 🔍 KQL Query: Identify Suspicious Executables - File Write via LOLBin Abuse



This query searches for `.exe` files on device `anthony-001` that:
- Start with the letters **A**, **B**, or **C**
- Were **not launched by the SYSTEM account**
- May indicate suspicious or user-executed activity

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessAccountName != "system"
| where FileName startswith "a" or FileName startswith "b" or FileName startswith "c"
| where FileName endswith ".exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```

During the investigation of file creation events on `anthony-001`, I filtered for unusual write activity that deviated from normal patterns.

This led to the discovery of a suspicious binary:

> **BitSentinelCore.exe** — a deceptive application posing as antivirus software.

Digging deeper, I traced the parent process and found it originated from:

> **`csc.exe`** — Microsoft's trusted **C# compiler**.

This indicates a classic **LOLBin (Living-off-the-Land Binary)** technique, where a legitimate system tool was leveraged to:
- **Compile** malicious code directly on the target system
- **Drop** the malware to disk under the guise of a security tool

By abusing `csc.exe`, the attackers bypassed traditional detection mechanisms, blending malicious activity within trusted system processes.
![1st kql](https://github.com/user-attachments/assets/02eba8db-2fea-4d2f-b0e2-c855f335b02d)

![process tree bitsentinel](https://github.com/user-attachments/assets/7d69b731-3b00-4263-8736-f45790cdf1c4)



## 🧭 Execution Path

To confirm how the malware was launched, I analyzed the initiating process details.

The execution trail led back to:

> **`explorer.exe`** — indicating the malware was likely launched through the Windows shell.

This strongly suggests that **Bubba executed the file manually**, possibly by double-clicking the malicious executable, unaware of its true nature.

```kql
DeviceProcessEvents
| where FileName == "BitSentinelCore.exe" or InitiatingProcessFileName == "BitSentinelCore.exe"
```
![3 execution](https://github.com/user-attachments/assets/e65df0ca-ed9b-4441-884e-a7fe04f16921)

## 📝 Keylogger Artifact

Shortly after the malware was executed, a suspicious file named **`systemreport.lnk`** was observed in the `AppData` directory.

Its appearance closely aligned with the execution timeline of the malicious binary, strongly suggesting it was dropped as part of a **keylogging or surveillance component**.

Notably:
- It was the **only instance** of this file on the system
- Its timing and location implied **intentional deployment** for capturing user input or sensitive data

```kql
DeviceFileEvents
| where DeviceName contains "anthony-001"
| where InitiatingProcessRemoteSessionDeviceName contains "bubba"
| where Timestamp >= datetime("2025-05-07T02:00:36.794406Z")
```
![keylogger log 4](https://github.com/user-attachments/assets/7a837039-d493-4ec7-88fc-83a0fd061793)

## 🛠️ Registry Persistence

Further investigation into registry modifications revealed a persistence mechanism located at:

> `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

This entry was configured to launch **`BitSecSvc`** — a disguised alias of the malware — during system startup.

This technique ensured the malware would **automatically execute on boot**, maintaining persistence across user logins and reboots.

```kql
DeviceRegistryEvents
| where DeviceName contains "anthony-001"
| where RegistryKey contains "Run"
| where RegistryValueData has "BitSentinelCore"
```

![registry 5](https://github.com/user-attachments/assets/c9fbae52-956d-465e-8d3e-e49f63dbcb07)

## ⏰ Scheduled Task Creation

Persistence was further reinforced through the creation of a **scheduled task**.

The most notable entry was named:

> **`UpdateHealthTelemetry`**

This **deceptively benign name** was likely chosen to mimic legitimate Windows health-related services, helping it blend in and avoid suspicion.

The task was designed to trigger the malware during system uptime, enabling **long-term execution** without relying solely on startup events.

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine has "BitSentinelCore"
```
![scheduled tasks 6](https://github.com/user-attachments/assets/623a3f56-2762-412e-bf6b-5aa077248ff4)



