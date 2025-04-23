# Threat Hunt Report: Unauthorized TOR Usage

![logo](https://github.com/user-attachments/assets/085c6b67-a35b-4efb-819e-959621b3e111)



## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called tor-shopping-list.txt on the desktop at 2025-04-23T01:12:44.9496403Z These events began at 2025-04-21T19:47:54.3167109Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "officelabk"
| where InitiatingProcessAccountName == "labuser"
| where FileName startswith "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![1](https://github.com/user-attachments/assets/2c6121f8-9528-4995-b796-222ff378ea63)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2025-04-21T20:09:16.4584679Z`, an employee on the "officelabk" device ran the file `tor-browser-windows-x86_64-portable-14.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "officelabk"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FolderPath, SHA256, ProcessCommandLine
```
![2](https://github.com/user-attachments/assets/e848bf7a-cf75-4147-b121-159126bd0bf0)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-04-23T01:01:58.8810958Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "officelabk"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![3](https://github.com/user-attachments/assets/ef5c0db4-e3d7-434c-84ce-2b2cbb155416)


---

### 4. Searched the `DeviceNetworkEvents` Table for Network Connections to TOR Nodes

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-23T01:02:44.7013732Z`, an employee on the 'officelabk' device successfully established a connection to the remote IP address `140.238.145.127` on port `9001`. The connection was initiated by the process `tor.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "officelabk"
| where InitiatingProcessFileName contains "tor"
| where RemotePort in ("80", "443", "9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![4](https://github.com/user-attachments/assets/f1e3d07f-f35c-48b4-be78-679ada5a8f36)

---

## Chronological Event Timeline 

Timestamp (UTC) | Event

2025-04-21T19:47:54 | User labuser downloaded TOR-related files; multiple TOR files copied to Desktop.

2025-04-21T20:09:16 | Silent install of tor-browser-windows-x86_64-portable-14.5.exe initiated.

2025-04-23T01:01:58 | Execution of TOR browser (tor.exe, firefox.exe) confirmed.

2025-04-23T01:02:44 | TOR established outbound connection to IP 140.238.145.127 over port 9001.

2025-04-23T01:12:44 | File tor-shopping-list.txt created on Desktop — potentially used for anonymous tracking.

---

## Summary

Management suspected TOR usage within the network due to encrypted traffic patterns and connections to known TOR entry nodes. Investigation confirmed TOR activity by a user named labuser on the workstation officelabk.

Key findings:

- TOR browser was downloaded and installed.

- It was executed and successfully connected to the TOR network.

- A suspicious .txt file was created, potentially linked to TOR activity.

Action Recommended: Notify management. Implement network and endpoint-level blocking of TOR activity. Consider disciplinary review and updates to security policy enforcement.


