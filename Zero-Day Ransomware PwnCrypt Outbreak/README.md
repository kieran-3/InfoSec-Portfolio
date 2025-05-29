
## ** Investigation Scenario: Zero-Day Ransomware PwnCrypt Outbreak** 
### **Scenario**  
A new ransomware variant known as PwnCrypt has been identified. It leverages a PowerShell-based payload to encrypt files, appending the extension .pwncrypt to affected filenames (e.g., hello.txt becomes hello.pwncrypt.txt). The payload is retrieved using Invoke-WebRequest in PowerShell and specifically targets directories such as C:\Users\Public\Desktop. The CISO has flagged this as a critical concern, and an immediate investigation is necessary.
## Platforms and Languages Leveraged
- Microsoft Sentinel
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
---
### **1️⃣ Preparation**  
📌 **Objective:** Formulate a hypothesis using threat intelligence and known security gaps.  
- The organization's underdeveloped security posture (e.g., lack of user awareness training) may have enabled ransomware infiltration.  
- Leverage known indicators of compromise (IoCs), such as the `.pwncrypt` file extension, to focus the investigation.  

🔎 **Working Hypothesis:** Has PwnCrypt propagated laterally within the network?

---

### **2️⃣ Data Collection**  
📌 **Objective:** Collect relevant data from endpoints, file systems, and network traffic to support or refute the hypothesis.

#### 🖥️ **Suspicious PowerShell Command Query:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has "Invoke-WebRequest" and ProcessCommandLine has "pwncrypt.ps1"
| project Timestamp, DeviceName, InitiatingProcessParentFileName, ProcessCommandLine, AccountName
```
![1](https://github.com/user-attachments/assets/b9f1c7ee-4302-415b-be41-b3160af627ac)

#### 🔄 **Trace Ransomware Execution:**  
```kql
DeviceProcessEvents
| where ProcessCommandLine has "C:\\programdata\\pwncrypt.ps1" or FileName == "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, InitiatingProcessAccountName
```
![2](https://github.com/user-attachments/assets/99d8d936-c44d-4492-aa1d-d721a75dc9e5)

#### 🌐 **Outbound Network Activity:**  
```kql
DeviceNetworkEvents
| where RemoteUrl has "githubusercontent.com"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
![3](https://github.com/user-attachments/assets/22d5c4b2-b6dd-4001-bca3-dd9bdae0fbdb)

---

### **3️⃣ Data Analysis**  
📌 **Objective:** Analyze collected data to identify anomalies, patterns, and known indicators of compromise.

🛑 **Key Indicators Identified:**  
- **PowerShell Execution:** Use of `Invoke-WebRequest` to run `pwncrypt.ps1`.  
- **Outbound Communication:** Connection to GitHub to retrieve the payload.  
- **File Activity:** Creation of files with the `.pwncrypt` extension in user directories.

🧠 **Mapped MITRE ATT&CK Techniques:**  
- **T1059.001** – Command and Scripting Interpreter: PowerShell  
- **T1486** – Data Encrypted for Impact (Ransomware)  
- **T1105** – Ingress Tool Transfer (Payload Download)  
- **T1547** – Boot or Logon Autostart Execution (Persistence)

---

### **4️⃣ Investigation**  
📌 **Objective:** Conduct a thorough review of the incident to determine scope and initial access vector.

#### 🔍 **Investigation Steps:**  
1. Query `DeviceFileEvents` for the creation of `.pwncrypt` files.  
2. Analyze `DeviceProcessEvents` to trace the origin of the malicious process.  
3. Review account activity to identify signs of credential compromise or misuse.

---

### **5️⃣ Response**  
📌 **Objective:** Contain the threat, eliminate malicious artifacts, and restore systems safely.

#### 🛡️ **Containment Measures:**  
- 🚫 Immediately isolate affected devices from the network.  
- 🧱 Block known malicious domains and IP addresses.

#### 🧹 **Eradication Actions:**  
- Delete `pwncrypt.ps1` and terminate associated processes.  
- Scan for persistence mechanisms such as scheduled tasks or registry changes.

#### 🔄 **Recovery Steps:**  
- Restore affected systems from **verified clean backups**.  
- Confirm system integrity and verify no backdoors remain.

---

### **6️⃣ Documentation**  
📌 **Objective:** Maintain a clear record of the incident and the response process.

🗒️ **Documentation Checklist:**  
- Complete timeline of the incident.  
- List of IoCs (e.g., `.pwncrypt` files, GitHub URLs).  
- Actions taken for containment, eradication, and recovery.  
- Identified security gaps and recommendations for future prevention.

---

### **7️⃣ Improvement**  
📌 **Objective:** Strengthen the organization's resilience against similar threats.

#### 🚀 **Recommended Actions:**  
1. Enforce **endpoint protection policies** to detect and block suspicious scripts.  
2. Launch **user awareness training** to reduce phishing-related risks.  
3. Enhance **logging and monitoring** capabilities to improve early detection.


