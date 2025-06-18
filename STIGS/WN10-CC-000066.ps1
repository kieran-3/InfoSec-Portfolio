<#
.SYNOPSIS
Enable 'Include command line in process creation events' policy.

.DESCRIPTION
This script creates the necessary registry key and sets the value to enable the policy for compliance with STIG ID: WN10-CC-000066.

.NOTES
STIG ID: WN10-CC-000066
#>

# Enable 'Include Command Line in Process Creation Events' Policy (STIG ID: WN10-CC-000066)

## **Overview**
This guide explains how to configure the **'Include command line in process creation events'** policy to **Enabled** using PowerShell. This ensures compliance with **STIG ID: WN10-CC-000066** by enabling logging of command-line arguments in process creation events.

---

## **Registry Configuration Details**

The policy corresponds to the following registry key and value:
- **Registry Path**:
  ```
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
  ```
- **Value Name**: `ProcessCreationIncludeCmdLine_Enabled`
- **Value Data**: `1` (Enabled)

---

## **Automated PowerShell Script**

Use the following PowerShell script to automate the policy configuration:

```powershell
# Define registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$valueName = "ProcessCreationIncludeCmdLine_Enabled"
$valueData = 1

# Ensure the registry path exists
if (-not (Test-Path -Path $regPath)) {
    Write-Output "Creating registry path: $regPath"
    New-Item -Path $regPath -Force
}

# Set the registry value
Write-Output "Configuring 'Include command line in process creation events' policy..."
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Force

# Verify the configuration
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
if ($currentValue -eq $valueData) {
    Write-Output "Configuration successful: 'Include command line in process creation events' is enabled."
} else {
    Write-Warning "Configuration failed. Please check the registry manually."
}
```
### **Verify the Registry is Correct**
After running the script, confirm the value in the registry editor:
1. Open `regedit`.
2. Navigate to:
   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
   ```
3. Verify that `ProcessCreationIncludeCmdLine_Enabled` is set to `1`.
